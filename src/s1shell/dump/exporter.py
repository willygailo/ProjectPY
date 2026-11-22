"""Atomic `0700`/`0600` target evidence bundle writer & SHA-256 manifest builder."""

from __future__ import annotations

import contextlib
import csv
import hashlib
import http
import io
import os
import secrets
import tarfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from s1shell import __version__
from s1shell.ai.redact import TelemetryRedactor
from s1shell.analyze.models import CSPAnalysisResult, EmailAuthAnalysisResult
from s1shell.assess.models import AssessmentResult, RemediationSnippet
from s1shell.assess.remediate import generate_remediation_plan
from s1shell.assess.service import build_report_bundle_from_assessment
from s1shell.config import chmod_private_file, ensure_private_dir
from s1shell.dump.models import DumpFileEntry, DumpResult
from s1shell.intel.models import CTLookupResult
from s1shell.models import SCHEMA_VERSION, dumps_json, to_json_compatible, utc_now_iso
from s1shell.profile.service import RawCaptureBundle
from s1shell.report.service import ReportService
from s1shell.scan.secrets import _SECRET_RULES, _is_placeholder, _redact_secret
from s1shell.scope import ScopeManager


def atomic_write_private_bytes(path: Path, data: bytes) -> tuple[int, str]:
    """Atomically write raw bytes to `path` with `0700` parent and `0600` file permissions."""
    ensure_private_dir(path.parent)
    tmp_path = path.parent / f".{path.name}.{secrets.token_hex(8)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(tmp_path, flags, 0o600)
    fd_owned = True
    try:
        with os.fdopen(fd, "wb") as handle:
            fd_owned = False
            handle.write(data)
            handle.flush()
            with contextlib.suppress(OSError):
                os.fsync(handle.fileno())
        chmod_private_file(tmp_path)
        os.replace(tmp_path, path)
    except BaseException:
        if fd_owned:
            with contextlib.suppress(OSError):
                os.close(fd)
        with contextlib.suppress(OSError):
            tmp_path.unlink()
        raise
    digest = hashlib.sha256(data).hexdigest()
    return len(data), digest


def atomic_write_private_text(path: Path, content: str) -> tuple[int, str]:
    """Atomically write UTF-8 text with `0600` permissions and return `(size_bytes, sha256)`."""
    return atomic_write_private_bytes(path, content.encode("utf-8"))


def infer_body_extension(content_type: str | None, body_bytes: bytes) -> str:
    """Infer a safe file extension for a captured HTTP response body."""
    mime = (content_type or "").split(";", 1)[0].strip().lower()
    if mime in {"text/html", "application/xhtml+xml"}:
        return ".html"
    if mime == "application/json" or mime.endswith("+json"):
        return ".json"
    if mime in {"application/xml", "text/xml"} or mime.endswith("+xml"):
        return ".xml"
    if mime in {"text/javascript", "application/javascript", "application/x-javascript"}:
        return ".js"
    if mime == "text/css":
        return ".css"
    if mime.startswith("text/"):
        return ".txt"

    sample = body_bytes[:4096]
    if b"\x00" in sample:
        return ".bin"
    stripped = sample.lstrip().lower()
    if stripped.startswith((b"<!doctype html", b"<html", b"<head", b"<body")):
        return ".html"
    if stripped.startswith((b"{", b"[")):
        return ".json"
    if stripped.startswith(b"<?xml"):
        return ".xml"
    return ".bin"


def format_raw_http_headers(
    status_code: int,
    http_version: str,
    raw_headers: Sequence[tuple[str, str]],
) -> str:
    """Format HTTP status line and response headers cleanly for offline re-analysis."""
    ver = (http_version or "HTTP/1.1").strip()
    if not ver.upper().startswith("HTTP/"):
        ver = f"HTTP/{ver}"
    try:
        phrase = http.HTTPStatus(status_code).phrase
    except ValueError:
        phrase = ""
    status_line = f"{ver} {status_code} {phrase}".rstrip()
    lines = [status_line]
    for name, value in raw_headers:
        clean_name = str(name).replace("\r", "").replace("\n", "")
        clean_val = str(value).replace("\r", " ").replace("\n", " ")
        lines.append(f"{clean_name}: {clean_val}")
    return "\n".join(lines) + "\n"


def redact_response_body(
    body_bytes: bytes,
    *,
    target: str,
    url: str,
    pinned_ip: str,
) -> bytes:
    """Mask IPs, emails, auth tokens, JWTs, and secret literals inside a text response body."""
    if not body_bytes or b"\x00" in body_bytes[:8192]:
        return body_bytes
    text = body_bytes.decode("utf-8", errors="replace")

    # Pass 1: redact emails, IPs, query secrets, Bearer tokens, and JWTs before host replacement
    # so emails on the target domain (e.g. ops@target.com) match intact and become [EMAIL_N].
    masked = TelemetryRedactor().redact_text(text)

    # Pass 2: redact remaining target hostname and pinned IP occurrences.
    host_redactor = TelemetryRedactor()
    host_redactor.redact_artifact({"target": target, "url": url, "pinned_ip": pinned_ip})
    masked = host_redactor.redact_text(masked)

    for rule in _SECRET_RULES:
        for match in list(rule.pattern.finditer(masked)):
            secret_val = match.group(rule.group)
            if not secret_val or _is_placeholder(secret_val, match.group(0)):
                continue
            masked = masked.replace(secret_val, _redact_secret(secret_val))
    return masked.encode("utf-8")


def _safe_filename(name: str) -> str | None:
    cleaned = name.strip().replace("\\", "/")
    if not cleaned or "/" in cleaned or cleaned in {".", ".."}:
        return None
    if not all(ch.isalnum() or ch in {".", "_", "-"} for ch in cleaned):
        return None
    return cleaned


def extract_surface_entities(
    assessment: AssessmentResult,
    *,
    ct_result: CTLookupResult | None = None,
) -> tuple[list[dict[str, str]], dict[str, int]]:
    """Aggregate deduplicated passive surface entities from an authorized assessment."""
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    def _add(category: str, source: str, value: str | None) -> None:
        if value is None:
            return
        cleaned = str(value).strip()
        if not cleaned:
            return
        key = (category, source, cleaned)
        if key in seen:
            return
        seen.add(key)
        rows.append({"category": category, "source": source, "value": cleaned})

    prof = assessment.profile

    # TLS identities & SANs
    if prof.tls is not None:
        _add("tls_subject", "tls", prof.tls.subject)
        _add("tls_issuer", "tls", prof.tls.issuer)
        for san in prof.tls.sans:
            _add("tls_san", "tls", san)

    # Passive DNS records
    for val in prof.dns.a:
        _add("dns_a", "dns", val)
    for val in prof.dns.aaaa:
        _add("dns_aaaa", "dns", val)
    for val in prof.dns.cname:
        _add("dns_cname", "dns", val)
    for val in prof.dns.mx:
        _add("dns_mx", "dns", val)
    for val in prof.dns.ns:
        _add("dns_ns", "dns", val)
    for val in prof.dns.caa:
        _add("dns_caa", "dns", val)
    for val in prof.dns.dangling_cnames:
        _add("dns_dangling_cname", "dns", val)

    # Fingerprinted technologies
    for match in assessment.fingerprint.matches:
        ver_part = f" {match.version}" if match.version else ""
        eol_part = " [EOL]" if match.eol else ""
        _add("technology", "fingerprint", f"{match.product}{ver_part}{eol_part} ({match.category})")

    # Zero-extra-packet HTML entities
    if prof.html is not None and prof.html.analyzed:
        html = prof.html
        if html.title:
            _add("page_title", "html", html.title)
        for ident in html.identities_and_names:
            itype = ident.get("type") or "identity"
            ival = ident.get("value") or ""
            _add("identity", f"html:{itype}", ival)
        for email in html.emails:
            _add("email", "html", email)
        for phone in html.phone_numbers:
            _add("phone", "html", phone)
        for item in html.exposed_ids_and_keys:
            ktype = item.get("type") or "key"
            kval = item.get("value") or ""
            _add("client_id_or_key", f"html:{ktype}", kval)
        for leak in html.leaked_secrets:
            ltype = leak.get("type") or "secret"
            # Always emit only the pre-redacted sample — never raw credential material
            lsample = leak.get("redacted") or leak.get("sample") or "[REDACTED]"
            _add("redacted_secret_leak", f"html:{ltype}", lsample)
        for jwt_item in html.passive_jwts:
            alg = str(jwt_item.get("alg") or "unknown")
            src = str(jwt_item.get("source") or "html")
            issues = ", ".join(str(x) for x in (jwt_item.get("issues") or []))
            summary = f"alg={alg}" + (f" ({issues})" if issues else "")
            _add("passive_jwt", f"jwt:{src}", summary)
        for link in html.social_links:
            _add("social_link", "html", link)
        for ep in html.cloud_and_api_endpoints:
            _add("cloud_or_api_endpoint", "html", ep)
        for ep in html.form_endpoints:
            _add("form_endpoint", "html", ep)
        for smap in html.source_maps:
            _add("source_map", "html", smap)
        for leak_note in html.internal_leaks_and_comments:
            _add("internal_leak_or_comment", "html", leak_note)
        for origin in html.third_party_origins:
            _add("third_party_origin", "html", origin)

    # RFC Well-Known metadata
    if prof.well_known is not None:
        wk = prof.well_known
        for contact in wk.security_txt_contacts:
            cat = "email" if "@" in contact else "security_contact"
            _add(cat, "well_known:security.txt", contact)
        for hint in wk.robots_sensitive_hints:
            _add("robots_disallow_hint", "well_known:robots.txt", hint)
        for sm in wk.robots_sitemaps:
            _add("robots_sitemap", "well_known:robots.txt", sm)
        if wk.oidc_issuer:
            _add("oidc_issuer", "well_known:oidc", wk.oidc_issuer)
        for mfile in wk.mobile_trust_files:
            _add("mobile_trust_file", "well_known:mobile", mfile)

    # Passive RDAP contacts & entities
    if assessment.intel is not None and assessment.intel.rdap is not None:
        rdap = assessment.intel.rdap
        if rdap.abuse_contact:
            _add("rdap_abuse_contact", "intel:rdap", rdap.abuse_contact)
        for email in rdap.emails:
            _add("email", "intel:rdap", email)
        for phone in rdap.phone_numbers:
            _add("phone", "intel:rdap", phone)
        for ent in rdap.entities:
            _add("rdap_entity", "intel:rdap", ent)

    # Passive CT subdomains
    if ct_result is not None:
        for sub in ct_result.unique_subdomains:
            _add("ct_subdomain", "osint:crtsh", sub)

    counts: dict[str, int] = {}
    for row in rows:
        cat = row["category"]
        counts[cat] = counts.get(cat, 0) + 1
    return rows, counts


def _format_entities_csv(rows: Sequence[dict[str, str]]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(["category", "source", "value"])
    for row in rows:
        writer.writerow([row["category"], row["source"], row["value"]])
    return buf.getvalue()


def _format_hardening_md(
    target_url: str,
    snippets: Sequence[RemediationSnippet],
) -> str:
    lines = [
        f"# S1shell Hardening Playbook: `{target_url}`",
        "",
        "Deterministic offline remediation snippets tailored to observed findings.",
        "",
    ]
    for idx, snip in enumerate(snippets, start=1):
        fids = ", ".join(snip.finding_ids) or "general"
        lines.extend(
            [
                f"## {idx}. {snip.title}",
                "",
                f"- **Stack:** `{snip.stack}` | **Findings:** `{fids}`",
                "",
                f"```{snip.language}",
                snip.config.rstrip(),
                "```",
                "",
            ]
        )
    return "\n".join(lines)


def _create_private_tar_gz(source_dir: Path) -> tuple[Path, str]:
    archive_path = source_dir.parent / f"{source_dir.name}.tar.gz"
    tmp_path = source_dir.parent / f".{archive_path.name}.{secrets.token_hex(8)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(tmp_path, flags, 0o600)
    fd_owned = True
    try:
        with os.fdopen(fd, "wb") as raw_fh:
            fd_owned = False
            with tarfile.open(fileobj=raw_fh, mode="w:gz") as tf:
                tf.add(source_dir, arcname=source_dir.name)
            raw_fh.flush()
            with contextlib.suppress(OSError):
                os.fsync(raw_fh.fileno())
        chmod_private_file(tmp_path)
        os.replace(tmp_path, archive_path)
    except BaseException:
        if fd_owned:
            with contextlib.suppress(OSError):
                os.close(fd)
        with contextlib.suppress(OSError):
            tmp_path.unlink()
        raise

    hasher = hashlib.sha256()
    with archive_path.open("rb") as fh:
        while chunk := fh.read(65536):
            hasher.update(chunk)
    return archive_path, hasher.hexdigest()


def export_evidence_bundle(
    out_dir: Path,
    *,
    assessment: AssessmentResult,
    capture: RawCaptureBundle | None,
    report_service: ReportService,
    scope_manager: ScopeManager | None = None,
    ct_result: CTLookupResult | None = None,
    csp_result: CSPAnalysisResult | None = None,
    email_result: EmailAuthAnalysisResult | None = None,
    include_body: bool = True,
    redact_body: bool = False,
    include_reports: bool = True,
    extra_manifest_entries: Sequence[tuple[Path, str]] = (),
    operator: str | None = None,
    archive: bool = False,
    warnings: Sequence[str] = (),
) -> DumpResult:
    """Write a complete `0700`/`0600` evidence directory and SHA-256 chain-of-custody manifest."""
    root = ensure_private_dir(out_dir.expanduser().resolve())
    entries: list[DumpFileEntry] = []
    warn_list = list(warnings)

    def _record_text(rel_path: str, category: str, text: str) -> Path:
        full_path = root / rel_path
        size, sha = atomic_write_private_text(full_path, text)
        entries.append(
            DumpFileEntry(
                relative_path=rel_path,
                category=category,
                size_bytes=size,
                sha256=sha,
            )
        )
        return full_path

    def _record_bytes(rel_path: str, category: str, data: bytes) -> Path:
        full_path = root / rel_path
        size, sha = atomic_write_private_bytes(full_path, data)
        entries.append(
            DumpFileEntry(
                relative_path=rel_path,
                category=category,
                size_bytes=size,
                sha256=sha,
            )
        )
        return full_path

    prof = assessment.profile

    # --- 1. Raw Target Artifacts (`raw/`) ---
    status_code = capture.status_code if capture is not None else prof.protocol.status_code
    http_ver = capture.http_version if capture is not None else prof.protocol.http_version
    raw_hdrs = capture.raw_headers if capture is not None else prof.raw_headers
    _record_text(
        "raw/response_headers.txt",
        "raw",
        format_raw_http_headers(status_code, http_ver, raw_hdrs),
    )

    body_captured = False
    body_redacted = False
    body_truncated = bool(
        capture.body_truncated if capture is not None else prof.protocol.body_truncated
    )
    if include_body and capture is not None:
        raw_body = capture.body_bytes
        if redact_body:
            raw_body = redact_response_body(
                raw_body,
                target=assessment.target,
                url=assessment.url,
                pinned_ip=assessment.pinned_ip,
            )
            body_redacted = True
        ext = infer_body_extension(capture.content_type, raw_body)
        _record_bytes(f"raw/response_body{ext}", "raw", raw_body)
        body_captured = True

    if capture is not None and capture.tls_chain_pem:
        _record_text("raw/tls_chain.pem", "raw", capture.tls_chain_pem)

    _record_text("raw/dns_records.json", "raw", dumps_json(prof.dns))

    # --- 2. Raw RFC Well-Known Metadata (`well_known/`) ---
    if capture is not None and capture.well_known_files:
        for fname, raw_wk_bytes in sorted(capture.well_known_files.items()):
            safe_name = _safe_filename(fname)
            if safe_name is None:
                warn_list.append(f"Skipped unsafe well-known filename: {fname!r}")
                continue
            _record_bytes(f"well_known/{safe_name}", "well_known", raw_wk_bytes)

    # --- 3. Extracted Surface Entities (`entities/`) ---
    entity_rows, entity_counts = extract_surface_entities(assessment, ct_result=ct_result)
    entities_payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "tool_version": __version__,
        "generated_at_utc": utc_now_iso(),
        "target": assessment.target,
        "url": assessment.url,
        "pinned_ip": assessment.pinned_ip,
        "total_entities": len(entity_rows),
        "counts": entity_counts,
        "entities": entity_rows,
    }
    _record_text("entities/entities.json", "entities", dumps_json(entities_payload))
    _record_text("entities/entities.csv", "entities", _format_entities_csv(entity_rows))

    # --- 4. Offline Deep Analysis (`analysis/`) ---
    if csp_result is not None:
        _record_text("analysis/csp_analysis.json", "analysis", dumps_json(csp_result))
    if email_result is not None:
        _record_text("analysis/email_auth.json", "analysis", dumps_json(email_result))

    snippets = list(assessment.remediation_snippets)
    if not snippets and assessment.findings:
        plan = generate_remediation_plan(
            target_url=assessment.url,
            findings=assessment.findings,
            fingerprint_matches=[to_json_compatible(m) for m in assessment.fingerprint.matches],
            stack="auto",
        )
        snippets = list(plan.snippets)
    if snippets:
        _record_text(
            "analysis/hardening.md",
            "analysis",
            _format_hardening_md(assessment.url, snippets),
        )

    # --- 5. Passive OSINT (`osint/`) ---
    if assessment.intel is not None:
        _record_text("osint/intel.json", "osint", dumps_json(assessment.intel))
    if ct_result is not None:
        _record_text("osint/ct.json", "osint", dumps_json(ct_result))
        sub_lines = [
            f"# Passive Certificate Transparency subdomains for {ct_result.domain}",
            "# Review and explicitly authorize before adding to scope.yaml.",
            *ct_result.unique_subdomains,
        ]
        _record_text("osint/ct_subdomains.txt", "osint", "\n".join(sub_lines) + "\n")

    # --- 6. Compiled Reports (`reports/`) ---
    if include_reports:
        _record_text("reports/profile.json", "report", dumps_json(prof))
        _record_text("reports/fingerprint.json", "report", dumps_json(assessment.fingerprint))
        if assessment.cve is not None:
            _record_text("reports/cves.json", "report", dumps_json(assessment.cve))
        _record_text("reports/assess.json", "report", dumps_json(assessment))

        bundle = build_report_bundle_from_assessment(
            assessment,
            operator=operator,
            scope_manager=scope_manager,
        )
        _record_text("reports/report.md", "report", report_service.render(bundle, fmt="md"))
        _record_text("reports/report.html", "report", report_service.render(bundle, fmt="html"))
        _record_text(
            "reports/report.sarif",
            "report",
            report_service.render(bundle, fmt="sarif"),
        )

    # Optional pre-written files in the same output directory (used by `assess --dump-evidence`)
    seen_rel = {e.relative_path for e in entries}
    for extra_path, extra_cat in extra_manifest_entries:
        resolved_extra = extra_path.expanduser().resolve()
        if not resolved_extra.is_file():
            continue
        try:
            rel_str = resolved_extra.relative_to(root).as_posix()
        except ValueError:
            continue
        if rel_str in seen_rel:
            continue
        chmod_private_file(resolved_extra)
        raw_bytes = resolved_extra.read_bytes()
        entries.append(
            DumpFileEntry(
                relative_path=rel_str,
                category=extra_cat,
                size_bytes=len(raw_bytes),
                sha256=hashlib.sha256(raw_bytes).hexdigest(),
            )
        )
        seen_rel.add(rel_str)

    entries.sort(key=lambda e: e.relative_path)
    total_bytes = sum(e.size_bytes for e in entries)

    # --- 7. Chain-of-Custody Manifest (`evidence_manifest.json`) ---
    generated_ts = utc_now_iso()
    manifest_payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "tool_version": __version__,
        "artifact_type": "evidence_manifest",
        "generated_at_utc": generated_ts,
        "target": assessment.target,
        "url": assessment.url,
        "pinned_ip": assessment.pinned_ip,
        "scope_id": assessment.scope_id,
        "auth_ref": assessment.auth_ref,
        "authorized_via": prof.authorized_via,
        "posture": {
            "score": assessment.posture.score,
            "grade": assessment.posture.grade,
            "risk_level": assessment.posture.risk_level,
            "finding_count": len(assessment.findings),
        },
        "capture_options": {
            "include_body": include_body,
            "body_captured": body_captured,
            "body_redacted": body_redacted,
            "body_truncated": body_truncated,
        },
        "entity_counts": entity_counts,
        "file_count": len(entries),
        "total_bytes": total_bytes,
        "files": [to_json_compatible(e) for e in entries],
        "warnings": warn_list,
    }
    manifest_path = root / "evidence_manifest.json"
    atomic_write_private_text(manifest_path, dumps_json(manifest_payload))

    archive_path_str: str | None = None
    archive_sha256: str | None = None
    if archive:
        arch_path, arch_sha = _create_private_tar_gz(root)
        archive_path_str = str(arch_path)
        archive_sha256 = arch_sha

    return DumpResult(
        target=assessment.target,
        url=assessment.url,
        pinned_ip=assessment.pinned_ip,
        scope_id=assessment.scope_id,
        auth_ref=assessment.auth_ref,
        out_dir=str(root),
        manifest_path=str(manifest_path),
        posture_score=assessment.posture.score,
        posture_grade=assessment.posture.grade,
        risk_level=assessment.posture.risk_level,
        finding_count=len(assessment.findings),
        file_count=len(entries),
        total_bytes=total_bytes,
        body_captured=body_captured,
        body_redacted=body_redacted,
        body_truncated=body_truncated,
        archive_path=archive_path_str,
        archive_sha256=archive_sha256,
        files=entries,
        entity_counts=entity_counts,
        warnings=warn_list,
        generated_at_utc=generated_ts,
    )
