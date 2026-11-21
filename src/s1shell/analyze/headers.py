"""100% offline HTTP response header, CSP, cookie, banner & stack posture auditor."""

from __future__ import annotations

import json
import re
from dataclasses import asdict

from s1shell.analyze.csp import analyze_csp
from s1shell.analyze.models import HeaderOfflineResult
from s1shell.assess.remediate import generate_remediation_plan
from s1shell.assess.scorer import evaluate_posture_with_suppressions
from s1shell.errors import ValidationError
from s1shell.fingerprint.matcher import match_signatures
from s1shell.fingerprint.models import FingerprintResult
from s1shell.profile.header_check import analyze_headers, detect_http3_from_alt_svc
from s1shell.profile.models import DNSRecords, ProfileResult, ProtocolInfo

_STATUS_LINE_RE = re.compile(r"^(HTTP/\d(?:\.\d)?)\s+(\d{3})(?:\s+.*)?$", re.IGNORECASE)


def parse_raw_http_headers(raw_text: str) -> tuple[str | None, int | None, list[tuple[str, str]]]:
    """Parse raw HTTP response headers (curl -i, Burp, DevTools, or plain Name: Value lines)."""
    http_ver: str | None = None
    status_code: int | None = None
    headers: list[tuple[str, str]] = []

    for raw_line in raw_text.splitlines():
        line = raw_line.rstrip("\r\n")
        stripped = line.strip()
        if not stripped:
            # Stop at body delimiter if we already collected headers
            if headers:
                break
            continue
        sm = _STATUS_LINE_RE.match(stripped)
        if sm:
            http_ver = sm.group(1).upper()
            status_code = int(sm.group(2))
            continue
        if ":" in stripped:
            name, val = stripped.split(":", 1)
            cname = name.strip()
            if cname and " " not in cname and not cname.startswith("<"):
                headers.append((cname, val.strip()))
    return http_ver, status_code, headers


def analyze_raw_headers(
    raw_text: str,
    *,
    url: str = "https://offline.local/",
    preset: str = "web",
    source: str = "inline",
) -> HeaderOfflineResult:
    """Audit raw HTTP response headers (or a saved profile.json) offline with zero traffic."""
    stripped = raw_text.strip()
    if not stripped:
        raise ValidationError("Provide raw HTTP response headers via text, stdin, or `--file`.")

    http_ver: str | None = None
    status_code: int | None = None
    headers: list[tuple[str, str]] = []
    effective_url = url

    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
        except ValueError as exc:
            raise ValidationError(f"Invalid JSON input: {exc}") from exc
        if isinstance(data, dict):
            prof = data.get("profile") if data.get("artifact_type") == "assess_report" else data
            if isinstance(prof, dict) and isinstance(prof.get("raw_headers"), list):
                effective_url = str(prof.get("url") or effective_url)
                proto = prof.get("protocol") if isinstance(prof.get("protocol"), dict) else {}
                http_ver = str(proto.get("http_version") or "") or None
                status_code = int(proto["status_code"]) if proto.get("status_code") else None
                for pair in prof["raw_headers"]:
                    if isinstance(pair, (list, tuple)) and len(pair) == 2:
                        headers.append((str(pair[0]), str(pair[1])))
    else:
        http_ver, status_code, headers = parse_raw_http_headers(stripped)

    if not headers:
        raise ValidationError("No valid `Header-Name: value` lines found in input.")

    is_https = effective_url.lower().startswith("https://")
    hdr_analysis = analyze_headers(headers, is_https=is_https)

    alt_svc = next((v for k, v in headers if k.lower() == "alt-svc"), None)
    redir = next((v for k, v in headers if k.lower() == "location"), None)

    profile = ProfileResult(
        target=effective_url,
        url=effective_url,
        pinned_ip="offline",
        scope_id="offline",
        auth_ref="offline",
        authorized_via="offline",
        dns=DNSRecords(),
        protocol=ProtocolInfo(
            http_version=http_ver or "HTTP/1.1",
            status_code=status_code if status_code is not None else 200,
            redirect_location=redir,
            alt_svc=alt_svc,
            http3_advertised=detect_http3_from_alt_svc(alt_svc),
        ),
        tls=None,
        headers=hdr_analysis,
        raw_headers=headers,
    )

    matches = match_signatures(headers)
    fp_res = FingerprintResult(
        target=effective_url,
        url=effective_url,
        mode="from_profile",
        scope_id="offline",
        auth_ref="offline",
        matches=matches,
    )

    posture, findings, _ = evaluate_posture_with_suppressions(profile, fp_res, preset=preset)
    # Remove transport/DNS findings that require live probing rather than headers alone
    header_findings = [
        f
        for f in findings
        if f.category in {"headers", "cookies", "cors", "disclosure", "cve"}
        or f.id.startswith(("HDR-", "COOKIE-", "CORS-", "DISC-", "EOL-"))
    ]

    csp_val = next((v for k, v in headers if k.lower() == "content-security-policy"), None)
    csp_res = analyze_csp(csp_val, source=source) if csp_val else None

    match_dicts = [asdict(m) for m in matches]
    rem_plan = generate_remediation_plan(
        target_url=effective_url,
        findings=header_findings,
        fingerprint_matches=match_dicts,
        stack="auto",
    )

    return HeaderOfflineResult(
        source=source,
        url=effective_url,
        status_code=status_code,
        http_version=http_ver,
        preset=preset,
        score=posture.score,
        grade=posture.grade,
        risk_level=posture.risk_level,
        header_count=len(headers),
        fingerprints=match_dicts,
        csp_analysis=csp_res,
        findings=[asdict(f) for f in header_findings],
        remediation_snippets=[asdict(s) for s in rem_plan.snippets],
    )
