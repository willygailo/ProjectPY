"""Terminal (Rich), JSON, Markdown, HTML, SARIF, and file output helpers."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from rich.console import Console
from rich.table import Table

from s1shell.ai.models import AIAnalysisResult, AIEnvStatus, AIInvestigationResult
from s1shell.ai.skills import AISkill, AISkillsCatalog
from s1shell.assess.models import (
    AssessmentDiffResult,
    AssessmentResult,
    BatchAssessmentResult,
    RemediationPlan,
)
from s1shell.assess.service import build_report_bundle_from_assessment
from s1shell.audit import AuditEvent, AuditVerifyResult
from s1shell.codec.models import CodecHashResult, CodecInspectResult, CodecTransformResult
from s1shell.config import RuntimeConfig
from s1shell.cve.models import CVESearchResult, DependencyAuditResult
from s1shell.doctor import DoctorReport
from s1shell.errors import ValidationError
from s1shell.fingerprint.models import FingerprintResult
from s1shell.intel.models import (
    CTLookupResult,
    GitHubAdvisoryResult,
    IntelEnvStatus,
    IntelLookupResult,
    RDAPLookupResult,
)
from s1shell.models import dumps_json
from s1shell.profile.models import ProfileResult
from s1shell.report.sarif import render_dependency_sarif
from s1shell.report.service import ReportService
from s1shell.scope import ScopeCheckResult, ScopeEntry, ScopeImportResult
from s1shell.tor import TorCheckResult, TorStatusResult


def make_console(*, no_color: bool = False, file: TextIO | None = None) -> Console:
    """Construct a Rich Console respecting `--no-color`."""
    return Console(no_color=no_color, highlight=not no_color, file=file)


def write_or_print(
    text: str,
    *,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Write text output to `--out` file or stdout."""
    if out_file is not None:
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(text, encoding="utf-8")
        return
    if stdout is not None:
        stdout.write(text)
        if not text.endswith("\n"):
            stdout.write("\n")
    else:
        print(text)


def _require_format(fmt: str, allowed: Sequence[str], *, command: str) -> str:
    norm = fmt.lower()
    if norm not in allowed:
        opts = ", ".join(allowed)
        raise ValidationError(f"Unsupported format '{fmt}' for `{command}`. Choose {opts}.")
    return norm


def _md_cell(value: str | None) -> str:
    if not value:
        return "—"
    return value.replace("\r\n", " ").replace("\n", " ").replace("|", "\\|")


def _emit_tables(
    tables: Sequence[Table],
    *,
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    if out_file is not None:
        buf_console = Console(no_color=True, width=120)
        with buf_console.capture() as cap:
            for tbl in tables:
                buf_console.print(tbl)
        write_or_print(cap.get(), out_file=out_file, stdout=stdout)
        return
    for tbl in tables:
        console.print(tbl)


def render_cve_result(
    result: CVESearchResult,
    *,
    fmt: str,
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Render CVE search or get results in `table`, `json`, or `md`."""
    norm = _require_format(fmt, ("table", "json", "md"), command="cve")
    if norm == "json":
        write_or_print(dumps_json(result), out_file=out_file, stdout=stdout)
        return
    if norm == "md":
        lines = [
            "| CVE ID | Priority | CVSS | Severity | KEV | EPSS | Published | Description |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for rec in result.records:
            score = str(rec.cvss.base_score) if rec.cvss else "—"
            sev = rec.cvss.severity if rec.cvss else "—"
            kev = "YES" if rec.in_kev else "—"
            epss = f"{rec.epss_score * 100:.1f}%" if rec.epss_score is not None else "—"
            desc = _md_cell(rec.description)
            lines.append(
                f"| `{rec.cve_id}` | `{rec.priority}` | {score} | {sev} | {kev} | {epss} | "
                f"{rec.published[:10]} | {desc} |"
            )
        write_or_print("\n".join(lines), out_file=out_file, stdout=stdout)
        return

    table = Table(title=f"CVE Results (cached={result.cached})")
    table.add_column("CVE ID", style="cyan", no_wrap=True)
    table.add_column("Priority", no_wrap=True)
    table.add_column("CVSS", justify="right")
    table.add_column("Severity")
    table.add_column("KEV", no_wrap=True)
    table.add_column("EPSS", justify="right", no_wrap=True)
    table.add_column("Published", no_wrap=True)
    table.add_column("Description")
    for rec in result.records:
        score = f"{rec.cvss.base_score:.1f}" if rec.cvss else "—"
        sev = rec.cvss.severity if rec.cvss else "—"
        kev = "YES" if rec.in_kev else "—"
        epss = f"{rec.epss_score * 100:.1f}%" if rec.epss_score is not None else "—"
        desc = rec.description[:140] + ("..." if len(rec.description) > 140 else "")
        table.add_row(rec.cve_id, rec.priority, score, sev, kev, epss, rec.published[:10], desc)

    _emit_tables([table], console=console, out_file=out_file, stdout=stdout)


def render_dependency_audit(
    result: DependencyAuditResult,
    *,
    fmt: str,
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Render `s1shell cve audit` lockfile/SBOM findings in `table`, `json`, `md`, or `sarif`."""
    norm = _require_format(fmt, ("table", "json", "md", "sarif"), command="cve audit")
    if norm == "json":
        write_or_print(dumps_json(result), out_file=out_file, stdout=stdout)
        return
    if norm == "sarif":
        write_or_print(render_dependency_sarif(result), out_file=out_file, stdout=stdout)
        return
    if norm == "md":
        lines = [
            f"# S1shell Dependency & SBOM Audit: `{result.source_file}`",
            "",
            (
                f"- **Format:** `{result.format_detected}` | **Packages Scanned:** "
                f"{result.packages_scanned} | **Vulnerable Packages:** {result.vulnerable_packages}"
            ),
            f"- **Vulnerabilities Found:** {len(result.vulnerabilities)} (cached={result.cached})",
            "",
            "| Package | Version | Eco | ID / CVE | Priority | Sev | KEV | EPSS | Fix | Summary |",
            "|---|---|---|---|---|---|---|---|---|---|",
        ]
        for v in result.vulnerabilities:
            ident = f"{v.vuln_id} ({v.cve_id})" if v.cve_id and v.cve_id != v.vuln_id else v.vuln_id
            kev = "YES" if v.in_kev else "—"
            epss = f"{v.epss_score * 100:.1f}%" if v.epss_score is not None else "—"
            fix = ", ".join(v.fixed_versions[:2]) or "—"
            lines.append(
                f"| `{_md_cell(v.package)}` | `{_md_cell(v.version)}` | {v.ecosystem} | "
                f"`{_md_cell(ident)}` | `{v.priority}` | {v.severity} | {kev} | {epss} | "
                f"`{_md_cell(fix)}` | {_md_cell(v.summary)} |"
            )
        write_or_print("\n".join(lines), out_file=out_file, stdout=stdout)
        return

    table = Table(
        title=(
            f"Dependency Audit: {result.source_file} ({result.format_detected}, "
            f"{result.packages_scanned} pkgs, {len(result.vulnerabilities)} vulns)"
        )
    )
    table.add_column("Package", style="cyan")
    table.add_column("Version")
    table.add_column("ID / CVE", no_wrap=True)
    table.add_column("Priority", no_wrap=True)
    table.add_column("Sev")
    table.add_column("KEV")
    table.add_column("EPSS", justify="right")
    table.add_column("Fixed")
    table.add_column("Summary")
    for v in result.vulnerabilities:
        ident = v.cve_id or v.vuln_id
        kev = "YES" if v.in_kev else "—"
        epss = f"{v.epss_score * 100:.1f}%" if v.epss_score is not None else "—"
        fix = ", ".join(v.fixed_versions[:2]) or "—"
        summ = v.summary[:100] + ("..." if len(v.summary) > 100 else "")
        table.add_row(v.package, v.version, ident, v.priority, v.severity, kev, epss, fix, summ)
    _emit_tables([table], console=console, out_file=out_file, stdout=stdout)


def render_scope_entries(
    entries: list[ScopeEntry],
    *,
    fmt: str,
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Render scope entries as Rich table, JSON, or Markdown."""
    norm = _require_format(fmt, ("table", "json", "md"), command="scope")
    if norm == "json":
        write_or_print(dumps_json({"entries": entries}), out_file=out_file, stdout=stdout)
        return
    if norm == "md":
        lines = [
            "| ID | Target | Type | Subdomains | Owner | Auth Ref | Expires | Status |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for e in entries:
            status = "EXPIRED" if e.is_expired() else ("EXCLUDE" if e.exclude else "ACTIVE")
            lines.append(
                f"| `{e.id}` | `{_md_cell(e.target)}` | {e.type} | {e.include_subdomains} | "
                f"{_md_cell(e.owner)} | {_md_cell(e.auth_ref)} | {e.expires_at} | {status} |"
            )
        write_or_print("\n".join(lines), out_file=out_file, stdout=stdout)
        return

    table = Table(title="Authorized Scope Entries")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Target", min_width=16, overflow="fold")
    table.add_column("Type", no_wrap=True)
    table.add_column("Sub", no_wrap=True)
    table.add_column("Owner")
    table.add_column("Ref")
    table.add_column("Expires", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    for e in entries:
        status = "EXPIRED" if e.is_expired() else ("EXCLUDE" if e.exclude else "ACTIVE")
        table.add_row(
            e.id,
            e.target,
            e.type,
            "yes" if e.include_subdomains else "no",
            e.owner,
            e.auth_ref,
            e.expires_at,
            status,
        )
    _emit_tables([table], console=console, out_file=out_file, stdout=stdout)


def render_scope_import(
    result: ScopeImportResult,
    *,
    fmt: str,
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Render `s1shell scope import` summary."""
    norm = _require_format(fmt, ("table", "json", "md"), command="scope import")
    if norm == "json":
        write_or_print(dumps_json(result), out_file=out_file, stdout=stdout)
        return
    mode_tag = "DRY-RUN" if result.dry_run else "APPLIED"
    if norm == "md":
        lines = [
            f"# Scope Import ({mode_tag}): `{result.source}`",
            "",
            (
                f"- **Added:** {len(result.added)} | **Skipped (duplicates):** "
                f"{len(result.skipped)} | **Errors:** {len(result.errors)}"
            ),
        ]
        if result.added:
            lines.extend(["", "| ID | Target | Type | Rule |", "|---|---|---|---|"])
            for e in result.added:
                rule = "EXCLUDE" if e.exclude else "ALLOW"
                lines.append(f"| `{e.id}` | `{_md_cell(e.target)}` | {e.type} | {rule} |")
        if result.errors:
            lines.extend(["", "## Errors", ""])
            for err in result.errors:
                lines.append(f"- {err}")
        write_or_print("\n".join(lines), out_file=out_file, stdout=stdout)
        return

    tbl = Table(title=f"Scope Import ({mode_tag}): {result.source}")
    tbl.add_column("Metric", style="cyan", no_wrap=True)
    tbl.add_column("Value")
    tbl.add_row("Added", str(len(result.added)))
    tbl.add_row("Skipped (active duplicates)", str(len(result.skipped)))
    tbl.add_row("Errors", str(len(result.errors)))
    if result.errors:
        tbl.add_row("Error Details", "\n".join(result.errors[:10]))
    _emit_tables([tbl], console=console, out_file=out_file, stdout=stdout)


def render_scope_check(
    result: ScopeCheckResult,
    *,
    fmt: str,
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Render `scope check` decision."""
    norm = _require_format(fmt, ("table", "json", "md"), command="scope check")
    if norm == "json":
        write_or_print(dumps_json(result), out_file=out_file, stdout=stdout)
        return
    status = "IN SCOPE" if result.in_scope else "OUT OF SCOPE"
    ips = ", ".join(result.resolved_ips) if result.resolved_ips else "none"
    if norm == "md":
        lines = [
            "| Status | Target | Resolved IPs | Pinned IP | Reason |",
            "|---|---|---|---|---|",
            (
                f"| **{status}** | `{_md_cell(result.parsed_target.raw)}` | "
                f"`{_md_cell(ips)}` | `{result.pinned_ip or '—'}` | {_md_cell(result.reason)} |"
            ),
        ]
        write_or_print("\n".join(lines), out_file=out_file, stdout=stdout)
        return
    text = f"[{status}] target={result.parsed_target.raw} resolved_ips=[{ips}] — {result.reason}"
    if out_file is not None or stdout is not None:
        write_or_print(text, out_file=out_file, stdout=stdout)
    else:
        console.print(text)


def _append_profile_entity_markdown(
    result: ProfileResult,
    lines: list[str],
    *,
    intel: IntelLookupResult | None = None,
) -> None:
    """Append Markdown sections for extracted identity, emails, phones, keys/IDs & endpoints."""
    html = result.html
    wk = result.well_known
    tls = result.tls
    rdap = intel.rdap if intel is not None else None

    all_emails: list[str] = []
    if html and html.emails:
        for em in html.emails:
            if em not in all_emails:
                all_emails.append(em)
    if wk and wk.security_txt_contacts:
        for sc in wk.security_txt_contacts:
            val = sc[7:] if sc.lower().startswith("mailto:") else sc
            if val and val not in all_emails:
                all_emails.append(val)
    if rdap:
        for em in rdap.emails:
            tag = f"{em} (RDAP)"
            if em not in all_emails and tag not in all_emails:
                all_emails.append(tag)

    all_phones: list[str] = []
    if html and html.phone_numbers:
        for ph in html.phone_numbers:
            if ph not in all_phones:
                all_phones.append(ph)
    if rdap:
        for ph in rdap.phone_numbers:
            tag = f"{ph} (RDAP)"
            if ph not in all_phones and tag not in all_phones:
                all_phones.append(tag)

    identities: list[str] = []
    if html and html.title:
        identities.append(f"Title: {html.title}")
    if html and html.meta_generator:
        identities.append(f"Generator: {html.meta_generator}")
    if html and html.identities_and_names:
        for item in html.identities_and_names:
            identities.append(f"{item.get('kind', 'meta')}: {item.get('value', '')}")
    if tls and tls.applicable and tls.subject:
        identities.append(f"TLS Subject: {tls.subject}")
    if tls and tls.applicable and tls.serial_number:
        identities.append(f"TLS Serial ID: {tls.serial_number}")
    if rdap:
        if rdap.handle or rdap.name:
            identities.append(f"RDAP Handle/Name: {rdap.handle or '—'} / {rdap.name or '—'}")
        if rdap.organization or rdap.registrar:
            identities.append(
                f"RDAP Org/Registrar: {rdap.organization or '—'} / {rdap.registrar or '—'}"
            )
        for ent in rdap.entities[:6]:
            identities.append(f"RDAP Entity: {ent}")
    if intel and intel.virustotal and intel.virustotal.as_owner:
        identities.append(f"AS Owner: {intel.virustotal.as_owner}")

    lines.extend(
        ["", "## Target Identity, Contacts (Email / Gmail / Phone) & Surface Metadata", ""]
    )
    lines.append(f"- **Target URL / Host:** `{result.url}` (Pinned IP: `{result.pinned_ip}`)")
    lines.append(
        f"- **Identities & Names:** "
        f"{'; '.join(f'`{_md_cell(i)}`' for i in identities) if identities else 'none detected'}"
    )
    lines.append(
        f"- **Emails & Gmail Contacts:** "
        f"{', '.join(f'`{_md_cell(e)}`' for e in all_emails) if all_emails else 'none detected'}"
    )
    lines.append(
        f"- **Phone / Contact Numbers:** "
        f"{', '.join(f'`{_md_cell(p)}`' for p in all_phones) if all_phones else 'none detected'}"
    )
    if html and html.social_links:
        lines.append(
            f"- **Social & External Profiles:** "
            f"{', '.join(f'`{_md_cell(s)}`' for s in html.social_links[:12])}"
        )
    if html and html.cloud_and_api_endpoints:
        lines.append(
            f"- **Cloud Buckets & API Endpoints:** "
            f"{', '.join(f'`{_md_cell(ep)}`' for ep in html.cloud_and_api_endpoints[:15])}"
        )
    if tls and tls.applicable and tls.sans:
        lines.append(f"- **TLS Certificate SANs:** `{', '.join(tls.sans[:15])}`")

    keys_and_ids = list(html.exposed_ids_and_keys) if (html and html.exposed_ids_and_keys) else []
    jwts = list(html.passive_jwts) if (html and html.passive_jwts) else []
    if keys_and_ids or jwts:
        lines.extend(
            [
                "",
                "## Exposed Keys, App / Client IDs & Passive Tokens",
                "",
                "| Type | Key / ID / Token Summary | Location |",
                "|---|---|---|",
            ]
        )
        for k in keys_and_ids:
            lines.append(
                f"| `{_md_cell(k.get('type', 'id'))}` | `{_md_cell(k.get('value', '—'))}` | "
                f"`{_md_cell(k.get('location', 'html'))}` |"
            )
        for j in jwts:
            claims = ", ".join(j.get("claim_keys", [])) or "none"
            lines.append(
                f"| `jwt ({j.get('alg', '?')})` | `claims=[{claims}] exp={j.get('has_exp')}` | "
                f"`{_md_cell(str(j.get('location', 'html')))}` |"
            )


def _build_profile_entity_tables(
    result: ProfileResult,
    *,
    intel: IntelLookupResult | None = None,
) -> list[Table]:
    """Build Rich tables displaying Target Identity, Emails/Gmail, Phones, Keys/IDs & Endpoints."""
    html = result.html
    wk = result.well_known
    tls = result.tls
    rdap = intel.rdap if intel is not None else None
    out: list[Table] = []

    all_emails: list[str] = []
    if html and html.emails:
        for em in html.emails:
            if em not in all_emails:
                all_emails.append(em)
    if wk and wk.security_txt_contacts:
        for sc in wk.security_txt_contacts:
            val = sc[7:] if sc.lower().startswith("mailto:") else sc
            if val and val not in all_emails:
                all_emails.append(f"{val} (security.txt)")
    if rdap:
        for em in rdap.emails:
            tag = f"{em} (RDAP)"
            if em not in all_emails and tag not in all_emails:
                all_emails.append(tag)

    all_phones: list[str] = []
    if html and html.phone_numbers:
        for ph in html.phone_numbers:
            if ph not in all_phones:
                all_phones.append(ph)
    if rdap:
        for ph in rdap.phone_numbers:
            tag = f"{ph} (RDAP)"
            if ph not in all_phones and tag not in all_phones:
                all_phones.append(tag)

    names_list: list[str] = []
    if html and html.title:
        names_list.append(f"Title: {html.title}")
    if html and html.meta_generator:
        names_list.append(f"Generator: {html.meta_generator}")
    if html and html.identities_and_names:
        for item in html.identities_and_names:
            names_list.append(f"{item.get('kind', 'meta')}: {item.get('value', '')}")
    if rdap:
        if rdap.organization or rdap.registrar:
            names_list.append(
                f"RDAP Org/Registrar: {rdap.organization or '—'} / {rdap.registrar or '—'}"
            )
        if rdap.handle or rdap.name:
            names_list.append(f"RDAP Handle/Name: {rdap.handle or '—'} / {rdap.name or '—'}")
        for ent in rdap.entities[:6]:
            names_list.append(f"RDAP Entity: {ent}")
    if intel and intel.virustotal and intel.virustotal.as_owner:
        names_list.append(f"AS Owner: {intel.virustotal.as_owner}")

    entity_tbl = Table(
        title=f"Target Identity, Contacts (Email / Gmail / Phone) & Surface Entities: {result.url}"
    )
    entity_tbl.add_column("Category", style="cyan", no_wrap=True)
    entity_tbl.add_column("Extracted Values / Details", overflow="fold")
    entity_tbl.add_row("Target URL / Host / IP", f"{result.url} | Pinned IP: {result.pinned_ip}")
    if tls and tls.applicable:
        cert_parts: list[str] = []
        if tls.subject:
            cert_parts.append(f"Subject={tls.subject}")
        if tls.issuer:
            cert_parts.append(f"Issuer={tls.issuer}")
        if tls.serial_number:
            cert_parts.append(f"Serial={tls.serial_number}")
        if tls.spki_sha256:
            cert_parts.append(f"SPKI={tls.spki_sha256}")
        if cert_parts:
            entity_tbl.add_row("TLS Cert Identity & ID", " | ".join(cert_parts))
        if tls.sans:
            extra_sans = f" (+{len(tls.sans) - 15} more)" if len(tls.sans) > 15 else ""
            entity_tbl.add_row(
                "Certificate SANs / Domains",
                ", ".join(tls.sans[:15]) + extra_sans,
            )
    entity_tbl.add_row(
        "Names / Org / Identity",
        "\n".join(names_list) if names_list else "none detected in HTML/RDAP",
    )
    entity_tbl.add_row(
        "Emails & Gmail Contacts",
        ", ".join(all_emails) if all_emails else "none detected",
    )
    entity_tbl.add_row(
        "Phone / Contact Numbers",
        ", ".join(all_phones) if all_phones else "none detected",
    )
    keys_and_ids = list(html.exposed_ids_and_keys) if (html and html.exposed_ids_and_keys) else []
    jwts = list(html.passive_jwts) if (html and html.passive_jwts) else []
    if keys_and_ids or jwts:
        key_summaries = [
            f"{k.get('type', 'id')}={k.get('value', '—')} ({k.get('location', 'html')})"
            for k in keys_and_ids[:15]
        ]
        for j in jwts[:5]:
            claims = ",".join(j.get("claim_keys", []))
            key_summaries.append(
                f"jwt[{j.get('alg', '?')}]: claims=({claims}) ({j.get('location', 'html')})"
            )
        entity_tbl.add_row("Keys / Client & App IDs", "\n".join(key_summaries))
    else:
        entity_tbl.add_row("Keys / Client & App IDs", "none detected")

    if html and html.social_links:
        entity_tbl.add_row("Social & Profile Links", "\n".join(html.social_links[:10]))
    if html and html.cloud_and_api_endpoints:
        entity_tbl.add_row(
            "Cloud Buckets & API Paths",
            ", ".join(html.cloud_and_api_endpoints[:15]),
        )
    if html and html.third_party_origins:
        entity_tbl.add_row(
            "Third-Party Origins",
            ", ".join(html.third_party_origins[:12]),
        )
    if wk and (
        wk.security_txt_present or wk.robots_txt_present or wk.oidc_issuer or wk.jwks_key_count
    ):
        wk_parts: list[str] = []
        if wk.security_txt_present:
            wk_parts.append(
                f"security.txt=present (contacts={', '.join(wk.security_txt_contacts) or 'none'})"
            )
        if wk.robots_txt_present:
            hints_txt = ", ".join(wk.robots_sensitive_hints[:6]) or "none"
            wk_parts.append(f"robots.txt=present (sensitive_paths={hints_txt})")
        if wk.oidc_issuer:
            wk_parts.append(f"OIDC issuer={wk.oidc_issuer}")
        if wk.jwks_key_count:
            wk_parts.append(f"JWKS keys={wk.jwks_key_count}")
        entity_tbl.add_row("Well-Known Surface", " | ".join(wk_parts))
    out.append(entity_tbl)
    return out


def render_profile_result(
    result: ProfileResult,
    *,
    fmt: str,
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Render `profile` output in `json`, `md`, or `table`."""
    norm = _require_format(fmt, ("table", "json", "md"), command="profile")
    if norm == "json":
        write_or_print(dumps_json(result), out_file=out_file, stdout=stdout)
        return
    if norm == "md":
        proto_line = (
            f"- **HTTP:** {result.protocol.status_code} "
            f"({result.protocol.http_version}, ALPN: `{result.protocol.alpn_protocol}`)"
        )
        lines = [
            f"# Profile: {result.url}",
            "",
            f"- **Pinned IP:** `{result.pinned_ip}`",
            f"- **Scope Ref:** `{result.auth_ref}` (`{result.scope_id}`)",
            proto_line,
            f"- **HTTP/3 Advertised:** {'Yes' if result.protocol.http3_advertised else 'No'}",
        ]
        if result.protocol.redirect_location:
            lines.append(f"- **Redirect (not followed):** `{result.protocol.redirect_location}`")
        if result.protocol.methods_checked:
            lines.append(
                f"- **HTTP Methods (`OPTIONS`):** "
                f"`{', '.join(result.protocol.allowed_methods) or 'none'}`"
            )
        lines.append(
            f"- **DNS:** A=`{', '.join(result.dns.a) or 'none'}`, "
            f"AAAA=`{', '.join(result.dns.aaaa) or 'none'}`, "
            f"CNAME=`{', '.join(result.dns.cname) or 'none'}`"
        )
        if result.dns.errors:
            lines.append(f"- **DNS Errors:** `{'; '.join(result.dns.errors)}`")
        if result.tls and result.tls.applicable:
            lines.append(
                f"- **TLS:** {result.tls.negotiated_version} (`{result.tls.cipher_suite}`), "
                f"Verified={result.tls.verified}, Expires={result.tls.not_after} "
                f"({result.tls.days_remaining} days)"
            )
            if result.tls.spki_sha256:
                lines.append(f"- **SPKI SHA-256 Pin:** `{result.tls.spki_sha256}`")
            if result.tls.supported_versions:
                lines.append(
                    f"- **Supported TLS Versions:** `{', '.join(result.tls.supported_versions)}`"
                )
            if result.tls.verification_error:
                lines.append(f"- **TLS Verification Error:** `{result.tls.verification_error}`")
        lines.extend(["", "| Header | Status | Value | Note |", "|---|---|---|---|"])
        for h in result.headers.security_headers:
            lines.append(
                f"| `{h.header}` | {h.status} | `{_md_cell(h.value)}` | {_md_cell(h.note)} |"
            )
        if result.headers.banner_disclosures:
            lines.extend(["", "**Banner Disclosures:**"])
            for b in result.headers.banner_disclosures:
                lines.append(f"- `{b.header}: {b.value}`")
        if result.headers.cookies:
            lines.extend(["", "| Cookie | Secure | HttpOnly | SameSite |", "|---|---|---|---|"])
            for c in result.headers.cookies:
                lines.append(
                    f"| `{_md_cell(c.name)}` | {c.secure} | {c.http_only} | "
                    f"{_md_cell(c.same_site)} |"
                )
        _append_profile_entity_markdown(result, lines)
        write_or_print("\n".join(lines), out_file=out_file, stdout=stdout)
        return

    tables: list[Table] = []

    summary = Table(title=f"Target Profile: {result.url} ({result.pinned_ip})")
    summary.add_column("Property", style="cyan", no_wrap=True)
    summary.add_column("Value")
    summary.add_row("Scope Ref", f"{result.auth_ref} ({result.scope_id})")
    summary.add_row(
        "HTTP",
        f"{result.protocol.status_code} ({result.protocol.http_version}, "
        f"ALPN: {result.protocol.alpn_protocol or 'none'})",
    )
    summary.add_row("HTTP/3 Advertised", "Yes" if result.protocol.http3_advertised else "No")
    if result.protocol.redirect_location:
        summary.add_row("Redirect (not followed)", result.protocol.redirect_location)
    if result.protocol.methods_checked:
        meth_str = ", ".join(result.protocol.allowed_methods) or "none advertised"
        if result.protocol.risky_methods:
            meth_str += f" [RISKY: {', '.join(result.protocol.risky_methods)}]"
        summary.add_row("HTTP Methods", meth_str)
    summary.add_row(
        "DNS",
        f"A={', '.join(result.dns.a) or 'none'} | "
        f"AAAA={', '.join(result.dns.aaaa) or 'none'} | "
        f"CNAME={', '.join(result.dns.cname) or 'none'}",
    )
    if result.dns.errors:
        summary.add_row("DNS Errors", "; ".join(result.dns.errors))
    if result.tls and result.tls.applicable:
        tls_ver = result.tls.negotiated_version or "unknown"
        tls_cipher = result.tls.cipher_suite or "unknown"
        tls_state = "verified" if result.tls.verified else "UNVERIFIED"
        days = (
            f"{result.tls.days_remaining}d remaining"
            if result.tls.days_remaining is not None
            else "unknown"
        )
        summary.add_row("TLS", f"{tls_ver} ({tls_cipher}) [{tls_state}, {days}]")
        if result.tls.issuer:
            summary.add_row("TLS Issuer", result.tls.issuer)
        if result.tls.subject:
            summary.add_row("TLS Subject", result.tls.subject)
        if result.tls.serial_number:
            summary.add_row("TLS Serial ID", result.tls.serial_number)
        if result.tls.supported_versions:
            summary.add_row("TLS Versions", ", ".join(result.tls.supported_versions))
        if result.tls.spki_sha256:
            summary.add_row("TLS SPKI Pin", result.tls.spki_sha256)
    tables.append(summary)
    tables.extend(_build_profile_entity_tables(result))

    headers_tbl = Table(title="Security Headers")
    headers_tbl.add_column("Security Header")
    headers_tbl.add_column("Status")
    headers_tbl.add_column("Value")
    headers_tbl.add_column("Note")
    for h in result.headers.security_headers:
        headers_tbl.add_row(h.header, h.status, h.value or "—", h.note)
    tables.append(headers_tbl)

    if result.headers.banner_disclosures:
        banner_tbl = Table(title="Banner Disclosures")
        banner_tbl.add_column("Header", style="yellow")
        banner_tbl.add_column("Value")
        for b in result.headers.banner_disclosures:
            banner_tbl.add_row(b.header, b.value)
        tables.append(banner_tbl)

    if result.headers.cookies:
        cookie_tbl = Table(title="Set-Cookie Attributes")
        cookie_tbl.add_column("Cookie")
        cookie_tbl.add_column("Secure")
        cookie_tbl.add_column("HttpOnly")
        cookie_tbl.add_column("SameSite")
        for c in result.headers.cookies:
            cookie_tbl.add_row(
                c.name,
                "yes" if c.secure else "no",
                "yes" if c.http_only else "no",
                c.same_site or "—",
            )
        tables.append(cookie_tbl)

    _emit_tables(tables, console=console, out_file=out_file, stdout=stdout)


def render_fingerprint_result(
    result: FingerprintResult,
    *,
    fmt: str,
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Render passive fingerprint matches."""
    norm = _require_format(fmt, ("table", "json", "md"), command="fingerprint")
    if norm == "json":
        write_or_print(dumps_json(result), out_file=out_file, stdout=stdout)
        return
    if norm == "md":
        lines = [
            f"# Fingerprint: {result.target} ({result.mode})",
            "",
            "| Product | Version | Vendor | Category | Confidence | Evidence |",
            "|---|---|---|---|---|---|",
        ]
        for m in result.matches:
            lines.append(
                f"| {_md_cell(m.product)} | {_md_cell(m.version)} | {_md_cell(m.vendor)} | "
                f"{m.category} | {m.confidence} | `{_md_cell('; '.join(m.evidence))}` |"
            )
        write_or_print("\n".join(lines), out_file=out_file, stdout=stdout)
        return

    table = Table(title=f"Passive Fingerprints: {result.target}")
    table.add_column("Product", style="cyan")
    table.add_column("Version")
    table.add_column("Vendor")
    table.add_column("Category")
    table.add_column("Confidence")
    table.add_column("Evidence")
    for m in result.matches:
        table.add_row(
            m.product,
            m.version or "—",
            m.vendor,
            m.category,
            m.confidence,
            "; ".join(m.evidence),
        )
    _emit_tables([table], console=console, out_file=out_file, stdout=stdout)


def render_audit_events(
    events: list[AuditEvent],
    *,
    fmt: str,
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Render audit log records."""
    norm = _require_format(fmt, ("table", "json", "md"), command="audit list")
    if norm == "json":
        write_or_print(dumps_json({"events": events}), out_file=out_file, stdout=stdout)
        return
    if norm == "md":
        lines = [
            "| Timestamp | Category | Command | Target | Scope ID | Auth Ref | "
            "Outcome | Exit | Duration (ms) | Error |",
            "|---|---|---|---|---|---|---|---|---|---|",
        ]
        for ev in events:
            lines.append(
                f"| {ev.timestamp_utc} | {ev.category} | {_md_cell(ev.command)} | "
                f"`{_md_cell(ev.target)}` | `{ev.scope_id or '—'}` | "
                f"{_md_cell(ev.auth_ref)} | {ev.outcome} | {ev.exit_code} | "
                f"{ev.duration_ms} | {_md_cell(ev.error)} |"
            )
        write_or_print("\n".join(lines), out_file=out_file, stdout=stdout)
        return

    table = Table(title="S1shell Audit Log")
    table.add_column("Timestamp", no_wrap=True)
    table.add_column("Category")
    table.add_column("Command")
    table.add_column("Target")
    table.add_column("Scope")
    table.add_column("Ref")
    table.add_column("Outcome")
    table.add_column("Exit", justify="right")
    table.add_column("ms", justify="right")
    table.add_column("Error")
    for ev in events:
        err = (ev.error[:60] + "...") if ev.error and len(ev.error) > 60 else (ev.error or "—")
        table.add_row(
            ev.timestamp_utc,
            ev.category,
            ev.command,
            ev.target,
            ev.scope_id or "—",
            ev.auth_ref or "—",
            ev.outcome,
            str(ev.exit_code),
            str(ev.duration_ms),
            err,
        )
    _emit_tables([table], console=console, out_file=out_file, stdout=stdout)


def render_doctor_report(
    report: DoctorReport,
    *,
    fmt: str,
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Render `s1shell doctor` diagnostics in `table`, `json`, or `md`."""
    norm = _require_format(fmt, ("table", "json", "md"), command="doctor")
    if norm == "json":
        write_or_print(dumps_json(report), out_file=out_file, stdout=stdout)
        return
    if norm == "md":
        lines = [
            f"# S1shell Doctor (`healthy={report.healthy}`)",
            "",
            "| Check | Status | Detail |",
            "|---|---|---|",
        ]
        for chk in report.checks:
            lines.append(f"| `{chk.name}` | {chk.status} | {_md_cell(chk.detail)} |")
        write_or_print("\n".join(lines), out_file=out_file, stdout=stdout)
        return

    table = Table(title=f"S1shell Doctor (home={report.home_dir}, healthy={report.healthy})")
    table.add_column("Check", style="cyan", no_wrap=True)
    table.add_column("Status")
    table.add_column("Detail")
    for chk in report.checks:
        table.add_row(chk.name, chk.status.upper(), chk.detail)
    _emit_tables([table], console=console, out_file=out_file, stdout=stdout)


def render_ai_env_status(
    result: AIEnvStatus,
    *,
    fmt: str,
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Render `s1shell ai env` status in `table`, `json`, or `md`."""
    norm = _require_format(fmt, ("table", "json", "md"), command="ai env")
    if norm == "json":
        write_or_print(dumps_json(result), out_file=out_file, stdout=stdout)
        return
    if norm == "md":
        lines = [
            "# S1shell AI Environment Status",
            "",
            "| Field | Value |",
            "|---|---|",
            f"| Provider | `{_md_cell(result.provider)}` |",
            f"| Endpoint | `{_md_cell(result.base_url)}` |",
            f"| Configured | {'yes' if result.configured else 'no'} |",
            f"| Key | `{_md_cell(result.masked_key)}` |",
            f"| Key Type | `{result.key_type}` |",
            f"| Source | `{_md_cell(result.source)}` |",
            f"| Model | `{_md_cell(result.model)}` |",
            f"| Env File | `{_md_cell(result.env_file)}` |",
            f"| Note | {_md_cell(result.note)} |",
        ]
        write_or_print("\n".join(lines), out_file=out_file, stdout=stdout)
        return

    table = Table(title="S1shell AI Environment")
    table.add_column("Setting", style="cyan", no_wrap=True)
    table.add_column("Value")
    table.add_row("Provider", result.provider)
    table.add_row("Endpoint", result.base_url or "—")
    table.add_row("Configured", "yes" if result.configured else "no")
    table.add_row("API Key", result.masked_key or "—")
    table.add_row("Key Type", result.key_type)
    table.add_row("Source", result.source)
    table.add_row("Model", result.model)
    table.add_row("Env File", result.env_file)
    table.add_row("Note", result.note)
    _emit_tables([table], console=console, out_file=out_file, stdout=stdout)


def render_ai_analysis(
    result: AIAnalysisResult,
    *,
    fmt: str,
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Render `s1shell ai analyze` results in `table`, `json`, or `md`."""
    norm = _require_format(fmt, ("table", "json", "md"), command="ai analyze")
    if norm == "json":
        write_or_print(dumps_json(result), out_file=out_file, stdout=stdout)
        return

    meta_tags: list[str] = [f"mode={result.mode}"]
    if result.skill:
        meta_tags.append(f"skill={result.skill}")
    if result.pipeline:
        meta_tags.append(f"pipeline={result.pipeline}")
    if result.cached:
        meta_tags.append("cached=yes")
    if result.fallback_used:
        meta_tags.append(f"fallback={result.fallback_used}")
    if result.redacted:
        rest_str = ", restored" if result.restored else ""
        meta_tags.append(f"redacted={result.redactions_applied}{rest_str}")

    grounding_str = "—"
    if result.grounding is not None:
        g = result.grounding
        score_txt = f"{g.grounding_score:.2f}" if g.grounding_score is not None else "n/a"
        grounding_str = (
            f"score={score_txt} (verified={len(g.verified_refs)}, "
            f"ungrounded={len(g.ungrounded_refs)}) — {g.note}"
        )

    if norm == "md":
        lines = [
            f"# S1shell AI Analysis ({result.provider} / {result.model})",
            "",
            f"- **Execution:** `{' | '.join(meta_tags)}`",
            f"- **Task:** {result.task}",
            f"- **Artifacts:** {', '.join(result.input_artifacts) or 'none'}",
            f"- **Tokens:** input={result.input_tokens}, output={result.output_tokens}",
        ]
        if result.grounding is not None:
            lines.append(f"- **Grounding Verification:** {grounding_str}")
        if result.injection_warnings:
            lines.append(
                f"- **Prompt-Injection Guardrails:** {len(result.injection_warnings)} pattern(s) "
                f"neutralized ({'; '.join(result.injection_warnings[:3])})"
            )
        if result.pipeline_stages:
            stages_txt = " -> ".join(s.stage for s in result.pipeline_stages)
            lines.append(f"- **Pipeline Stages:** `{stages_txt}`")
        lines.extend(["", result.analysis])
        write_or_print("\n".join(lines), out_file=out_file, stdout=stdout)
        return

    table = Table(title=f"S1shell AI Analysis ({result.provider} / {result.model})")
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value")
    table.add_row("Execution", " | ".join(meta_tags))
    table.add_row("Task", result.task)
    table.add_row("Tokens", f"in={result.input_tokens}, out={result.output_tokens}")
    if result.pipeline_stages:
        table.add_row("Pipeline", " -> ".join(s.stage for s in result.pipeline_stages))
    if result.grounding is not None:
        table.add_row("Grounding", grounding_str)
    if result.injection_warnings:
        table.add_row(
            "Guardrails",
            f"Neutralized {len(result.injection_warnings)} injection pattern(s)",
        )
    table.add_row("Analysis", result.analysis)
    _emit_tables([table], console=console, out_file=out_file, stdout=stdout)


def render_ai_skills_catalog(
    catalog: AISkillsCatalog,
    *,
    fmt: str,
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Render `s1shell ai skills list` in `table`, `json`, or `md`."""
    norm = _require_format(fmt, ("table", "json", "md"), command="ai skills list")
    if norm == "json":
        write_or_print(dumps_json(catalog), out_file=out_file, stdout=stdout)
        return
    if norm == "md":
        lines = [
            f"# S1shell Defensive AI Skills ({len(catalog.skills)} loaded)",
            "",
            "| Skill ID | Category | Recommended Artifacts | Description |",
            "|---|---|---|---|",
        ]
        for s in catalog.skills:
            arts = ", ".join(s.recommended_artifacts) or "any"
            lines.append(
                f"| `{s.id}` | `{s.category}` | {_md_cell(arts)} | {_md_cell(s.description)} |"
            )
        write_or_print("\n".join(lines), out_file=out_file, stdout=stdout)
        return

    table = Table(title=f"S1shell Defensive AI Skills ({len(catalog.skills)} available)")
    table.add_column("Skill ID", style="cyan", no_wrap=True)
    table.add_column("Category", style="magenta", no_wrap=True)
    table.add_column("Source", no_wrap=True)
    table.add_column("Description")
    for s in catalog.skills:
        src = "bundled" if s.source == "bundled" else "custom"
        table.add_row(s.id, s.category, src, s.description)
    _emit_tables([table], console=console, out_file=out_file, stdout=stdout)


def render_ai_skill_detail(
    skill: AISkill,
    *,
    fmt: str,
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Render `s1shell ai skills show <id>` in `table`, `json`, or `md`."""
    norm = _require_format(fmt, ("table", "json", "md"), command="ai skills show")
    if norm == "json":
        write_or_print(dumps_json(skill), out_file=out_file, stdout=stdout)
        return
    if norm == "md":
        lines = [
            f"# AI Skill: {skill.name} (`{skill.id}`)",
            "",
            f"- **Category:** `{skill.category}` | **Source:** `{skill.source}`",
            f"- **Recommended Artifacts:** {', '.join(skill.recommended_artifacts) or 'any'}",
            f"- **Description:** {skill.description}",
            "",
            "## Output Sections",
            *[f"- {sec}" for sec in skill.output_sections],
            "",
            "## System Instructions",
            skill.system_prompt,
        ]
        write_or_print("\n".join(lines), out_file=out_file, stdout=stdout)
        return

    table = Table(title=f"AI Skill: {skill.name} ({skill.id})")
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value")
    table.add_row("Category", skill.category)
    table.add_row("Source", skill.source)
    table.add_row("Artifacts", ", ".join(skill.recommended_artifacts) or "any")
    table.add_row("Description", skill.description)
    table.add_row("Output Sections", "\n".join(f"- {s}" for s in skill.output_sections) or "—")
    table.add_row("System Prompt", skill.system_prompt)
    _emit_tables([table], console=console, out_file=out_file, stdout=stdout)


def render_ai_investigation(
    result: AIInvestigationResult,
    *,
    fmt: str,
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Render bounded read-only `s1shell ai investigate` results in `table`, `json`, or `md`."""
    norm = _require_format(fmt, ("table", "json", "md"), command="ai investigate")
    if norm == "json":
        write_or_print(dumps_json(result), out_file=out_file, stdout=stdout)
        return

    g_txt = "—"
    if result.grounding is not None:
        sc = (
            f"{result.grounding.grounding_score:.2f}"
            if result.grounding.grounding_score is not None
            else "n/a"
        )
        g_txt = f"score={sc} ({result.grounding.note})"

    if norm == "md":
        lines = [
            f"# S1shell Read-Only AI Investigation ({result.provider} / {result.model})",
            "",
            f"- **Goal:** {result.goal}",
            f"- **Steps Executed:** {len(result.steps)} | "
            f"**Tokens:** in={result.input_tokens}, out={result.output_tokens}",
            f"- **Grounding:** {g_txt}",
            "",
            "## Investigation Trace",
        ]
        for st in result.steps:
            tool_part = f" → `{st.tool}`" if st.tool else " → `final`"
            err_part = f" (error: {st.error})" if st.error else ""
            lines.append(f"- **Step {st.step}**{tool_part}: {st.thought}{err_part}")
        lines.extend(["", "## Final Defensive Brief", "", result.final_answer])
        write_or_print("\n".join(lines), out_file=out_file, stdout=stdout)
        return

    summary = Table(title=f"S1shell AI Investigation ({result.provider} / {result.model})")
    summary.add_column("Field", style="cyan", no_wrap=True)
    summary.add_column("Value")
    summary.add_row("Goal", result.goal)
    summary.add_row("Steps", str(len(result.steps)))
    summary.add_row("Tokens", f"in={result.input_tokens}, out={result.output_tokens}")
    summary.add_row("Grounding", g_txt)
    summary.add_row("Final Brief", result.final_answer)

    trace = Table(title="Read-Only Tool Trace")
    trace.add_column("#", no_wrap=True)
    trace.add_column("Action", style="magenta", no_wrap=True)
    trace.add_column("Thought")
    trace.add_column("Status")
    for st in result.steps:
        trace.add_row(
            str(st.step),
            st.tool or "final",
            st.thought[:100],
            f"ERR: {st.error}" if st.error else "ok",
        )
    _emit_tables([summary, trace], console=console, out_file=out_file, stdout=stdout)


def render_remediation_plan(
    plan: RemediationPlan,
    *,
    fmt: str,
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Render deterministic offline hardening playbook in `table`, `json`, or `md`."""
    norm = _require_format(fmt, ("table", "json", "md"), command="remediate")
    if norm == "json":
        write_or_print(dumps_json(plan), out_file=out_file, stdout=stdout)
        return
    if norm == "md":
        lines = [
            f"# S1shell Hardening Playbook: {plan.target}",
            "",
            f"- **Selected Stack:** `{plan.selected_stack}`",
            f"- **Detected Stacks:** `{', '.join(plan.detected_stacks) or 'generic'}`",
        ]
        for snip in plan.snippets:
            lines.extend(
                [
                    "",
                    f"## {snip.title} (`{', '.join(snip.finding_ids)}`)",
                    "",
                    f"```{snip.language}",
                    snip.config,
                    "```",
                ]
            )
        if not plan.snippets:
            lines.extend(["", "_No hardening snippets required for the active findings._"])
        write_or_print("\n".join(lines), out_file=out_file, stdout=stdout)
        return

    tbl = Table(
        title=f"Deterministic Hardening Playbook: {plan.target} (stack={plan.selected_stack})"
    )
    tbl.add_column("Section", style="cyan")
    tbl.add_column("Finding IDs")
    tbl.add_column("Recommended Configuration")
    for snip in plan.snippets:
        tbl.add_row(snip.title, ", ".join(snip.finding_ids), snip.config)
    _emit_tables([tbl], console=console, out_file=out_file, stdout=stdout)


def render_assessment_result(
    result: AssessmentResult,
    *,
    fmt: str,
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
    report_service: ReportService | None = None,
    operator: str | None = None,
) -> None:
    """Render `s1shell assess` results in `table`, `json`, `md`, `html`, or `sarif`."""
    norm = _require_format(fmt, ("table", "json", "md", "html", "sarif"), command="assess")
    if norm == "json":
        write_or_print(dumps_json(result), out_file=out_file, stdout=stdout)
        return
    if norm in {"html", "sarif"}:
        rep_svc = (
            report_service
            if report_service is not None
            else ReportService(RuntimeConfig.from_env())
        )
        bundle = build_report_bundle_from_assessment(
            result,
            operator=operator,
            scope_manager=rep_svc.scope_manager,
        )
        write_or_print(rep_svc.render(bundle, fmt=norm), out_file=out_file, stdout=stdout)
        return

    stack_summary = ", ".join(
        f"{m.product}{' ' + m.version if m.version else ''}" for m in result.fingerprint.matches
    )
    cve_count = len(result.cve.records) if result.cve is not None else 0
    counts_str = (
        f"CRITICAL={result.posture.counts.get('CRITICAL', 0)}, "
        f"HIGH={result.posture.counts.get('HIGH', 0)}, "
        f"MEDIUM={result.posture.counts.get('MEDIUM', 0)}, "
        f"LOW={result.posture.counts.get('LOW', 0)}, "
        f"INFO={result.posture.counts.get('INFO', 0)}"
    )

    if norm == "md":
        lines = [
            f"# S1shell Assessment: {result.url}",
            "",
            f"- **Pinned IP:** `{result.pinned_ip}` | **Preset:** `{result.preset}`",
            f"- **Scope Ref:** `{result.auth_ref}` (`{result.scope_id}`)",
            (
                f"- **Posture Score:** `{result.posture.score}/100` "
                f"(Grade `{result.posture.grade}`, Risk `{result.posture.risk_level}`)"
            ),
            f"- **Finding Counts:** {counts_str}",
            f"- **Detected Stack:** {stack_summary or 'none'}",
            f"- **Correlated CVEs:** {cve_count}",
            "",
            "## Prioritized Findings",
            "",
            "| ID | Severity | Category | OWASP / NIST | Title | Evidence | Remediation |",
            "|---|---|---|---|---|---|---|",
        ]
        for finding in result.findings:
            comp = f"{finding.owasp or '—'} / {finding.nist or '—'}"
            lines.append(
                f"| `{finding.id}` | {finding.severity} | {finding.category} | `{comp}` | "
                f"{_md_cell(finding.title)} | {_md_cell(finding.evidence)} | "
                f"{_md_cell(finding.remediation)} |"
            )
        _append_profile_entity_markdown(result.profile, lines, intel=result.intel)
        if result.ai_analysis is not None:
            lines.extend(["", "## AI Defensive Triage", "", result.ai_analysis.analysis])
        if result.saved_files:
            lines.extend(["", "## Saved Artifacts", ""])
            for path_str in result.saved_files:
                lines.append(f"- `{path_str}`")
        write_or_print("\n".join(lines), out_file=out_file, stdout=stdout)
        return

    tables: list[Table] = []
    summary = Table(title=f"Assessment Posture Summary: {result.url} ({result.pinned_ip})")
    summary.add_column("Metric", style="cyan", no_wrap=True)
    summary.add_column("Value")
    summary.add_row("Scope Ref", f"{result.auth_ref} ({result.scope_id}) | preset={result.preset}")
    summary.add_row(
        "Posture Score",
        (
            f"{result.posture.score}/100 "
            f"(Grade {result.posture.grade} | Risk {result.posture.risk_level})"
        ),
    )
    summary.add_row("Findings", counts_str)
    if result.suppressed_findings:
        summary.add_row("Suppressed", str(len(result.suppressed_findings)))
    summary.add_row("Detected Stack", stack_summary or "none")
    summary.add_row("Correlated CVEs", str(cve_count))
    if result.saved_files:
        summary.add_row("Saved Bundle", ", ".join(result.saved_files))
    tables.append(summary)
    tables.extend(_build_profile_entity_tables(result.profile, intel=result.intel))

    findings_tbl = Table(title="Prioritized Pentester Findings & Remediation")
    findings_tbl.add_column("ID", style="cyan", no_wrap=True)
    findings_tbl.add_column("Severity", no_wrap=True)
    findings_tbl.add_column("Category", no_wrap=True)
    findings_tbl.add_column("Title")
    findings_tbl.add_column("Evidence")
    findings_tbl.add_column("Remediation")
    for finding in result.findings:
        findings_tbl.add_row(
            finding.id,
            finding.severity,
            finding.category,
            finding.title,
            finding.evidence,
            finding.remediation,
        )
    tables.append(findings_tbl)

    if result.ai_analysis is not None:
        ai_tbl = Table(
            title=(
                f"AI Defensive Triage ({result.ai_analysis.provider} / {result.ai_analysis.model})"
            )
        )
        ai_tbl.add_column("Analysis")
        ai_tbl.add_row(result.ai_analysis.analysis)
        tables.append(ai_tbl)

    _emit_tables(tables, console=console, out_file=out_file, stdout=stdout)


def render_audit_verify(
    result: AuditVerifyResult,
    *,
    fmt: str,
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Render `s1shell audit verify` integrity check results."""
    norm = _require_format(fmt, ("table", "json", "md"), command="audit verify")
    if norm == "json":
        write_or_print(dumps_json(result), out_file=out_file, stdout=stdout)
        return
    status_label = "VALID" if result.valid else "TAMPERED / INVALID"
    if norm == "md":
        lines = [
            f"# S1shell Audit Log Integrity (`{status_label}`)",
            "",
            f"- **Log Path:** `{result.log_path}`",
            f"- **Total Entries:** {result.total_entries}",
            f"- **Hash-Chained Entries:** {result.chained_entries}",
            f"- **Legacy Unhashed Entries:** {result.legacy_unhashed_entries}",
        ]
        if result.errors:
            lines.extend(["", "## Integrity Errors", ""])
            for err in result.errors:
                lines.append(f"- {err}")
        write_or_print("\n".join(lines), out_file=out_file, stdout=stdout)
        return

    table = Table(title=f"Audit Log Integrity: {status_label}")
    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Value")
    table.add_row("Log Path", result.log_path)
    table.add_row("Status", status_label)
    table.add_row("Total Entries", str(result.total_entries))
    table.add_row("Hash-Chained", str(result.chained_entries))
    table.add_row("Legacy Unhashed", str(result.legacy_unhashed_entries))
    if result.errors:
        table.add_row("Errors", "\n".join(result.errors))
    _emit_tables([table], console=console, out_file=out_file, stdout=stdout)


def render_assessment_diff(
    result: AssessmentDiffResult,
    *,
    fmt: str,
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Render posture drift diff results between baseline and current assessments."""
    norm = _require_format(fmt, ("table", "json", "md"), command="diff")
    if norm == "json":
        write_or_print(dumps_json(result), out_file=out_file, stdout=stdout)
        return
    delta_str = f"{result.score_delta:+d}"
    if norm == "md":
        lines = [
            f"# S1shell Posture Drift Diff (`regressed={result.regressed}`)",
            "",
            (
                f"- **Baseline:** `{result.baseline_url}` "
                f"(`{result.score_before}/100`, Grade `{result.grade_before}`)"
            ),
            (
                f"- **Current:** `{result.current_url}` "
                f"(`{result.score_after}/100`, Grade `{result.grade_after}`)"
            ),
            (
                f"- **Score Delta:** `{delta_str}` | Risk: "
                f"`{result.risk_before}` -> `{result.risk_after}`"
            ),
            (
                f"- **Findings:** new={len(result.new_findings)}, "
                f"resolved={len(result.resolved_findings)}, persisting={result.persisting_count}"
            ),
        ]
        if result.new_cves:
            lines.append(f"- **New CVEs:** `{', '.join(result.new_cves)}`")
        if result.resolved_cves:
            lines.append(f"- **Resolved CVEs:** `{', '.join(result.resolved_cves)}`")
        if result.new_findings:
            lines.extend(["", "## New Findings", "", "| ID | Severity | Title |", "|---|---|---|"])
            for f in result.new_findings:
                lines.append(f"| `{f['id']}` | {f['severity']} | {_md_cell(f['title'])} |")
        if result.resolved_findings:
            lines.extend(
                ["", "## Resolved Findings", "", "| ID | Severity | Title |", "|---|---|---|"]
            )
            for f in result.resolved_findings:
                lines.append(f"| `{f['id']}` | {f['severity']} | {_md_cell(f['title'])} |")
        write_or_print("\n".join(lines), out_file=out_file, stdout=stdout)
        return

    tables: list[Table] = []
    summary = Table(title=f"Posture Drift Summary (regressed={result.regressed})")
    summary.add_column("Metric", style="cyan", no_wrap=True)
    summary.add_column("Value")
    summary.add_row(
        "Score / Grade",
        f"{result.score_before} ({result.grade_before}) -> "
        f"{result.score_after} ({result.grade_after}) [{delta_str}]",
    )
    summary.add_row("Risk Level", f"{result.risk_before} -> {result.risk_after}")
    summary.add_row(
        "Findings",
        f"new={len(result.new_findings)}, resolved={len(result.resolved_findings)}, "
        f"persisting={result.persisting_count}",
    )
    if result.cert_days_delta is not None:
        summary.add_row("TLS Cert Days Delta", f"{result.cert_days_delta:+d}d")
    if result.new_cves or result.resolved_cves:
        summary.add_row(
            "CVE Drift",
            f"new=[{', '.join(result.new_cves) or 'none'}] | "
            f"resolved=[{', '.join(result.resolved_cves) or 'none'}]",
        )
    tables.append(summary)

    if result.new_findings:
        ntbl = Table(title="New Findings")
        ntbl.add_column("ID", style="red", no_wrap=True)
        ntbl.add_column("Severity")
        ntbl.add_column("Title")
        for f in result.new_findings:
            ntbl.add_row(f["id"], f["severity"], f["title"])
        tables.append(ntbl)

    if result.resolved_findings:
        rtbl = Table(title="Resolved Findings")
        rtbl.add_column("ID", style="green", no_wrap=True)
        rtbl.add_column("Severity")
        rtbl.add_column("Title")
        for f in result.resolved_findings:
            rtbl.add_row(f["id"], f["severity"], f["title"])
        tables.append(rtbl)

    _emit_tables(tables, console=console, out_file=out_file, stdout=stdout)


def render_batch_assessment(
    result: BatchAssessmentResult,
    *,
    fmt: str,
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
    report_service: ReportService | None = None,
    operator: str | None = None,
) -> None:
    """Render sequential multi-target batch assessment summary (`table`, `json`, `md`, `html`)."""
    norm = _require_format(fmt, ("table", "json", "md", "html"), command="assess --targets-file")
    if norm == "json":
        write_or_print(dumps_json(result), out_file=out_file, stdout=stdout)
        return
    if norm == "html":
        rep_svc = (
            report_service
            if report_service is not None
            else ReportService(RuntimeConfig.from_env())
        )
        write_or_print(
            rep_svc.render_batch_html(result, operator=operator),
            out_file=out_file,
            stdout=stdout,
        )
        return
    avg_disp = result.average_score if result.average_score is not None else "—"
    if norm == "md":
        lines = [
            "# S1shell Batch Assessment Summary",
            "",
            (
                f"- **Targets:** {result.targets_total} "
                f"(ok={result.succeeded}, blocked={result.blocked}, err={result.errored})"
            ),
            f"- **Average Score:** {avg_disp}",
            "",
            "| Target | Status | Score | Grade | Risk | High Sev | Findings | CVEs | Error |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
        for item in result.results:
            lines.append(
                f"| `{_md_cell(item.target)}` | {item.status} | "
                f"{item.score if item.score is not None else '—'} | "
                f"{item.grade or '—'} | {item.risk_level or '—'} | "
                f"{item.highest_severity or '—'} | "
                f"{item.finding_count} | {item.cve_count} | {_md_cell(item.error)} |"
            )
        write_or_print("\n".join(lines), out_file=out_file, stdout=stdout)
        return

    tbl = Table(
        title=f"Batch Assessment ({result.succeeded}/{result.targets_total} ok, avg={avg_disp})"
    )
    tbl.add_column("Target", style="cyan")
    tbl.add_column("Status")
    tbl.add_column("Score", justify="right")
    tbl.add_column("Grade")
    tbl.add_column("Risk")
    tbl.add_column("High Sev")
    tbl.add_column("Findings", justify="right")
    tbl.add_column("CVEs", justify="right")
    tbl.add_column("Error")
    for item in result.results:
        tbl.add_row(
            item.target,
            item.status,
            str(item.score) if item.score is not None else "—",
            item.grade or "—",
            item.risk_level or "—",
            item.highest_severity or "—",
            str(item.finding_count),
            str(item.cve_count),
            item.error or "—",
        )
    _emit_tables([tbl], console=console, out_file=out_file, stdout=stdout)


def render_intel_env(
    result: IntelEnvStatus,
    *,
    fmt: str,
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Render masked status of passive threat intelligence API keys."""
    norm = _require_format(fmt, ("table", "json", "md"), command="intel env")
    if norm == "json":
        write_or_print(dumps_json(result), out_file=out_file, stdout=stdout)
        return
    if norm == "md":
        lines = [
            f"# S1shell Threat Intel Environment (`{result.env_file}`)",
            "",
            "| Feed | Env Var | Configured | Key | Source | Purpose |",
            "|---|---|---|---|---|---|",
        ]
        for f in result.feeds:
            lines.append(
                f"| `{f.feed}` | `{f.env_var}` | {'yes' if f.configured else 'no'} | "
                f"`{_md_cell(f.masked_key)}` | `{_md_cell(f.source)}` | {_md_cell(f.purpose)} |"
            )
        write_or_print("\n".join(lines), out_file=out_file, stdout=stdout)
        return

    tbl = Table(title=f"S1shell Threat Intel API Keys ({result.env_file})")
    tbl.add_column("Feed", style="cyan", no_wrap=True)
    tbl.add_column("Env Var", no_wrap=True)
    tbl.add_column("Configured")
    tbl.add_column("Masked Key")
    tbl.add_column("Source")
    tbl.add_column("Purpose")
    for f in result.feeds:
        tbl.add_row(
            f.feed,
            f.env_var,
            "yes" if f.configured else "no",
            f.masked_key or "—",
            f.source,
            f.purpose,
        )
    _emit_tables([tbl], console=console, out_file=out_file, stdout=stdout)


def render_intel_lookup(
    result: IntelLookupResult,
    *,
    fmt: str,
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Render `s1shell intel lookup` multi-feed passive intelligence results."""
    norm = _require_format(fmt, ("table", "json", "md"), command="intel lookup")
    if norm == "json":
        write_or_print(dumps_json(result), out_file=out_file, stdout=stdout)
        return
    if norm == "md":
        lines = [
            f"# S1shell Passive Threat Intel: `{result.indicator}` ({result.indicator_type})",
            "",
            f"- **Sources:** `{', '.join(result.sources_queried) or 'none'}` "
            f"(cached={result.cached})",
        ]
        if result.virustotal:
            vt = result.virustotal
            lines.append(
                f"- **VirusTotal:** malicious={vt.malicious}, suspicious={vt.suspicious}, "
                f"harmless={vt.harmless}, reputation={vt.reputation} ({vt.gui_url})"
            )
        if result.greynoise:
            gn = result.greynoise
            lines.append(
                f"- **GreyNoise ({gn.ip}):** classification=`{gn.classification}`, "
                f"noise={gn.noise}, riot={gn.riot}, name=`{gn.name or '—'}`"
            )
        if result.urlscan:
            us = result.urlscan
            lines.append(
                f"- **urlscan.io (`{us.query}`):** total={us.total_results}, "
                f"servers=`{', '.join(us.observed_servers) or 'none'}`, "
                f"ips=`{', '.join(us.observed_ips[:5]) or 'none'}`"
            )
        if result.rdap:
            rd = result.rdap
            lines.append(
                f"- **RDAP ({rd.indicator_type}):** registrar=`{rd.registrar or '—'}`, "
                f"org=`{rd.organization or '—'}`, expires=`{rd.expires_at or '—'}`, "
                f"locked=`{rd.transfer_locked}`"
            )
        if result.warnings:
            lines.extend(["", "## Warnings", ""])
            for w in result.warnings:
                lines.append(f"- {w}")
        write_or_print("\n".join(lines), out_file=out_file, stdout=stdout)
        return

    tables: list[Table] = []
    tbl = Table(
        title=f"Passive Threat Intel: {result.indicator} ({result.indicator_type}, "
        f"cached={result.cached})"
    )
    tbl.add_column("Source", style="cyan", no_wrap=True)
    tbl.add_column("Summary")
    if result.virustotal:
        vt = result.virustotal
        tbl.add_row(
            "VirusTotal",
            f"malicious={vt.malicious}, suspicious={vt.suspicious}, harmless={vt.harmless}, "
            f"rep={vt.reputation} | AS={vt.as_owner or '—'} | {vt.gui_url}",
        )
    if result.greynoise:
        gn = result.greynoise
        tbl.add_row(
            "GreyNoise",
            f"ip={gn.ip} | class={gn.classification} | noise={gn.noise} | "
            f"riot={gn.riot} ({gn.name or '—'})",
        )
    if result.urlscan:
        us = result.urlscan
        tbl.add_row(
            "urlscan.io",
            f"total={us.total_results} | servers={', '.join(us.observed_servers) or 'none'} | "
            f"ips={', '.join(us.observed_ips[:5]) or 'none'}",
        )
    if result.rdap:
        rd = result.rdap
        tbl.add_row(
            "RDAP",
            f"registrar={rd.registrar or '—'} | org={rd.organization or '—'} | "
            f"expires={rd.expires_at or '—'} | locked={rd.transfer_locked}",
        )
    if result.warnings:
        tbl.add_row("Warnings", "\n".join(result.warnings))
    tables.append(tbl)
    _emit_tables(tables, console=console, out_file=out_file, stdout=stdout)


def render_ghsa_advisories(
    result: GitHubAdvisoryResult,
    *,
    fmt: str,
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Render GitHub Security Advisories (GHSA) query results."""
    norm = _require_format(fmt, ("table", "json", "md"), command="intel advisory")
    if norm == "json":
        write_or_print(dumps_json(result), out_file=out_file, stdout=stdout)
        return
    if norm == "md":
        lines = [
            f"# GitHub Security Advisories (cached={result.cached})",
            "",
            "| GHSA ID | CVE ID | Severity | CVSS | Patched | Summary | URL |",
            "|---|---|---|---|---|---|---|",
        ]
        for a in result.advisories:
            patched = ", ".join(a.patched_versions[:3]) or "—"
            cvss = str(a.cvss_score) if a.cvss_score is not None else "—"
            lines.append(
                f"| `{a.ghsa_id}` | `{a.cve_id or '—'}` | {a.severity} | {cvss} | "
                f"`{_md_cell(patched)}` | {_md_cell(a.summary)} | {a.html_url} |"
            )
        write_or_print("\n".join(lines), out_file=out_file, stdout=stdout)
        return

    tbl = Table(title=f"GitHub Security Advisories (cached={result.cached})")
    tbl.add_column("GHSA ID", style="cyan", no_wrap=True)
    tbl.add_column("CVE ID", no_wrap=True)
    tbl.add_column("Severity")
    tbl.add_column("CVSS", justify="right")
    tbl.add_column("Patched")
    tbl.add_column("Summary")
    for a in result.advisories:
        patched = ", ".join(a.patched_versions[:3]) or "—"
        cvss = f"{a.cvss_score:.1f}" if a.cvss_score is not None else "—"
        summ = a.summary[:120] + ("..." if len(a.summary) > 120 else "")
        tbl.add_row(a.ghsa_id, a.cve_id or "—", a.severity, cvss, patched, summ)
    _emit_tables([tbl], console=console, out_file=out_file, stdout=stdout)


def render_ct_lookup(
    result: CTLookupResult,
    *,
    fmt: str,
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Render passive Certificate Transparency (crt.sh) lookup results."""
    norm = _require_format(fmt, ("table", "json", "md"), command="intel ct")
    if norm == "json":
        write_or_print(dumps_json(result), out_file=out_file, stdout=stdout)
        return
    if norm == "md":
        lines = [
            f"# Passive Certificate Transparency: `{result.domain}` (cached={result.cached})",
            "",
            (
                f"- **Certificates:** total={result.total_certificates} "
                f"(active={result.active_certificates}, expired={result.expired_certificates})"
            ),
            f"- **Unique Subdomains:** {len(result.unique_subdomains)}",
            f"- **Wildcard SANs:** `{', '.join(result.wildcard_sans[:10]) or 'none'}`",
            f"- **Observed CAs:** `{', '.join(result.issuers[:6]) or 'none'}`",
        ]
        if result.exported_candidates_file:
            lines.append(f"- **Exported Scope Candidates:** `{result.exported_candidates_file}`")
        if result.unique_subdomains:
            lines.extend(["", "## Discovered Passive Subdomains", ""])
            for sub in result.unique_subdomains[:50]:
                lines.append(f"- `{sub}`")
        write_or_print("\n".join(lines), out_file=out_file, stdout=stdout)
        return

    tables: list[Table] = []
    summary = Table(title=f"Certificate Transparency (crt.sh): {result.domain}")
    summary.add_column("Metric", style="cyan", no_wrap=True)
    summary.add_column("Value")
    summary.add_row(
        "Certificates",
        f"total={result.total_certificates} "
        f"(active={result.active_certificates}, expired={result.expired_certificates}, "
        f"cached={result.cached})",
    )
    summary.add_row("Unique Subdomains", str(len(result.unique_subdomains)))
    summary.add_row("Wildcard SANs", ", ".join(result.wildcard_sans[:8]) or "none")
    summary.add_row("Issuers", ", ".join(result.issuers[:4]) or "none")
    if result.exported_candidates_file:
        summary.add_row("Exported Candidates", result.exported_candidates_file)
    tables.append(summary)

    if result.unique_subdomains:
        sub_tbl = Table(title="Passive SAN Subdomains (top 30)")
        sub_tbl.add_column("Hostname", style="cyan")
        for sub in result.unique_subdomains[:30]:
            sub_tbl.add_row(sub)
        tables.append(sub_tbl)

    _emit_tables(tables, console=console, out_file=out_file, stdout=stdout)


def render_rdap_lookup(
    result: RDAPLookupResult,
    *,
    fmt: str,
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Render RFC 7480–7484 RDAP domain or IP/ASN registration record."""
    norm = _require_format(fmt, ("table", "json", "md"), command="intel rdap")
    if norm == "json":
        write_or_print(dumps_json(result), out_file=out_file, stdout=stdout)
        return
    if norm == "md":
        lines = [
            f"# RDAP Registration: `{result.indicator}` ({result.indicator_type})",
            "",
            f"- **Handle / Name:** `{result.handle or '—'}` / `{result.name or '—'}`",
            f"- **Registrar / Org:** `{result.registrar or '—'}` / `{result.organization or '—'}`",
            f"- **Country:** `{result.country or '—'}`",
            f"- **Statuses:** `{', '.join(result.statuses) or 'none'}`",
            (
                f"- **Transfer Locked:** `{result.transfer_locked}` | "
                f"**DNSSEC Signed:** `{result.dnssec_signed}`"
            ),
            f"- **Created:** `{result.created_at or '—'}` (age={result.domain_age_days}d)",
            f"- **Expires:** `{result.expires_at or '—'}` (remaining={result.days_until_expiry}d)",
            (
                f"- **CIDR / Range:** `{result.cidr or '—'}` "
                f"({result.start_address or '—'} - {result.end_address or '—'})"
            ),
            f"- **Abuse Contact:** `{result.abuse_contact or '—'}`",
            f"- **Emails:** `{', '.join(result.emails) or 'none'}`",
            f"- **Phone Numbers:** `{', '.join(result.phone_numbers) or 'none'}`",
            f"- **Entities:** `{'; '.join(result.entities) or 'none'}`",
        ]
        write_or_print("\n".join(lines), out_file=out_file, stdout=stdout)
        return

    tbl = Table(title=f"RDAP Registration: {result.indicator} ({result.indicator_type})")
    tbl.add_column("Field", style="cyan", no_wrap=True)
    tbl.add_column("Value")
    tbl.add_row("Handle / Name", f"{result.handle or '—'} / {result.name or '—'}")
    tbl.add_row("Registrar / Org", f"{result.registrar or '—'} / {result.organization or '—'}")
    tbl.add_row("Country", result.country or "—")
    tbl.add_row("Statuses", ", ".join(result.statuses) or "—")
    tbl.add_row(
        "Locks / DNSSEC",
        f"transfer_locked={result.transfer_locked} | dnssec_signed={result.dnssec_signed}",
    )
    tbl.add_row(
        "Dates",
        f"created={result.created_at or '—'} (age={result.domain_age_days}d) | "
        f"expires={result.expires_at or '—'} (in {result.days_until_expiry}d)",
    )
    if result.nameservers:
        tbl.add_row("Nameservers", ", ".join(result.nameservers[:6]))
    if result.cidr or result.start_address:
        tbl.add_row(
            "IP Block",
            f"{result.cidr or '—'} ({result.start_address or '—'} - {result.end_address or '—'})",
        )
    tbl.add_row("Abuse Contact", result.abuse_contact or "—")
    if result.emails:
        tbl.add_row("RDAP Emails", ", ".join(result.emails))
    if result.phone_numbers:
        tbl.add_row("RDAP Phones", ", ".join(result.phone_numbers))
    if result.entities:
        tbl.add_row("RDAP Entities", "\n".join(result.entities[:8]))
    tbl.add_row("Cached", str(result.cached))
    _emit_tables([tbl], console=console, out_file=out_file, stdout=stdout)


def render_codec_transform(
    result: CodecTransformResult,
    *,
    fmt: str,
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Render `s1shell codec decode|encode` results in `table`, `json`, or `md`."""
    norm = _require_format(fmt, ("table", "json", "md"), command=f"codec {result.operation}")
    if norm == "json":
        write_or_print(dumps_json(result), out_file=out_file, stdout=stdout)
        return

    chain_str = " -> ".join(s.codec for s in result.steps) or "none"
    if norm == "md":
        lines = [
            f"# S1shell Codec {result.operation.title()} (`{chain_str}`)",
            "",
            (
                f"- **Bytes:** `{result.byte_length}` | **UTF-8:** `{result.is_utf8}` | "
                f"**Entropy:** `{result.entropy}` | **SHA-256:** `{result.sha256}`"
            ),
            "",
            "## Pipeline Steps",
            "",
            "| Stage | Codec | In Bytes | Out Bytes | Note |",
            "|---|---|---|---|---|",
        ]
        for s in result.steps:
            lines.append(
                f"| {s.stage} | `{s.codec}` | {s.input_bytes} | {s.output_bytes} | "
                f"{_md_cell(s.note)} |"
            )
        lines.extend(["", "## Output", "", "```text", result.output_text, "```"])
        if not result.is_utf8:
            lines.extend(["", f"- **Hex:** `{result.output_hex[:256]}`"])
        if result.variants:
            lines.extend(["", "## Caesar Shift Candidates", "", "| Shift | Text |", "|---|---|"])
            for v in result.variants:
                lines.append(f"| -{v['shift']} | `{_md_cell(v['text'])}` |")
        write_or_print("\n".join(lines), out_file=out_file, stdout=stdout)
        return

    tables: list[Table] = []
    tbl = Table(title=f"Codec {result.operation.title()}: {chain_str}")
    tbl.add_column("Field", style="cyan", no_wrap=True)
    tbl.add_column("Value")
    tbl.add_row("Pipeline", chain_str)
    tbl.add_row(
        "Metadata",
        f"bytes={result.byte_length} | utf8={result.is_utf8} | entropy={result.entropy}",
    )
    tbl.add_row("SHA-256", result.sha256)
    tbl.add_row("Output", result.output_text[:2000])
    if not result.is_utf8:
        tbl.add_row("Hex Preview", result.output_hex[:256])
        tbl.add_row("Base64 Preview", result.output_base64[:256])
    tables.append(tbl)

    if len(result.steps) > 1:
        stbl = Table(title="Decoding / Encoding Trace")
        stbl.add_column("#", justify="right")
        stbl.add_column("Codec", style="cyan")
        stbl.add_column("Bytes")
        stbl.add_column("Note")
        for s in result.steps:
            stbl.add_row(str(s.stage), s.codec, f"{s.input_bytes} -> {s.output_bytes}", s.note)
        tables.append(stbl)

    if result.variants:
        vtbl = Table(title="Caesar Shift Candidates (1–25)")
        vtbl.add_column("Shift", style="cyan", no_wrap=True)
        vtbl.add_column("Decoded Candidate")
        for v in result.variants:
            vtbl.add_row(f"-{v['shift']}", v["text"][:160])
        tables.append(vtbl)

    _emit_tables(tables, console=console, out_file=out_file, stdout=stdout)


def render_codec_inspect(
    result: CodecInspectResult,
    *,
    fmt: str,
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Render `s1shell codec inspect` smart artifact/token/cert/hash analysis."""
    norm = _require_format(fmt, ("table", "json", "md"), command="codec inspect")
    if norm == "json":
        write_or_print(dumps_json(result), out_file=out_file, stdout=stdout)
        return
    if norm == "md":
        lines = [
            "# S1shell Offline Artifact Inspector",
            "",
            f"- **Detected:** `{', '.join(result.detected_types)}`",
            (
                f"- **Bytes:** `{result.byte_length}` | **Entropy:** `{result.entropy}` | "
                f"**SHA-256:** `{result.sha256}`"
            ),
        ]
        if result.timestamp_utc:
            lines.append(f"- **Unix Epoch (UTC):** `{result.timestamp_utc}`")
        if result.jwt:
            lines.extend(
                [
                    "",
                    "## JWT Details",
                    "",
                    f"- **Algorithm:** `{result.jwt.get('alg')}` | "
                    f"**Signed:** `{result.jwt.get('signature_present')}`",
                    f"- **Timestamps:** `{result.jwt.get('timestamps_utc')}`",
                    f"- **Payload:** `{result.jwt.get('payload')}`",
                ]
            )
        if result.x509:
            lines.extend(
                [
                    "",
                    "## X.509 Certificate",
                    "",
                    f"- **Subject:** `{result.x509.get('subject')}`",
                    f"- **Issuer:** `{result.x509.get('issuer')}`",
                    (
                        f"- **Validity:** `{result.x509.get('not_before')}` -> "
                        f"`{result.x509.get('not_after')}` ({result.x509.get('days_remaining')}d)"
                    ),
                    f"- **SPKI Pin:** `{result.x509.get('spki_sha256')}`",
                ]
            )
        if result.hash_candidates:
            lines.extend(["", "## Hash / ID Candidates", ""])
            for cand in result.hash_candidates:
                lines.append(f"- **{cand['format']}** (`{cand['strength']}`): {cand['note']}")
        if result.auto_decoded:
            chain_str = " -> ".join(s.codec for s in result.auto_decoded.steps)
            lines.extend(
                [
                    "",
                    f"## Auto-Decoded (`{chain_str}`)",
                    "",
                    "```text",
                    result.auto_decoded.output_text,
                    "```",
                ]
            )
        if result.notes:
            lines.extend(["", "## Notes & Warnings", ""])
            for note in result.notes:
                lines.append(f"- {note}")
        write_or_print("\n".join(lines), out_file=out_file, stdout=stdout)
        return

    tbl = Table(title="S1shell Offline Artifact Inspector")
    tbl.add_column("Field", style="cyan", no_wrap=True)
    tbl.add_column("Value")
    tbl.add_row("Detected", ", ".join(result.detected_types))
    tbl.add_row("Bytes / Entropy", f"{result.byte_length} bytes | {result.entropy} bits/byte")
    tbl.add_row("SHA-256", result.sha256)
    if result.timestamp_utc:
        tbl.add_row("Unix Epoch (UTC)", result.timestamp_utc)
    if result.jwt:
        tbl.add_row(
            "JWT",
            f"alg={result.jwt.get('alg')} | signed={result.jwt.get('signature_present')} | "
            f"payload={result.jwt.get('payload')}",
        )
    if result.x509:
        tbl.add_row(
            "X.509 Cert",
            f"subject={result.x509.get('subject')} | issuer={result.x509.get('issuer')} | "
            f"days={result.x509.get('days_remaining')} | spki={result.x509.get('spki_sha256')}",
        )
    if result.hash_candidates:
        tbl.add_row(
            "Hash Candidates",
            "; ".join(f"{c['format']} ({c['strength']})" for c in result.hash_candidates),
        )
    if result.auto_decoded:
        chain_str = " -> ".join(s.codec for s in result.auto_decoded.steps)
        tbl.add_row("Auto-Decode Chain", chain_str)
        tbl.add_row("Decoded Output", result.auto_decoded.output_text[:1500])
    if result.notes:
        tbl.add_row("Notes", "\n".join(result.notes))
    _emit_tables([tbl], console=console, out_file=out_file, stdout=stdout)


def render_codec_hash(
    result: CodecHashResult,
    *,
    fmt: str,
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Render `s1shell codec hash` digests and entropy."""
    norm = _require_format(fmt, ("table", "json", "md"), command="codec hash")
    if norm == "json":
        write_or_print(dumps_json(result), out_file=out_file, stdout=stdout)
        return
    if norm == "md":
        lines = [
            f"# S1shell Checksums (`{result.source}`)",
            "",
            f"- **Bytes:** `{result.byte_length}` | **Entropy:** `{result.entropy}`",
            "",
            "| Algorithm | Digest |",
            "|---|---|",
        ]
        for algo, digest in result.hashes.items():
            lines.append(f"| `{algo.upper()}` | `{digest}` |")
        write_or_print("\n".join(lines), out_file=out_file, stdout=stdout)
        return

    tbl = Table(
        title=f"Checksums: {result.source} ({result.byte_length} bytes, entropy={result.entropy})"
    )
    tbl.add_column("Algorithm", style="cyan", no_wrap=True)
    tbl.add_column("Digest")
    for algo, digest in result.hashes.items():
        tbl.add_row(algo.upper(), digest)
    _emit_tables([tbl], console=console, out_file=out_file, stdout=stdout)


def render_mcp_ping(
    result: dict[str, object],
    *,
    fmt: str,
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Render `s1shell mcp ping` online MCP server connectivity results."""
    norm = _require_format(fmt, ("table", "json", "md"), command="mcp ping")
    if norm == "json":
        write_or_print(dumps_json(result), out_file=out_file, stdout=stdout)
        return
    if norm == "md":
        lines = [
            f"# S1shell Online MCP Server Status (`{result.get('url', '')}`)",
            "",
            f"- **Healthy:** `{result.get('healthy')}` (`{result.get('latency_ms', 0)} ms`)",
            (
                f"- **Server:** `{result.get('server_name')}` "
                f"`v{result.get('server_version')}` (MCP `{result.get('protocol_version')}`)"
            ),
            (
                f"- **Capabilities:** `{result.get('tools_count', 0)}` tools · "
                f"`{result.get('resources_count', 0)}` resources · "
                f"`{result.get('prompts_count', 0)}` prompts"
            ),
            f"- **Scoped Targets Enabled:** `{result.get('scoped_targets_enabled')}`",
            f"- **Bearer Auth Used:** `{result.get('auth_used')}`",
        ]
        write_or_print("\n".join(lines), out_file=out_file, stdout=stdout)
        return

    tbl = Table(title=f"S1shell Online MCP Status ({result.get('url', '')})")
    tbl.add_column("Metric", style="cyan", no_wrap=True)
    tbl.add_column("Value")
    tbl.add_row("Status", f"ONLINE ({result.get('latency_ms', 0)} ms)")
    tbl.add_row(
        "Server",
        (
            f"{result.get('server_name')} v{result.get('server_version')} "
            f"(MCP {result.get('protocol_version')})"
        ),
    )
    tbl.add_row("Tools Exposed", str(result.get("tools_count", 0)))
    tbl.add_row("Resources Exposed", str(result.get("resources_count", 0)))
    tbl.add_row("Prompts (AI Skills)", str(result.get("prompts_count", 0)))
    tbl.add_row("Scoped Targets Mode", str(result.get("scoped_targets_enabled", False)))
    tbl.add_row("Bearer Auth Used", str(result.get("auth_used", False)))
    _emit_tables([tbl], console=console, out_file=out_file, stdout=stdout)


def render_tor_status(
    result: TorStatusResult,
    *,
    fmt: str,
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Render `s1shell tor status` offline local Tor readiness report."""
    norm = _require_format(fmt, ("table", "json", "md"), command="tor status")
    if norm == "json":
        write_or_print(dumps_json(result), out_file=out_file, stdout=stdout)
        return
    if norm == "md":
        lines = [
            "# S1shell Local Tor Readiness (Offline Check)",
            "",
            f"- **Configured Proxy:** `{result.configured_proxy}`",
            f"- **Reachable:** `{result.reachable}` (`{result.active_proxy or 'none'}`)",
            f"- **Tor Binary:** `{result.tor_binary or 'not found'}`",
            f"- **socksio Library:** `{result.socksio_available}`",
            f"- **Detail:** {result.detail}",
        ]
        write_or_print("\n".join(lines), out_file=out_file, stdout=stdout)
        return

    tbl = Table(title="S1shell Local Tor Status (Offline)")
    tbl.add_column("Check", style="cyan", no_wrap=True)
    tbl.add_column("Value")
    tbl.add_row("Configured Proxy", result.configured_proxy)
    tbl.add_row("Port Reachable", f"{result.reachable} ({result.active_proxy or 'none'})")
    tbl.add_row("Tor Binary", result.tor_binary or "not found")
    tbl.add_row("socksio Package", "installed" if result.socksio_available else "MISSING")
    tbl.add_row("Detail", result.detail)
    _emit_tables([tbl], console=console, out_file=out_file, stdout=stdout)


def render_tor_check(
    result: TorCheckResult,
    *,
    fmt: str,
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Render `s1shell tor check` live Tor exit verification report."""
    norm = _require_format(fmt, ("table", "json", "md"), command="tor check")
    if norm == "json":
        write_or_print(dumps_json(result), out_file=out_file, stdout=stdout)
        return
    if norm == "md":
        lines = [
            "# S1shell Tor Egress Verification",
            "",
            f"- **Proxy:** `{result.proxy_url}`",
            f"- **Confirmed Tor (`IsTor`):** `{result.is_tor}`",
            f"- **Exit IP:** `{result.exit_ip or 'unknown'}`",
            f"- **Latency:** `{result.latency_ms} ms`",
            f"- **Detail:** {result.detail}",
        ]
        write_or_print("\n".join(lines), out_file=out_file, stdout=stdout)
        return

    tbl = Table(title="S1shell Tor Egress Verification")
    tbl.add_column("Metric", style="cyan", no_wrap=True)
    tbl.add_column("Value")
    tbl.add_row("SOCKS5h Proxy", result.proxy_url)
    tbl.add_row("Confirmed Tor", str(result.is_tor))
    tbl.add_row("Tor Exit IP", result.exit_ip or "unknown")
    tbl.add_row("Latency", f"{result.latency_ms} ms")
    tbl.add_row("Detail", result.detail)
    _emit_tables([tbl], console=console, out_file=out_file, stdout=stdout)
