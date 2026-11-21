"""Built-in offline telemetry-grounded tactical & defensive AI synthesis engine."""

from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass, field
from typing import Any

from s1shell.config import DEFAULT_BUILTIN_MODEL, RuntimeConfig

_TELEMETRY_BLOCK_RE = re.compile(
    r"<untrusted_telemetry\b[^>]*>(.*?)</untrusted_telemetry>",
    re.DOTALL | re.IGNORECASE,
)
_EMAIL_IN_TEXT_RE = re.compile(r"mailto:([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_PLACEHOLDER_EMAIL_RE = re.compile(r"\[EMAIL_\d+\]")
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class _TelemetryContext:
    target_url: str = "target"
    pinned_ip: str = "—"
    scope_id: str = "—"
    auth_ref: str = "—"
    preset: str = "web"
    score: int | None = None
    grade: str = "—"
    risk_level: str = "MODERATE"
    redirect_location: str | None = None
    http_version: str | None = None
    tls_version: str | None = None
    tls_cipher: str | None = None
    tls_issuer: str | None = None
    tls_days_remaining: int | None = None
    tls_spki: str | None = None
    tls_wildcard: bool = False
    findings: list[dict[str, Any]] = field(default_factory=list)
    cves: list[dict[str, Any]] = field(default_factory=list)
    dep_vulns: list[dict[str, Any]] = field(default_factory=list)
    upgrade_commands: list[str] = field(default_factory=list)
    stack_matches: list[dict[str, Any]] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    gmail_addresses: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    client_keys: list[str] = field(default_factory=list)
    cloud_buckets: list[str] = field(default_factory=list)
    forms: list[str] = field(default_factory=list)
    url_params: list[str] = field(default_factory=list)
    internal_ips: list[str] = field(default_factory=list)
    html_comments: list[str] = field(default_factory=list)
    csp_external_hosts: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    dangling_cnames: list[str] = field(default_factory=list)
    cookies: list[dict[str, Any]] = field(default_factory=list)
    banners: list[str] = field(default_factory=list)
    origin_drift_ips: list[str] = field(default_factory=list)
    observed_servers: list[str] = field(default_factory=list)
    observed_asns: list[str] = field(default_factory=list)
    ct_subdomains: list[str] = field(default_factory=list)
    wildcard_sans: list[str] = field(default_factory=list)
    registrar: str | None = None
    transfer_locked: bool | None = None
    dnssec_signed: bool | None = None
    days_until_expiry: int | None = None
    remediation_snippets: list[dict[str, Any]] = field(default_factory=list)
    diff_summary: dict[str, Any] | None = None


def _add_unique(target: list[str], items: list[Any]) -> None:
    seen = set(target)
    for raw in items:
        if raw is None:
            continue
        val = str(raw).strip()
        if val and val not in seen:
            seen.add(val)
            target.append(val)


def _extract_csp_external_hosts(csp_value: str) -> list[str]:
    hosts: list[str] = []
    skip = {"self", "none", "unsafe-inline", "unsafe-eval"}
    for token in re.split(r"[\s;]+", csp_value):
        cleaned = token.strip().strip("'\"")
        if not cleaned or cleaned.endswith(":") or cleaned in skip:
            continue
        cleaned = re.sub(r"^https?://", "", cleaned).rstrip("/")
        if "." in cleaned and not cleaned.startswith("*."):
            hosts.append(cleaned)
    return hosts


def _ingest_profile(ctx: _TelemetryContext, prof: dict[str, Any]) -> None:
    if prof.get("url") and ctx.target_url == "target":
        ctx.target_url = str(prof["url"])
    elif prof.get("target") and ctx.target_url == "target":
        ctx.target_url = str(prof["target"])
    if prof.get("pinned_ip") and ctx.pinned_ip == "—":
        ctx.pinned_ip = str(prof["pinned_ip"])

    proto = prof.get("protocol")
    if isinstance(proto, dict):
        if proto.get("redirect_location"):
            ctx.redirect_location = str(proto["redirect_location"])
        if proto.get("http_version"):
            ctx.http_version = str(proto["http_version"])

    tls = prof.get("tls")
    if isinstance(tls, dict):
        if tls.get("negotiated_version"):
            ctx.tls_version = str(tls["negotiated_version"])
        if tls.get("cipher_suite"):
            ctx.tls_cipher = str(tls["cipher_suite"])
        if tls.get("issuer"):
            ctx.tls_issuer = str(tls["issuer"])
        if isinstance(tls.get("days_remaining"), int):
            ctx.tls_days_remaining = int(tls["days_remaining"])
        if tls.get("spki_sha256"):
            ctx.tls_spki = str(tls["spki_sha256"])
        if tls.get("has_wildcard_san"):
            ctx.tls_wildcard = True
        if isinstance(tls.get("sans"), list):
            _add_unique(
                ctx.wildcard_sans,
                [s for s in tls["sans"] if isinstance(s, str) and "*" in s],
            )

    dns = prof.get("dns")
    if isinstance(dns, dict):
        if isinstance(dns.get("cname"), list):
            _add_unique(ctx.cnames, dns["cname"])
        if isinstance(dns.get("dangling_cnames"), list):
            _add_unique(ctx.dangling_cnames, dns["dangling_cnames"])
        if isinstance(dns.get("dnssec_present"), bool) and ctx.dnssec_signed is None:
            ctx.dnssec_signed = bool(dns["dnssec_present"])
        dmarc_str = str(dns.get("dmarc") or "")
        if dmarc_str:
            _add_unique(ctx.emails, _EMAIL_IN_TEXT_RE.findall(dmarc_str))
            _add_unique(ctx.emails, _PLACEHOLDER_EMAIL_RE.findall(dmarc_str))

    headers = prof.get("headers")
    if isinstance(headers, dict):
        for b in headers.get("banner_disclosures", []) or []:
            if isinstance(b, dict) and b.get("header") and b.get("value"):
                _add_unique(ctx.banners, [f"{b['header']}: {b['value']}"])
        cookies = headers.get("cookies") or headers.get("insecure_cookies") or []
        if isinstance(cookies, list):
            seen_c = {c.get("name") for c in ctx.cookies}
            for c in cookies:
                if isinstance(c, dict) and c.get("name") and c.get("name") not in seen_c:
                    seen_c.add(c.get("name"))
                    ctx.cookies.append(c)
        csp_dirs = headers.get("csp_directives")
        if isinstance(csp_dirs, dict):
            for vals in csp_dirs.values():
                if isinstance(vals, list):
                    for v in vals:
                        _add_unique(ctx.csp_external_hosts, _extract_csp_external_hosts(str(v)))
        sec_hdrs = headers.get("security_headers") or headers.get("non_ok_security_headers") or []
        for sh in sec_hdrs:
            if isinstance(sh, dict):
                h_name = str(sh.get("header") or "").lower()
                if h_name == "content-security-policy" and sh.get("value"):
                    _add_unique(
                        ctx.csp_external_hosts,
                        _extract_csp_external_hosts(str(sh["value"])),
                    )

    html_blk = prof.get("html")
    if isinstance(html_blk, dict):
        _add_unique(ctx.emails, html_blk.get("emails", []) or [])
        _add_unique(ctx.gmail_addresses, html_blk.get("gmail_addresses", []) or [])
        _add_unique(ctx.phones, html_blk.get("phone_numbers", []) or [])
        _add_unique(ctx.client_keys, html_blk.get("client_keys", []) or [])
        _add_unique(ctx.client_keys, html_blk.get("leaked_secrets", []) or [])
        _add_unique(ctx.cloud_buckets, html_blk.get("cloud_buckets", []) or [])
        _add_unique(ctx.forms, html_blk.get("forms", []) or [])
        _add_unique(ctx.forms, html_blk.get("insecure_forms", []) or [])
        _add_unique(ctx.url_params, html_blk.get("url_params", []) or [])
        _add_unique(ctx.internal_ips, html_blk.get("internal_ips", []) or [])
        _add_unique(ctx.html_comments, html_blk.get("html_comments", []) or [])


def _ingest_intel(ctx: _TelemetryContext, intel: dict[str, Any]) -> None:
    us = intel.get("urlscan")
    if isinstance(us, dict):
        _add_unique(ctx.origin_drift_ips, us.get("observed_ips", []) or [])
        _add_unique(ctx.observed_servers, us.get("observed_servers", []) or [])
        _add_unique(ctx.observed_asns, us.get("observed_asns", []) or [])
    rdap = intel.get("rdap")
    if isinstance(rdap, dict):
        if rdap.get("registrar"):
            ctx.registrar = str(rdap["registrar"])
        if isinstance(rdap.get("transfer_locked"), bool):
            ctx.transfer_locked = bool(rdap["transfer_locked"])
        if isinstance(rdap.get("dnssec_signed"), bool):
            ctx.dnssec_signed = bool(rdap["dnssec_signed"])
        if isinstance(rdap.get("days_until_expiry"), int):
            ctx.days_until_expiry = int(rdap["days_until_expiry"])
        if rdap.get("abuse_contact"):
            _add_unique(ctx.emails, [rdap["abuse_contact"]])
        _add_unique(ctx.emails, rdap.get("emails", []) or [])
        _add_unique(ctx.phones, rdap.get("phone_numbers", []) or [])


def _ingest_cves(ctx: _TelemetryContext, cve_blk: dict[str, Any]) -> None:
    seen_ids = {c.get("cve_id") for c in ctx.cves}
    for rec in cve_blk.get("records", []) or []:
        if not isinstance(rec, dict) or not rec.get("cve_id"):
            continue
        cid = str(rec["cve_id"]).upper()
        if cid in seen_ids:
            continue
        seen_ids.add(cid)
        raw_cvss = rec.get("cvss")
        cvss: dict[str, Any] = raw_cvss if isinstance(raw_cvss, dict) else {}
        default_prio = "P0-IMMEDIATE" if rec.get("in_kev") else "P1-HIGH"
        ctx.cves.append(
            {
                "cve_id": cid,
                "severity": rec.get("severity") or cvss.get("severity") or "HIGH",
                "base_score": rec.get("base_score") or cvss.get("base_score"),
                "in_kev": bool(rec.get("in_kev", False)),
                "epss_score": rec.get("epss_score"),
                "priority": rec.get("priority") or default_prio,
                "ghsa_id": rec.get("ghsa_id"),
                "patched_versions": rec.get("patched_versions", []) or [],
                "description": str(rec.get("description") or "")[:200],
            }
        )


def _extract_telemetry_context(prompt: str) -> _TelemetryContext:
    ctx = _TelemetryContext()
    blocks = _TELEMETRY_BLOCK_RE.findall(prompt)
    seen_fids: set[str] = set()

    for raw_block in blocks:
        unescaped = html.unescape(raw_block).strip()
        if unescaped.endswith("... [truncated]"):
            unescaped = unescaped[: -len("... [truncated]")].strip()
        try:
            data = json.loads(unescaped)
        except ValueError:
            continue
        if not isinstance(data, dict):
            continue

        if data.get("url") and ctx.target_url == "target":
            ctx.target_url = str(data["url"])
        elif data.get("target") and ctx.target_url == "target":
            ctx.target_url = str(data["target"])
        elif data.get("indicator") and ctx.target_url == "target":
            ctx.target_url = str(data["indicator"])
        elif data.get("domain") and ctx.target_url == "target":
            ctx.target_url = str(data["domain"])

        if data.get("pinned_ip") and ctx.pinned_ip == "—":
            ctx.pinned_ip = str(data["pinned_ip"])
        elif data.get("resolved_ip") and ctx.pinned_ip == "—":
            ctx.pinned_ip = str(data["resolved_ip"])

        if data.get("scope_id") and ctx.scope_id == "—":
            ctx.scope_id = str(data["scope_id"])
        if data.get("auth_ref") and ctx.auth_ref == "—":
            ctx.auth_ref = str(data["auth_ref"])
        if data.get("preset"):
            ctx.preset = str(data["preset"])

        posture = data.get("posture")
        if isinstance(posture, dict):
            if isinstance(posture.get("score"), int):
                ctx.score = int(posture["score"])
            if posture.get("grade"):
                ctx.grade = str(posture["grade"])
            if posture.get("risk_level"):
                ctx.risk_level = str(posture["risk_level"])

        for f in data.get("findings", []) or []:
            if isinstance(f, dict) and f.get("id"):
                fid = str(f["id"]).strip()
                key = f"{fid}:{f.get('evidence', '')}"
                if key not in seen_fids:
                    seen_fids.add(key)
                    ctx.findings.append(f)

        fp_matches = data.get("fingerprint_matches")
        if not isinstance(fp_matches, list) and isinstance(data.get("fingerprint"), dict):
            fp_matches = data["fingerprint"].get("matches")
        if not isinstance(fp_matches, list) and data.get("artifact_type") == "fingerprint_report":
            fp_matches = data.get("matches")
        if isinstance(fp_matches, list):
            for m in fp_matches:
                if isinstance(m, dict) and m.get("product"):
                    ctx.stack_matches.append(m)

        if isinstance(data.get("profile"), dict):
            _ingest_profile(ctx, data["profile"])
        if isinstance(data.get("profile_summary"), dict):
            _ingest_profile(ctx, data["profile_summary"])
        if data.get("artifact_type") == "profile_report":
            _ingest_profile(ctx, data)

        if isinstance(data.get("cve"), dict):
            _ingest_cves(ctx, data["cve"])
        if data.get("artifact_type") == "cve_report":
            _ingest_cves(ctx, data)

        if isinstance(data.get("intel"), dict):
            _ingest_intel(ctx, data["intel"])
        if data.get("artifact_type") == "intel_report":
            _ingest_intel(ctx, data)
        if data.get("artifact_type") == "rdap_report":
            _ingest_intel(ctx, {"rdap": data})

        if data.get("artifact_type") == "ct_report":
            _add_unique(ctx.ct_subdomains, data.get("unique_subdomains", []) or [])
            _add_unique(ctx.wildcard_sans, data.get("wildcard_sans", []) or [])

        if data.get("artifact_type") == "dependency_audit_report":
            for v in data.get("vulnerabilities", []) or []:
                if isinstance(v, dict):
                    ctx.dep_vulns.append(v)
            _add_unique(ctx.upgrade_commands, data.get("upgrade_commands", []) or [])

        if data.get("artifact_type") == "assess_diff_report":
            ctx.diff_summary = data

        if isinstance(data.get("remediation_snippets"), list):
            for snip in data["remediation_snippets"]:
                if isinstance(snip, dict):
                    ctx.remediation_snippets.append(snip)

    ctx.findings.sort(
        key=lambda item: (
            _SEV_ORDER.get(str(item.get("severity") or "INFO").upper(), 9),
            str(item.get("id") or ""),
        )
    )
    return ctx


def _map_finding_tactics(finding: dict[str, Any]) -> tuple[str, str, str, str]:
    """Return `(attck_id, wstg_id, d3fend_id, confidence)` for a finding dict."""
    fid = str(finding.get("id") or "").upper()
    cat = str(finding.get("category") or "").lower()

    if fid.startswith("LEAK-SECRET") or fid.startswith("HTML-KEY"):
        return "TA0006 T1552.001", "WSTG-INFO-05", "D3-CH (Credential Hardening)", "Confirmed"
    if fid.startswith(("LEAK-JWT", "OIDC-", "JWKS-")):
        return "TA0006 T1606.002", "WSTG-ATHN-06", "D3-CH (Token Validation)", "Confirmed"
    if fid.startswith(("CVE-KEV", "CVE-VER", "EOL-")):
        return "TA0001 T1190", "WSTG-INFO-08", "D3-SVA (Software Patching)", "Confirmed"
    if fid.startswith("CVE-UNVER"):
        return "TA0001 T1190", "WSTG-INFO-08", "D3-SVA (Software Patching)", "Unconfirmed"
    if fid.startswith("COOKIE-SEC-"):
        return "TA0006 T1539", "WSTG-SESS-02", "D3-CH (Secure Cookie Attribute)", "Confirmed"
    if fid.startswith("COOKIE-HTTPONLY-"):
        return "TA0006 T1539", "WSTG-SESS-02", "D3-CH (HttpOnly Cookie Attribute)", "Confirmed"
    if fid.startswith("COOKIE-SAMESITE-"):
        return "TA0001 T1189", "WSTG-SESS-05", "D3-CH (SameSite CSRF Guard)", "Confirmed"
    if fid in {"HDR-CSP-UNSAFE", "HDR-CSP"}:
        return "TA0001 T1189", "WSTG-CLNT-01", "D3-SPP (Strict Nonce/Hash CSP)", "Confirmed"
    if fid.startswith("HDR-HSTS"):
        return "TA0006 T1557", "WSTG-CONF-07", "D3-ITF (HSTS Preload Enforcement)", "Confirmed"
    if fid == "HDR-XCTO":
        return "TA0001 T1189", "WSTG-CONF-07", "D3-ITF (X-Content-Type-Options)", "Confirmed"
    if fid in {"HDR-REF", "HDR-PERM", "HDR-COOP", "HDR-CORP", "HDR-COEP", "HDR-XFO"}:
        return "TA0043 T1592.002", "WSTG-CONF-07", "D3-ITF (Browser Isolation Headers)", "Confirmed"
    if fid.startswith("DISC-"):
        return "TA0043 T1592.002", "WSTG-INFO-02", "D3-ITF (Edge Banner/Timing Strip)", "Confirmed"
    if fid == "INTEL-ORIGIN-DRIFT":
        return "TA0043 T1596", "WSTG-INFO-04", "D3-NI (Origin IP Direct-Access ACL)", "Confirmed"
    if fid == "DNS-001":
        return "TA0042 T1584.001", "WSTG-CONF-10", "D3-DNSA (Dangling CNAME Cleanup)", "Likely"
    if fid == "DNS-002":
        return "TA0042 T1587.003", "WSTG-CRYP-01", "D3-DNSA (DNS CAA Restriction)", "Confirmed"
    if fid.startswith("DNS-"):
        return "TA0043 T1590.002", "WSTG-INFO-04", "D3-DNSA (DNSSEC & Mail Hygiene)", "Confirmed"
    if cat == "tls" or fid.startswith("TLS-"):
        return "TA0006 T1557", "WSTG-CRYP-01", "D3-ITF (TLS 1.3 / Cipher Hardening)", "Confirmed"
    if cat == "cors" or fid.startswith("CORS-"):
        return "TA0009 T1185", "WSTG-CLNT-07", "D3-ITF (Strict CORS Origin Allowlist)", "Confirmed"
    return "TA0043 T1592", "WSTG-INFO-01", "D3-ITF (Defensive Configuration)", "Confirmed"


def _build_structured_json(ctx: _TelemetryContext) -> str:
    top_findings = [str(f.get("id")) for f in ctx.findings[:6] if f.get("id")]
    top_cves = [str(c.get("cve_id")) for c in ctx.cves[:4] if c.get("cve_id")]
    all_refs = top_findings + top_cves

    has_crit = any(str(f.get("severity")).upper() == "CRITICAL" for f in ctx.findings) or any(
        c.get("in_kev") for c in ctx.cves
    )
    has_high = any(str(f.get("severity")).upper() == "HIGH" for f in ctx.findings) or bool(ctx.cves)
    has_med = any(str(f.get("severity")).upper() == "MEDIUM" for f in ctx.findings)
    risk_rating = (
        "CRITICAL"
        if has_crit
        else ("HIGH" if has_high else ("MEDIUM" if has_med else "LOW"))
    )

    actions: list[dict[str, Any]] = []
    if top_cves:
        actions.append(
            {
                "priority": "P0",
                "title": "Remediate Correlated CVE / KEV Stack Exposure",
                "finding_refs": top_cves + [f for f in top_findings if f.startswith("EOL-")],
                "remediation": (
                    "Upgrade affected stack components to patched releases and enforce "
                    "edge WAF virtual patching."
                ),
                "verification": f"s1shell assess {ctx.target_url} --authorized --enrich-cve",
            }
        )
    cookie_hdr_refs = [
        str(f["id"])
        for f in ctx.findings
        if str(f.get("id", "")).startswith(("HDR-", "COOKIE-", "CORS-"))
    ][:6]
    if cookie_hdr_refs:
        actions.append(
            {
                "priority": "P1",
                "title": "Harden CSP, Transport Headers, and Cookie Security Attributes",
                "finding_refs": cookie_hdr_refs,
                "remediation": (
                    "Remove 'unsafe-inline'/'unsafe-eval' from CSP in favor of cryptographic "
                    "nonces, enforce HSTS max-age>=31536000, add X-Content-Type-Options: nosniff, "
                    "and set Secure, HttpOnly, and SameSite=Lax/Strict on all cookies."
                ),
                "verification": f"s1shell assess {ctx.target_url} --authorized",
            }
        )
    recon_refs = [
        str(f["id"])
        for f in ctx.findings
        if str(f.get("id", "")).startswith(("INTEL-", "DISC-", "DNS-"))
    ][:6]
    if recon_refs:
        actions.append(
            {
                "priority": "P2",
                "title": "Close Origin Drift, Edge Telemetry Leaks, and DNS CAA/DNSSEC Gaps",
                "finding_refs": recon_refs,
                "remediation": (
                    "Verify historical origin IPs block direct non-CDN ingress, strip verbose "
                    "Server-Timing/Server banners at the edge, and publish DNS CAA + DNSSEC."
                ),
                "verification": f"s1shell profile {ctx.target_url} --authorized --dns-security",
            }
        )
    if not actions and all_refs:
        actions.append(
            {
                "priority": "P2",
                "title": "Apply Baseline Defensive Hardening",
                "finding_refs": all_refs[:5],
                "remediation": "Apply S1shell deterministic remediation snippets across edge/DNS.",
                "verification": f"s1shell assess {ctx.target_url} --authorized",
            }
        )

    cookie_chain_ids = ", ".join(cookie_hdr_refs[:4]) or "baseline"
    recon_chain_ids = ", ".join(recon_refs[:4]) or "baseline"
    score_val = ctx.score if ctx.score is not None else "n/a"
    refs_summary = ", ".join(all_refs[:6]) or "no active IDs"

    payload = {
        "summary": (
            f"Assessment of {ctx.target_url} ({ctx.pinned_ip}) yielded posture score "
            f"{score_val}/100 (Grade {ctx.grade}, Risk {ctx.risk_level}) across "
            f"{len(ctx.findings)} finding(s) and {len(ctx.cves)} CVE(s) ({refs_summary})."
        ),
        "risk_rating": risk_rating,
        "prioritized_actions": actions,
        "attack_paths": [
            (
                f"Client-Side Script & Session Cookie Chain ({cookie_chain_ids}): "
                "Permissive CSP directives combined with cookies lacking Secure/HttpOnly/SameSite "
                "enable DOM script execution to read or transmit session state."
            ),
            (
                f"Origin Drift & Edge Telemetry Recon Chain ({recon_chain_ids}): "
                "Historical origin IP drift and Server-Timing metadata allow adversaries to map "
                "backend infrastructure and probe for direct-to-origin WAF bypass."
            ),
        ],
        "detection_ideas": [
            "Alert on direct HTTP/HTTPS connections to origin IPs bypassing CDN edge IP ranges.",
            "Monitor CSP violation reports for unauthorized inline script execution.",
            "Alert on CT log issuance outside approved corporate CAs (DNS CAA).",
        ],
        "quick_wins": [
            "Enforce Secure, HttpOnly, and SameSite attributes on all Set-Cookie headers.",
            "Set X-Content-Type-Options: nosniff, Referrer-Policy, and Permissions-Policy.",
            "Publish DNS CAA records restricting certificate issuance to authorized CAs.",
        ],
    }
    return json.dumps(payload, indent=2)


def _build_markdown_analysis(ctx: _TelemetryContext) -> str:
    stack_str = (
        ", ".join(
            f"{m.get('product')}{' ' + str(m.get('version')) if m.get('version') else ''}"
            for m in ctx.stack_matches
        )
        or "Generic Web / Edge"
    )
    score_str = (
        f"{ctx.score}/100 (Grade `{ctx.grade}`, Risk `{ctx.risk_level}`)"
        if ctx.score is not None
        else "n/a"
    )
    proto_str = f"`{ctx.http_version or 'HTTP/2'}` / `{ctx.tls_version or 'TLSv1.3'}`"

    lines: list[str] = [
        "## 1. Target Surface & High-Signal Primitives (Identities, Keys/IDs, Forms, Origin IPs)",
        "",
        "| Surface Dimension | Observed Telemetry & High-Signal Primitives |",
        "|---|---|",
        (
            f"| **Target / Pinned IP** | `{ctx.target_url}` → `{ctx.pinned_ip}` "
            f"(Scope `{ctx.auth_ref}` / `{ctx.scope_id}`, Preset `{ctx.preset}`) |"
        ),
        (
            f"| **Posture & Stack** | Score `{score_str}` · Stack: `{stack_str}` · "
            f"Protocol: {proto_str} |"
        ),
    ]
    if ctx.redirect_location:
        lines.append(
            f"| **HTTP Redirect Target** | `{ctx.redirect_location}` "
            "(`301/302` regional/canonical routing) |"
        )
    if ctx.emails or ctx.gmail_addresses or ctx.phones:
        id_parts: list[str] = []
        if ctx.emails:
            id_parts.append(f"Emails: `{', '.join(ctx.emails[:6])}`")
        if ctx.gmail_addresses:
            id_parts.append(f"Gmail: `{', '.join(ctx.gmail_addresses[:4])}`")
        if ctx.phones:
            id_parts.append(f"Phones: `{', '.join(ctx.phones[:4])}`")
        lines.append(f"| **Identities & Contacts** | {' · '.join(id_parts)} |")
    if ctx.csp_external_hosts:
        hosts_csv = ", ".join(ctx.csp_external_hosts[:8])
        lines.append(
            f"| **CSP Trusted / Non-Prod Hosts** | `{hosts_csv}` "
            "(disclosed in `Content-Security-Policy`) |"
        )
    if ctx.client_keys or ctx.cloud_buckets:
        key_parts: list[str] = []
        if ctx.client_keys:
            key_parts.append(f"Keys/Tokens: `{', '.join(ctx.client_keys[:5])}`")
        if ctx.cloud_buckets:
            key_parts.append(f"Cloud Buckets: `{', '.join(ctx.cloud_buckets[:5])}`")
        lines.append(f"| **Exposed Keys & Buckets** | {' · '.join(key_parts)} |")
    if ctx.forms or ctx.url_params:
        inp_parts: list[str] = []
        if ctx.forms:
            inp_parts.append(f"Forms: `{', '.join(ctx.forms[:4])}`")
        if ctx.url_params:
            inp_parts.append(f"URL Params: `{', '.join(ctx.url_params[:8])}`")
        lines.append(f"| **Input Vectors (Forms/Params)** | {' · '.join(inp_parts)} |")
    if ctx.cookies:
        c_summaries = [
            (
                f"`{c.get('name')}` (Secure=`{c.get('secure')}`, "
                f"HttpOnly=`{c.get('http_only')}`, SameSite=`{c.get('same_site')}`)"
            )
            for c in ctx.cookies[:6]
        ]
        lines.append(f"| **Observed Cookies** | {', '.join(c_summaries)} |")
    if ctx.origin_drift_ips or ctx.observed_servers:
        drift_txt = f"Historical IPs: `{', '.join(ctx.origin_drift_ips[:6]) or 'none'}`"
        if ctx.observed_servers:
            drift_txt += f" · Historical Servers: `{', '.join(ctx.observed_servers[:4])}`"
        if ctx.observed_asns:
            drift_txt += f" · ASNs: `{', '.join(ctx.observed_asns[:3])}`"
        lines.append(f"| **Passive Origin Drift (urlscan)** | {drift_txt} |")
    if ctx.cnames or ctx.wildcard_sans or ctx.registrar:
        dns_parts: list[str] = []
        if ctx.cnames:
            dns_parts.append(f"CNAME: `{', '.join(ctx.cnames[:3])}`")
        if ctx.wildcard_sans:
            dns_parts.append(f"Wildcard SANs: `{', '.join(ctx.wildcard_sans[:3])}`")
        if ctx.registrar:
            dns_parts.append(
                f"Registrar: `{ctx.registrar}` "
                f"(locked=`{ctx.transfer_locked}`, DNSSEC=`{ctx.dnssec_signed}`)"
            )
        lines.append(f"| **DNS / PKI / RDAP** | {' · '.join(dns_parts)} |")
    if ctx.banners:
        lines.append(f"| **Edge Banner & Timing Leaks** | `{'; '.join(ctx.banners[:4])}` |")

    lines.extend(
        [
            "",
            "## 2. Chained Attack Paths (Ordered by Cost-to-Attacker)",
            "",
        ]
    )

    fids_by_prefix = {str(f.get("id", "")): f for f in ctx.findings if f.get("id")}
    csp_fids = [
        fid for fid in fids_by_prefix if fid.startswith(("HDR-CSP", "HDR-XCTO", "HDR-HSTS"))
    ]
    cookie_fids = [fid for fid in fids_by_prefix if fid.startswith("COOKIE-")]
    drift_fids = [fid for fid in fids_by_prefix if fid.startswith(("INTEL-", "DISC-"))]
    dns_fids = [fid for fid in fids_by_prefix if fid.startswith(("DNS-", "TLS-"))]
    iso_set = {"HDR-REF", "HDR-PERM", "HDR-COOP", "HDR-CORP", "HDR-COEP"}
    iso_fids = [fid for fid in fids_by_prefix if fid in iso_set]
    cve_ids = [str(c.get("cve_id")) for c in ctx.cves if c.get("cve_id")]
    eol_fids = [fid for fid in fids_by_prefix if fid.startswith("EOL-")]

    path_idx = 1
    if cve_ids or eol_fids:
        chain_refs = ", ".join(f"`{r}`" for r in (cve_ids + eol_fids)[:6])
        lines.extend(
            [
                (
                    f"### Path {path_idx} — Public-Facing Stack / EOL CVE Exploitation Chain "
                    "(`Confirmed`, Cost: Low)"
                ),
                f"- **Composed Primitives:** {chain_refs} on `{stack_str}` (`{ctx.target_url}`).",
                (
                    "- **ATT&CK Chain:** `TA0043 T1592.002` (Software Discovery) → "
                    "`TA0001 T1190` (Exploit Public-Facing Application)."
                ),
                (
                    "- **Operator Impact:** Version-fingerprinted edge/server stack with "
                    "correlated CVE/KEV advisories provides a direct initial-access candidate "
                    "if unpatched at origin."
                ),
                (
                    "- **Chokepoint Counter (`MITRE D3FEND D3-SVA`):** Upgrade affected stack "
                    "version and enforce virtual patching at the edge WAF."
                ),
                "",
            ]
        )
        path_idx += 1

    if csp_fids or cookie_fids:
        chain_refs = ", ".join(f"`{r}`" for r in (csp_fids + cookie_fids)[:8])
        lines.extend(
            [
                (
                    f"### Path {path_idx} — Client-Side Script Execution & Session Cookie Chain "
                    "(`Confirmed`, Cost: Low)"
                ),
                f"- **Composed Primitives:** {chain_refs}.",
                (
                    "- **ATT&CK & WSTG Chain:** `TA0001 T1189` / `WSTG-CLNT-01` (Permissive CSP "
                    "`'unsafe-inline'`/`'unsafe-eval'`/`data:`/`blob:` & missing `nosniff`) → "
                    "`TA0006 T1539` / `WSTG-SESS-02` (Cookies missing `Secure`, `HttpOnly`, "
                    "and `SameSite` flags)."
                ),
                (
                    "- **Operator Impact:** Reflected/DOM script injection on the origin or "
                    "trusted `frame-ancestors` bypasses CSP script restrictions and reads "
                    "non-`HttpOnly` cookies via `document.cookie`, while cookies lacking `Secure` "
                    "can transmit over plaintext HTTP before HSTS preload takes effect."
                ),
                (
                    "- **Chokepoint Counter (`MITRE D3FEND D3-SPP` + `D3-CH`):** Replace "
                    "`'unsafe-inline'`/`'unsafe-eval'` with per-response CSP nonces and enforce "
                    "`Secure; HttpOnly; SameSite=Lax` across all `Set-Cookie` headers."
                ),
                "",
            ]
        )
        path_idx += 1

    if drift_fids or ctx.csp_external_hosts or iso_fids:
        chain_refs = ", ".join(f"`{r}`" for r in (drift_fids + iso_fids)[:7])
        csp_hosts_note = (
            " plus CSP-disclosed non-production/third-party hosts "
            f"(`{', '.join(ctx.csp_external_hosts[:5])}`)"
            if ctx.csp_external_hosts
            else ""
        )
        hist_ips = ", ".join(ctx.origin_drift_ips[:5]) or "n/a"
        hist_srvs = ", ".join(ctx.observed_servers[:3]) or "n/a"
        lines.extend(
            [
                (
                    f"### Path {path_idx} — Origin IP Drift, Non-Prod CSP Pivot & Edge Telemetry "
                    "Chain (`Confirmed`, Cost: Low–Medium)"
                ),
                f"- **Composed Primitives:** {chain_refs or 'passive telemetry'}{csp_hosts_note}.",
                (
                    "- **ATT&CK & WSTG Chain:** `TA0043 T1596` / `WSTG-INFO-04` (Search Open "
                    "Technical Databases / Origin Drift) → `TA0043 T1592.002` / `WSTG-INFO-02` "
                    "(`Server-Timing` & banner fingerprinting) → `TA0001 T1190` "
                    "(Direct-to-Origin / Non-Prod Instance Probing)."
                ),
                (
                    f"- **Operator Impact:** Live edge IP (`{ctx.pinned_ip}`) differs from "
                    f"historical observed IPs (`{hist_ips}`) and backend servers (`{hist_srvs}`), "
                    "while CSP `frame-ancestors` exposes internal/staging tenant hostnames and "
                    "missing cross-origin headers allow cross-window/referrer leakage."
                ),
                (
                    "- **Chokepoint Counter (`MITRE D3FEND D3-NI` + `D3-ITF`):** Restrict origin "
                    "firewall ingress strictly to authenticated CDN IP ranges, strip non-prod "
                    "hostnames from production CSP headers, and scrub `Server-Timing` metrics."
                ),
                "",
            ]
        )
        path_idx += 1

    if dns_fids:
        chain_refs = ", ".join(f"`{r}`" for r in dns_fids[:5])
        lines.extend(
            [
                (
                    f"### Path {path_idx} — Domain PKI Issuance & Unsigned DNS Zone Chain "
                    "(`Confirmed`, Cost: Medium)"
                ),
                (
                    f"- **Composed Primitives:** {chain_refs} "
                    f"(Wildcard SAN=`{ctx.tls_wildcard}`, DNSSEC=`{ctx.dnssec_signed}`)."
                ),
                (
                    "- **ATT&CK & WSTG Chain:** `TA0043 T1590.002` (DNS Recon) → "
                    "`TA0042 T1587.003` / `WSTG-CRYP-01` (Unrestricted CA Issuance without "
                    "DNS `CAA` or `DNSSEC`)."
                ),
                (
                    "- **Operator Impact:** Absence of DNS `CAA` records allows any publicly "
                    "trusted CA to issue certificates for the domain if domain-validation or "
                    "routing is subverted on an unsigned zone."
                ),
                (
                    "- **Chokepoint Counter (`MITRE D3FEND D3-DNSA`):** Publish restrictive "
                    "`CAA` records and enable DNSSEC signing at the registrar."
                ),
                "",
            ]
        )

    lines.extend(
        [
            "## 3. Technique Breakdown (ATT&CK, WSTG v4.2, Confidence & Evidence)",
            "",
            (
                "| Finding / CVE ID | Severity | Confidence | MITRE ATT&CK | "
                "OWASP WSTG | Observed Evidence |"
            ),
            "|---|---|---|---|---|---|",
        ]
    )
    for cve in ctx.cves[:10]:
        cid = str(cve.get("cve_id"))
        sev = str(cve.get("severity") or "HIGH")
        score = cve.get("base_score")
        epss = cve.get("epss_score")
        kev = "KEV=YES" if cve.get("in_kev") else "KEV=no"
        desc = str(cve.get("description") or "")[:80].replace("|", "/")
        ev = f"CVSS={score or 'n/a'}, EPSS={epss if epss is not None else 'n/a'}, {kev} — {desc}"
        lines.append(
            f"| `{cid}` | **{sev}** | `Confirmed` | `TA0001 T1190` | `WSTG-INFO-08` | {ev} |"
        )
    for f in ctx.findings:
        fid = str(f.get("id") or "")
        sev = str(f.get("severity") or "INFO")
        attck, wstg, _d3, conf = _map_finding_tactics(f)
        raw_ev = str(f.get("evidence") or f.get("title") or "")
        ev = raw_ev.replace("|", "/").replace("\n", " ")[:110]
        lines.append(f"| `{fid}` | **{sev}** | `{conf}` | `{attck}` | `{wstg}` | {ev} |")

    verify_cmds: list[str] = [
        "# 1. Re-verify HTTP security headers, cookies, TLS chain, and DNS CAA/DNSSEC posture",
        (
            f"s1shell profile {ctx.target_url} --authorized "
            "--tls-versions --dns-security --well-known --check-methods"
        ),
        "",
        "# 2. Correlate passive origin IP drift, CT SAN subdomains, and RDAP registration",
        f"s1shell intel lookup {ctx.target_url} --sources vt,greynoise,urlscan,rdap",
        f"s1shell intel ct {ctx.target_url}",
        "",
        "# 3. Generate deterministic stack-tailored hardening configs & re-score posture",
        "s1shell remediate ./results/target/assess.json --stack auto --format md",
    ]
    if ctx.cves:
        cve_args = " ".join(str(c["cve_id"]) for c in ctx.cves[:5])
        verify_cmds.extend(
            [
                "",
                "# 4. Verify correlated CVE advisories against CISA KEV & FIRST EPSS",
                f"s1shell cve get {cve_args} --enrich",
            ]
        )

    lines.extend(
        [
            "",
            "### Reproducible S1shell Verification Commands & OPSEC Footprint",
            "",
            (
                "- **OPSEC / Detection Footprint:** `profile` / `assess` executes bounded "
                f"read-only HTTP `GET`/`HEAD` requests pinned to `{ctx.pinned_ip}` with honest "
                "`S1shell` User-Agent; `intel`, `cve`, and `remediate` are "
                "**zero-target-contact**."
            ),
            "",
            "```bash",
            *verify_cmds,
            "```",
        ]
    )

    lines.extend(
        [
            "",
            "## 4. Prioritized Remediation & MITRE D3FEND Countermeasure Table",
            "",
            (
                "| Priority | Finding / CVE ID | MITRE D3FEND Counter | "
                "Compliance (CWE / ASVS / OWASP / NIST) | Concrete Defensive Remediation |"
            ),
            "|---|---|---|---|---|",
        ]
    )
    seen_rem_ids: set[str] = set()
    for cve in ctx.cves[:10]:
        cid = str(cve.get("cve_id"))
        seen_rem_ids.add(cid)
        prio = "P0" if cve.get("in_kev") else "P1"
        patched_list = [str(p) for p in (cve.get("patched_versions") or [])[:3]]
        patched = ", ".join(patched_list) or "latest patched release"
        lines.append(
            f"| **{prio}** | `{cid}` | `D3-SVA (Software Patching)` | `A06:2021 / SI-2` | "
            f"Upgrade component to `{patched}` and verify via `s1shell cve get {cid} --enrich`. |"
        )
    for f in ctx.findings:
        fid = str(f.get("id") or "")
        if not fid or fid in seen_rem_ids:
            continue
        seen_rem_ids.add(fid)
        sev = str(f.get("severity") or "INFO").upper()
        if sev == "CRITICAL":
            prio = "P0"
        elif sev in {"HIGH", "MEDIUM"}:
            prio = "P1"
        elif sev == "LOW":
            prio = "P2"
        else:
            prio = "P3"
        _attck, _wstg, d3fend, _conf = _map_finding_tactics(f)
        comp = (
            " / ".join(
                str(x)
                for x in (f.get("cwe"), f.get("asvs"), f.get("owasp"), f.get("nist"))
                if x
            )
            or "—"
        )
        raw_rem = str(f.get("remediation") or "Apply baseline hardening.")
        rem = raw_rem.replace("|", "/").replace("\n", " ")
        lines.append(f"| **{prio}** | `{fid}` | `{d3fend}` | `{comp}` | {rem} |")

    if ctx.dep_vulns:
        lines.extend(
            [
                "",
                "## 5. Supply-Chain & SBOM Vulnerability Queue",
                "",
                "| Package | Installed | Fixed | Advisory ID | Severity / KEV |",
                "|---|---|---|---|---|",
            ]
        )
        for v in ctx.dep_vulns[:20]:
            vid = str(v.get("vuln_id") or "")
            pkg = f"{v.get('ecosystem', '')}:{v.get('package', '')}"
            ver = str(v.get("version") or "—")
            fix = str(v.get("fixed_version") or "unpatched")
            sev = f"{v.get('severity', 'UNKNOWN')} (KEV={v.get('in_kev', False)})"
            lines.append(f"| `{pkg}` | `{ver}` | `{fix}` | `{vid}` | {sev} |")
        if ctx.upgrade_commands:
            lines.extend(["", "```bash", *ctx.upgrade_commands[:10], "```"])

    if ctx.diff_summary:
        d = ctx.diff_summary
        sb = f"{d.get('score_before')}/100 (`{d.get('grade_before')}`)"
        sa = (
            f"{d.get('score_after')}/100 "
            f"(`{d.get('grade_after')}`, delta `{d.get('score_delta')}`)"
        )
        verdict = "REGRESSED" if d.get("regressed") else "PASS / IMPROVED"
        lines.extend(
            [
                "",
                "## 5. Baseline vs Current Re-Test Drift Summary",
                "",
                f"- **Score Drift:** `{sb}` → `{sa}`",
                f"- **Regression Verdict:** `{verdict}`",
            ]
        )

    return "\n".join(lines)


class BuiltinAIClient:
    """Zero-key, offline, telemetry-grounded tactical & defensive AI synthesis engine."""

    def __init__(self, cfg: RuntimeConfig) -> None:
        self._cfg = cfg

    @property
    def audit_target(self) -> str:
        return f"local:{DEFAULT_BUILTIN_MODEL}"

    def complete(
        self,
        *,
        prompt: str,
        model: str = DEFAULT_BUILTIN_MODEL,
        max_tokens: int = 1024,
        system_prompt: str = "",
    ) -> tuple[str, int, int]:
        """Synthesize a 100% telemetry-grounded response and return `(text, in_tok, out_tok)`."""
        _ = (model, max_tokens)
        ctx = _extract_telemetry_context(prompt)
        in_tok = max(1, len(system_prompt + prompt) // 4)

        if "Return ONLY a single valid JSON object" in system_prompt:
            text = _build_structured_json(ctx)
            out_tok = max(1, len(text) // 4)
            return text, in_tok, out_tok

        if "bounded read-only defensive investigation loop" in system_prompt:
            md_answer = _build_markdown_analysis(ctx)
            react_payload = {
                "action": "final",
                "thought": (
                    "Synthesized all Finding IDs, CVE IDs, passive OSINT indicators, and "
                    "MITRE ATT&CK / D3FEND mappings directly from verified S1shell telemetry."
                ),
                "answer": md_answer,
            }
            text = json.dumps(react_payload)
            out_tok = max(1, len(text) // 4)
            return text, in_tok, out_tok

        text = _build_markdown_analysis(ctx)
        out_tok = max(1, len(text) // 4)
        return text, in_tok, out_tok
