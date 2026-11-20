"""Deterministic offline hardening configuration generator (zero AI / zero network)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from s1shell.assess.models import AssessmentFinding, RemediationPlan, RemediationSnippet
from s1shell.errors import ValidationError

SUPPORTED_STACKS = ("auto", "nginx", "apache", "caddy", "express", "generic")

_HSTS_VAL = "max-age=31536000; includeSubDomains"
_CSP_STRICT = "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
_CSP_NONCE = (
    "default-src 'self'; script-src 'self' 'nonce-$request_id'; object-src 'none'; base-uri 'self'"
)
_PERM_VAL = "camera=(), geolocation=(), microphone=()"


def _detect_stacks(fingerprint_matches: list[dict[str, Any]]) -> list[str]:
    stacks: list[str] = []
    for m in fingerprint_matches:
        prod = str(m.get("product") or "").lower()
        if ("nginx" in prod or "openresty" in prod) and "nginx" not in stacks:
            stacks.append("nginx")
        elif "apache" in prod and "tomcat" not in prod and "apache" not in stacks:
            stacks.append("apache")
        elif "caddy" in prod and "caddy" not in stacks:
            stacks.append("caddy")
        elif ("express" in prod or "next.js" in prod) and "express" not in stacks:
            stacks.append("express")
    return stacks


def _build_nginx_snippets(fids: set[str]) -> list[RemediationSnippet]:
    snippets: list[RemediationSnippet] = []

    tls_ids = sorted(fid for fid in fids if fid in {"TLS-004", "TLS-005", "TLS-009"})
    if tls_ids:
        snippets.append(
            RemediationSnippet(
                title="NGINX TLS 1.2/1.3 & AEAD Cipher Hardening",
                stack="nginx",
                finding_ids=tls_ids,
                language="nginx",
                config=(
                    "ssl_protocols TLSv1.2 TLSv1.3;\n"
                    "ssl_prefer_server_ciphers off;\n"
                    "ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
                    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
                    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;\n"
                    "ssl_session_tickets off;"
                ),
            )
        )

    hdr_lines: list[str] = []
    hdr_ids: list[str] = []
    header_directives = [
        ("HDR-HSTS", f'add_header Strict-Transport-Security "{_HSTS_VAL}" always;'),
        ("HDR-HSTS-WEAK", f'add_header Strict-Transport-Security "{_HSTS_VAL}" always;'),
        ("HDR-CSP", f'add_header Content-Security-Policy "{_CSP_STRICT}" always;'),
        ("HDR-CSP-UNSAFE", f'add_header Content-Security-Policy "{_CSP_NONCE}" always;'),
        ("HDR-XFO", 'add_header X-Frame-Options "DENY" always;'),
        ("HDR-XCTO", 'add_header X-Content-Type-Options "nosniff" always;'),
        ("HDR-REF", 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;'),
        ("HDR-PERM", f'add_header Permissions-Policy "{_PERM_VAL}" always;'),
        ("HDR-COOP", 'add_header Cross-Origin-Opener-Policy "same-origin" always;'),
        ("HDR-CORP", 'add_header Cross-Origin-Resource-Policy "same-origin" always;'),
        ("HDR-CACHE", 'add_header Cache-Control "no-store, private" always;'),
    ]
    for fid, line in header_directives:
        if fid in fids:
            hdr_ids.append(fid)
            if line not in hdr_lines:
                hdr_lines.append(line)

    disc_ids = sorted(fid for fid in fids if fid.startswith("DISC-"))
    if disc_ids:
        hdr_ids.extend(disc_ids)
        hdr_lines.extend(["server_tokens off;", "proxy_hide_header X-Powered-By;"])

    if hdr_lines:
        snippets.append(
            RemediationSnippet(
                title="NGINX Security Headers & Banner Suppression",
                stack="nginx",
                finding_ids=sorted(set(hdr_ids)),
                language="nginx",
                config="\n".join(hdr_lines),
            )
        )

    if "METH-001" in fids:
        snippets.append(
            RemediationSnippet(
                title="NGINX Restrict HTTP Methods",
                stack="nginx",
                finding_ids=["METH-001"],
                language="nginx",
                config="if ($request_method !~ ^(GET|HEAD|POST)$) {\n    return 405;\n}",
            )
        )

    cookie_ids = sorted(fid for fid in fids if fid.startswith("COOKIE-"))
    if cookie_ids:
        snippets.append(
            RemediationSnippet(
                title="NGINX Enforce Secure Cookie Flags on Upstream Proxies",
                stack="nginx",
                finding_ids=cookie_ids,
                language="nginx",
                config="proxy_cookie_flags ~ secure httponly samesite=lax;",
            )
        )

    return snippets


def _build_apache_snippets(fids: set[str]) -> list[RemediationSnippet]:
    snippets: list[RemediationSnippet] = []
    tls_ids = sorted(fid for fid in fids if fid in {"TLS-004", "TLS-005", "TLS-009"})
    if tls_ids:
        snippets.append(
            RemediationSnippet(
                title="Apache HTTP Server TLS Hardening",
                stack="apache",
                finding_ids=tls_ids,
                language="apache",
                config=(
                    "SSLProtocol -all +TLSv1.2 +TLSv1.3\n"
                    "SSLHonorCipherOrder off\n"
                    "SSLSessionTickets off"
                ),
            )
        )

    lines: list[str] = []
    hdr_ids: list[str] = []
    mapping = [
        ("HDR-HSTS", f'Header always set Strict-Transport-Security "{_HSTS_VAL}"'),
        ("HDR-HSTS-WEAK", f'Header always set Strict-Transport-Security "{_HSTS_VAL}"'),
        ("HDR-CSP", f'Header always set Content-Security-Policy "{_CSP_STRICT}"'),
        ("HDR-CSP-UNSAFE", f'Header always set Content-Security-Policy "{_CSP_STRICT}"'),
        ("HDR-XFO", 'Header always set X-Frame-Options "DENY"'),
        ("HDR-XCTO", 'Header always set X-Content-Type-Options "nosniff"'),
        ("HDR-REF", 'Header always set Referrer-Policy "strict-origin-when-cross-origin"'),
        ("HDR-PERM", f'Header always set Permissions-Policy "{_PERM_VAL}"'),
        ("HDR-CACHE", 'Header always set Cache-Control "no-store, private"'),
    ]
    for fid, line in mapping:
        if fid in fids:
            hdr_ids.append(fid)
            if line not in lines:
                lines.append(line)
    disc_ids = sorted(fid for fid in fids if fid.startswith("DISC-"))
    if disc_ids:
        hdr_ids.extend(disc_ids)
        lines.extend(
            ["ServerTokens Prod", "ServerSignature Off", "Header always unset X-Powered-By"]
        )
    if "METH-001" in fids:
        hdr_ids.append("METH-001")
        lines.append("TraceEnable Off")
    if lines:
        snippets.append(
            RemediationSnippet(
                title="Apache HTTP Server Headers & Disclosure Hardening",
                stack="apache",
                finding_ids=sorted(set(hdr_ids)),
                language="apache",
                config="\n".join(lines),
            )
        )
    return snippets


def _build_caddy_snippets(fids: set[str]) -> list[RemediationSnippet]:
    hdr_lines: list[str] = []
    hdr_ids: list[str] = []
    mapping = [
        ("HDR-HSTS", f'Strict-Transport-Security "{_HSTS_VAL}"'),
        ("HDR-CSP", f'Content-Security-Policy "{_CSP_STRICT}"'),
        ("HDR-XFO", 'X-Frame-Options "DENY"'),
        ("HDR-XCTO", 'X-Content-Type-Options "nosniff"'),
        ("HDR-REF", 'Referrer-Policy "strict-origin-when-cross-origin"'),
        ("HDR-PERM", f'Permissions-Policy "{_PERM_VAL}"'),
        ("HDR-CACHE", 'Cache-Control "no-store, private"'),
    ]
    for fid, line in mapping:
        if fid in fids:
            hdr_ids.append(fid)
            hdr_lines.append(f"    {line}")
    disc_ids = sorted(fid for fid in fids if fid.startswith("DISC-"))
    if disc_ids:
        hdr_ids.extend(disc_ids)
        hdr_lines.extend(["    -Server", "    -X-Powered-By"])
    if not hdr_lines:
        return []
    return [
        RemediationSnippet(
            title="Caddyfile Security Headers",
            stack="caddy",
            finding_ids=sorted(set(hdr_ids)),
            language="caddy",
            config="header {\n" + "\n".join(hdr_lines) + "\n}",
        )
    ]


def _build_express_snippets(fids: set[str]) -> list[RemediationSnippet]:
    hdr_ids = sorted(fid for fid in fids if fid.startswith(("HDR-", "DISC-", "CORS-", "COOKIE-")))
    if not hdr_ids:
        return []
    return [
        RemediationSnippet(
            title="Express.js Helmet & Session Cookie Hardening",
            stack="express",
            finding_ids=hdr_ids,
            language="javascript",
            config=(
                'import helmet from "helmet";\n'
                'app.disable("x-powered-by");\n'
                "app.use(helmet({\n"
                "  hsts: { maxAge: 31536000, includeSubDomains: true },\n"
                "  contentSecurityPolicy: {\n"
                "    directives: { defaultSrc: [\"'self'\"], objectSrc: [\"'none'\"], "
                "baseUri: [\"'self'\"] }\n"
                "  }\n"
                "}));"
            ),
        )
    ]


def _build_generic_snippets(fids: set[str]) -> list[RemediationSnippet]:
    lines: list[str] = []
    hdr_ids: list[str] = []
    mapping = [
        ("HDR-HSTS", f"Strict-Transport-Security: {_HSTS_VAL}"),
        ("HDR-HSTS-WEAK", f"Strict-Transport-Security: {_HSTS_VAL}"),
        ("HDR-CSP", f"Content-Security-Policy: {_CSP_STRICT}"),
        ("HDR-CSP-UNSAFE", f"Content-Security-Policy: {_CSP_STRICT}"),
        ("HDR-XFO", "X-Frame-Options: DENY"),
        ("HDR-XCTO", "X-Content-Type-Options: nosniff"),
        ("HDR-REF", "Referrer-Policy: strict-origin-when-cross-origin"),
        ("HDR-PERM", f"Permissions-Policy: {_PERM_VAL}"),
        ("HDR-COOP", "Cross-Origin-Opener-Policy: same-origin"),
        ("HDR-CORP", "Cross-Origin-Resource-Policy: same-origin"),
        ("HDR-CACHE", "Cache-Control: no-store, private"),
    ]
    for fid, line in mapping:
        if fid in fids:
            hdr_ids.append(fid)
            if line not in lines:
                lines.append(line)
    if not lines:
        return []
    return [
        RemediationSnippet(
            title="Recommended HTTP Defensive Response Headers",
            stack="generic",
            finding_ids=sorted(set(hdr_ids)),
            language="http",
            config="\n".join(lines),
        )
    ]


def _build_dns_and_meta_snippets(fids: set[str], host: str) -> list[RemediationSnippet]:
    snippets: list[RemediationSnippet] = []
    dns_lines: list[str] = []
    dns_ids: list[str] = []
    if "DNS-002" in fids:
        dns_ids.append("DNS-002")
        dns_lines.append(f'{host}.  IN  CAA  0 issue "letsencrypt.org"')
    if "DNS-003" in fids or "DNS-003-NEUTRAL" in fids:
        dns_ids.extend(fid for fid in ("DNS-003", "DNS-003-NEUTRAL") if fid in fids)
        dns_lines.append(f'{host}.  IN  TXT  "v=spf1 -all"  ; adjust authorized mailers')
    if "DNS-004" in fids or "DNS-004-NONE" in fids:
        dns_ids.extend(fid for fid in ("DNS-004", "DNS-004-NONE") if fid in fids)
        dns_lines.append(
            f'_dmarc.{host}.  IN  TXT  "v=DMARC1; p=quarantine; adkim=s; aspf=s; '
            f'rua=mailto:dmarc@{host}"'
        )
    if "DNS-006" in fids:
        dns_ids.append("DNS-006")
        dns_lines.append(f'_mta-sts.{host}.  IN  TXT  "v=STSv1; id=20260101"')
        dns_lines.append(f'_smtp._tls.{host}.  IN  TXT  "v=TLSRPTv1; rua=mailto:tlsrpt@{host}"')
    if dns_lines:
        snippets.append(
            RemediationSnippet(
                title="DNS Security & Email Authentication Records",
                stack="dns",
                finding_ids=sorted(set(dns_ids)),
                language="dns",
                config="\n".join(dns_lines),
            )
        )

    wk_ids = sorted(fid for fid in fids if fid in {"WK-001", "WK-002", "WK-004"})
    if wk_ids:
        snippets.append(
            RemediationSnippet(
                title="RFC 9116 `/.well-known/security.txt` Template",
                stack="well_known",
                finding_ids=wk_ids,
                language="text",
                config=(
                    f"Contact: mailto:security@{host}\n"
                    f"Canonical: https://{host}/.well-known/security.txt\n"
                    "Preferred-Languages: en\n"
                    "Expires: 2027-12-31T23:59:59Z"
                ),
            )
        )

    return snippets


def generate_remediation_plan(
    *,
    target_url: str,
    findings: list[AssessmentFinding] | list[dict[str, Any]],
    fingerprint_matches: list[dict[str, Any]],
    stack: str = "auto",
) -> RemediationPlan:
    """Build deterministic defensive hardening snippets tailored to detected stack & findings."""
    norm_stack = stack.strip().lower()
    if norm_stack not in SUPPORTED_STACKS:
        raise ValidationError(f"Unsupported stack '{stack}'. Choose {', '.join(SUPPORTED_STACKS)}.")

    fids: set[str] = set()
    for item in findings:
        if isinstance(item, AssessmentFinding):
            fids.add(item.id)
        elif isinstance(item, dict) and item.get("id"):
            fids.add(str(item["id"]))

    detected = _detect_stacks(fingerprint_matches)
    selected = (detected[0] if detected else "generic") if norm_stack == "auto" else norm_stack

    if selected == "nginx":
        snippets = _build_nginx_snippets(fids)
    elif selected == "apache":
        snippets = _build_apache_snippets(fids)
    elif selected == "caddy":
        snippets = _build_caddy_snippets(fids)
    elif selected == "express":
        snippets = _build_express_snippets(fids)
    else:
        snippets = _build_generic_snippets(fids)

    host = (urlsplit(target_url).hostname or "example.com").strip()
    snippets.extend(_build_dns_and_meta_snippets(fids, host))

    return RemediationPlan(
        target=target_url,
        detected_stacks=detected,
        selected_stack=selected,
        snippets=snippets,
    )


def generate_remediation_from_file(path: Path, *, stack: str = "auto") -> RemediationPlan:
    """Load an `assess.json` artifact from disk and produce its offline remediation plan."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValidationError(f"Failed to read assessment artifact '{path}': {exc}") from exc

    if not isinstance(data, dict) or data.get("artifact_type") != "assess_report":
        raise ValidationError(
            f"File '{path}' is not a valid s1shell `assess_report` JSON artifact."
        )

    fp_blk = data.get("fingerprint")
    matches = (
        fp_blk.get("matches", [])
        if isinstance(fp_blk, dict) and isinstance(fp_blk.get("matches"), list)
        else []
    )
    findings = data.get("findings", []) if isinstance(data.get("findings"), list) else []
    target_url = str(data.get("url") or data.get("target") or "https://example.com/")
    return generate_remediation_plan(
        target_url=target_url,
        findings=findings,
        fingerprint_matches=matches,
        stack=stack,
    )
