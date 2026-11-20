"""Category-capped posture scoring, compliance mapping, and CI policy gate evaluation."""

from __future__ import annotations

from s1shell.assess.models import AssessmentFinding, PostureScore
from s1shell.cve.models import CVESearchResult
from s1shell.fingerprint.models import FingerprintResult
from s1shell.profile.models import ProfileResult

_SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}

_SEVERITY_PENALTIES = {
    "CRITICAL": 30,
    "HIGH": 18,
    "MEDIUM": 8,
    "LOW": 3,
    "INFO": 0,
}

# Domain penalty caps prevent noisy low-severity findings (e.g. many marketing cookies)
# from distorting the overall score relative to critical TLS/CVE issues.
_DOMAIN_MAP = {
    "transport": "tls_transport",
    "tls": "tls_transport",
    "headers": "headers",
    "cookies": "cookies_cors",
    "cors": "cookies_cors",
    "dns": "dns_hygiene",
    "html": "client_html",
    "well_known": "client_html",
    "disclosure": "disclosure",
    "cve": "cve_exposure",
}

_DOMAIN_PENALTY_CAPS = {
    "tls_transport": 40,
    "headers": 25,
    "cookies_cors": 20,
    "dns_hygiene": 18,
    "client_html": 15,
    "disclosure": 8,
    "cve_exposure": 35,
}

_DEPRECATED_TLS = {"TLSv1", "TLSv1.0", "TLSv1.1"}
_WEAK_SIG_HASHES = {"md5", "sha1"}

# (id, severity, remediation, cwe, asvs)
_HEADER_META: dict[str, tuple[str, str, str, str, str]] = {
    "Strict-Transport-Security": (
        "HDR-HSTS",
        "MEDIUM",
        "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` over HTTPS.",
        "CWE-319",
        "V14.4.5",
    ),
    "Content-Security-Policy": (
        "HDR-CSP",
        "MEDIUM",
        (
            "Define a restrictive `Content-Security-Policy` avoiding `'unsafe-inline'`, "
            "`'unsafe-eval'`, `data:`, and wildcard `*`."
        ),
        "CWE-693",
        "V14.4.3",
    ),
    "X-Frame-Options": (
        "HDR-XFO",
        "LOW",
        "Set `X-Frame-Options: DENY` (or `SAMEORIGIN`) alongside CSP `frame-ancestors`.",
        "CWE-1021",
        "V14.4.7",
    ),
    "X-Content-Type-Options": (
        "HDR-XCTO",
        "LOW",
        "Set `X-Content-Type-Options: nosniff` to prevent MIME-type sniffing.",
        "CWE-16",
        "V14.4.4",
    ),
    "Referrer-Policy": (
        "HDR-REF",
        "LOW",
        "Set `Referrer-Policy: strict-origin-when-cross-origin` or `no-referrer`.",
        "CWE-200",
        "V14.4.6",
    ),
    "Permissions-Policy": (
        "HDR-PERM",
        "LOW",
        "Set a `Permissions-Policy` restricting unused browser APIs (camera, geolocation, mic).",
        "CWE-693",
        "V14.4.1",
    ),
    "Cross-Origin-Opener-Policy": (
        "HDR-COOP",
        "INFO",
        "Consider setting `Cross-Origin-Opener-Policy: same-origin` for cross-origin isolation.",
        "CWE-346",
        "V14.4.1",
    ),
    "Cross-Origin-Resource-Policy": (
        "HDR-CORP",
        "INFO",
        "Consider setting `Cross-Origin-Resource-Policy: same-origin` or `same-site`.",
        "CWE-346",
        "V14.4.1",
    ),
    "Cross-Origin-Embedder-Policy": (
        "HDR-COEP",
        "INFO",
        "Consider setting `Cross-Origin-Embedder-Policy: require-corp` for cross-origin isolation.",
        "CWE-346",
        "V14.4.1",
    ),
}


def _compute_grade(score: int, counts: dict[str, int]) -> str:
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 55:
        grade = "D"
    else:
        grade = "F"

    # Enforce severity grade ceilings so critical/high risks cannot receive A/B grades.
    order = ["A", "B", "C", "D", "F"]
    if counts.get("CRITICAL", 0) > 0 and order.index(grade) < order.index("D"):
        return "D"
    if counts.get("HIGH", 0) > 0 and order.index(grade) < order.index("C"):
        return "C"
    return grade


def _compute_risk_level(score: int, counts: dict[str, int]) -> str:
    if counts.get("CRITICAL", 0) > 0:
        return "CRITICAL"
    if counts.get("HIGH", 0) > 0:
        return "HIGH"
    if score < 75 or counts.get("MEDIUM", 0) >= 2:
        return "MODERATE"
    if counts.get("MEDIUM", 0) > 0 or counts.get("LOW", 0) > 0:
        return "LOW"
    return "MINIMAL"


def check_policy_gate(
    posture: PostureScore,
    findings: list[AssessmentFinding],
    *,
    fail_on: str | None = None,
    min_score: int | None = None,
) -> str | None:
    """Return a failure reason if CI posture thresholds are breached, otherwise None."""
    reasons: list[str] = []
    if fail_on:
        norm_sev = fail_on.strip().upper()
        threshold = _SEVERITY_ORDER.get(norm_sev)
        if threshold is not None:
            breaching = [
                f for f in findings if _SEVERITY_ORDER.get(f.severity, 99) <= threshold
            ]
            if breaching:
                ids = ", ".join(f.id for f in breaching[:5])
                reasons.append(
                    f"Found {len(breaching)} finding(s) at or above {norm_sev} ({ids})"
                )
    if min_score is not None and posture.score < min_score:
        reasons.append(
            f"Posture score {posture.score}/100 (Grade {posture.grade}) is below "
            f"minimum threshold {min_score}"
        )
    return "; ".join(reasons) if reasons else None


def evaluate_posture(
    profile: ProfileResult,
    fingerprint: FingerprintResult,
    cve: CVESearchResult | None = None,
) -> tuple[PostureScore, list[AssessmentFinding]]:
    """Derive prioritized CWE/ASVS-mapped findings and a category-capped posture score."""
    findings: list[AssessmentFinding] = []
    is_https = profile.url.lower().startswith("https://")

    # 1. Transport & HTTP redirect posture
    if not is_https:
        redir = profile.protocol.redirect_location
        if redir and redir.lower().startswith("https://"):
            findings.append(
                AssessmentFinding(
                    id="TRANS-001",
                    severity="INFO",
                    category="transport",
                    title="Plain HTTP endpoint redirects to HTTPS",
                    evidence=f"HTTP {profile.protocol.status_code} -> {redir}",
                    remediation=(
                        "Ensure HSTS (`max-age>=31536000`) is served on the HTTPS destination."
                    ),
                    cwe="CWE-319",
                    asvs="V9.1.1",
                )
            )
        else:
            findings.append(
                AssessmentFinding(
                    id="TRANS-002",
                    severity="HIGH",
                    category="transport",
                    title="Plain HTTP endpoint does not redirect to HTTPS",
                    evidence=(f"HTTP {profile.protocol.status_code} (Location: {redir or 'none'})"),
                    remediation="Enforce an immediate 301/308 redirect from HTTP to HTTPS.",
                    cwe="CWE-319",
                    asvs="V9.1.1",
                )
            )

    # 2. TLS, Cipher & X.509 certificate posture
    tls = profile.tls
    if tls is not None and tls.applicable:
        if not tls.verified:
            findings.append(
                AssessmentFinding(
                    id="TLS-001",
                    severity="HIGH",
                    category="tls",
                    title="TLS certificate failed trust verification",
                    evidence=tls.verification_error or "Certificate chain validation failed",
                    remediation=(
                        "Install a valid certificate chain issued by a trusted CA "
                        "matching the hostname."
                    ),
                    cwe="CWE-295",
                    asvs="V9.2.1",
                )
            )
        if tls.days_remaining is not None:
            if tls.days_remaining < 0:
                findings.append(
                    AssessmentFinding(
                        id="TLS-002",
                        severity="CRITICAL",
                        category="tls",
                        title="TLS certificate has expired",
                        evidence=f"Expired on {tls.not_after} ({tls.days_remaining} days)",
                        remediation="Renew and deploy a valid TLS certificate immediately.",
                        cwe="CWE-298",
                        asvs="V9.2.1",
                    )
                )
            elif tls.days_remaining <= 30:
                findings.append(
                    AssessmentFinding(
                        id="TLS-003",
                        severity="MEDIUM",
                        category="tls",
                        title="TLS certificate expires within 30 days",
                        evidence=f"Expires on {tls.not_after} ({tls.days_remaining} days left)",
                        remediation="Renew the TLS certificate and verify automated renewal.",
                        cwe="CWE-298",
                        asvs="V9.2.1",
                    )
                )
        observed_versions = list(tls.supported_versions)
        if tls.negotiated_version and tls.negotiated_version not in observed_versions:
            observed_versions.append(tls.negotiated_version)
        deprecated = [v for v in observed_versions if v in _DEPRECATED_TLS]
        if deprecated:
            findings.append(
                AssessmentFinding(
                    id="TLS-004",
                    severity="HIGH",
                    category="tls",
                    title="Deprecated TLS protocol versions supported",
                    evidence=f"Supported TLS versions include: {', '.join(deprecated)}",
                    remediation="Disable TLS 1.0 and TLS 1.1; allow only TLS 1.2 and TLS 1.3.",
                    cwe="CWE-327",
                    asvs="V9.1.2",
                )
            )
        if tls.cipher_weaknesses:
            severe = any(
                tok in w.upper()
                for w in tls.cipher_weaknesses
                for tok in ("NULL", "EXPORT", "ANONYMOUS", "RC4", "3DES", "DES", "MD5")
            )
            findings.append(
                AssessmentFinding(
                    id="TLS-005",
                    severity="HIGH" if severe else "MEDIUM",
                    category="tls",
                    title="Weak negotiated TLS cipher suite",
                    evidence=f"{tls.cipher_suite}: {'; '.join(tls.cipher_weaknesses)}",
                    remediation=(
                        "Configure AEAD cipher suites with Forward Secrecy "
                        "(TLS 1.3 or ECDHE+AES-GCM/ChaCha20-Poly1305)."
                    ),
                    cwe="CWE-327",
                    asvs="V9.1.3",
                )
            )
        if tls.key_type == "RSA" and tls.key_size is not None and tls.key_size < 2048:
            findings.append(
                AssessmentFinding(
                    id="TLS-006",
                    severity="HIGH",
                    category="tls",
                    title="Weak RSA certificate key length",
                    evidence=f"Certificate uses RSA {tls.key_size}-bit key (< 2048 bits)",
                    remediation="Re-issue the certificate with RSA >= 2048-bit or ECDSA P-256/P-384.",
                    cwe="CWE-326",
                    asvs="V9.1.3",
                )
            )
        if tls.signature_algorithm and tls.signature_algorithm.lower() in _WEAK_SIG_HASHES:
            findings.append(
                AssessmentFinding(
                    id="TLS-007",
                    severity="HIGH",
                    category="tls",
                    title="Certificate signed with deprecated hash algorithm",
                    evidence=f"Signature hash algorithm: {tls.signature_algorithm}",
                    remediation="Re-issue the certificate signed with SHA-256 or stronger.",
                    cwe="CWE-328",
                    asvs="V9.1.3",
                )
            )
        if tls.cert_validity_days is not None and tls.cert_validity_days > 398:
            findings.append(
                AssessmentFinding(
                    id="TLS-008",
                    severity="LOW",
                    category="tls",
                    title="TLS certificate validity exceeds 398-day industry limit",
                    evidence=f"Certificate lifetime is {tls.cert_validity_days} days",
                    remediation="Issue shorter-lived certificates (<= 90–398 days) with ACME automation.",
                    cwe="CWE-298",
                    asvs="V9.2.1",
                )
            )
        if tls.supported_versions and "TLSv1.3" not in tls.supported_versions and tls.negotiated_version != "TLSv1.3":
            findings.append(
                AssessmentFinding(
                    id="TLS-009",
                    severity="INFO",
                    category="tls",
                    title="TLS 1.3 not negotiated or advertised",
                    evidence=f"Observed versions: {', '.join(tls.supported_versions)}",
                    remediation="Enable TLS 1.3 alongside TLS 1.2 for improved security and latency.",
                    cwe="CWE-327",
                    asvs="V9.1.2",
                )
            )
        if tls.client_blocked_versions:
            findings.append(
                AssessmentFinding(
                    id="TLS-010",
                    severity="INFO",
                    category="tls",
                    title="Local OpenSSL policy prevented probing legacy TLS version(s)",
                    evidence=f"Client-blocked probes: {', '.join(tls.client_blocked_versions)}",
                    remediation=(
                        "Verify TLS 1.0/1.1 disablement in server config or with an OpenSSL "
                        "build permitting legacy ClientHello probes."
                    ),
                    cwe="CWE-327",
                    asvs="V9.1.2",
                )
            )

    # 3. Security headers & directive-level CSP
    has_frame_ancestors = "frame-ancestors" in profile.headers.csp_directives
    for hdr in profile.headers.security_headers:
        if hdr.header == "Strict-Transport-Security" and not is_https:
            continue
        meta = _HEADER_META.get(hdr.header)
        if meta is None:
            continue
        base_id, base_sev, remediation, cwe, asvs = meta

        # Modern CSP frame-ancestors supersedes X-Frame-Options clickjacking defense.
        if hdr.header == "X-Frame-Options" and hdr.status == "missing" and has_frame_ancestors:
            findings.append(
                AssessmentFinding(
                    id="HDR-XFO-CSP",
                    severity="INFO",
                    category="headers",
                    title="X-Frame-Options absent (covered by CSP frame-ancestors)",
                    evidence=hdr.note,
                    remediation="Optionally add `X-Frame-Options` for legacy browser compatibility.",
                    cwe=cwe,
                    asvs=asvs,
                )
            )
            continue

        if hdr.header == "Content-Security-Policy" and hdr.status == "weak" and hdr.value:
            low_note = hdr.note.lower()
            if "'unsafe-inline'" in low_note or "'unsafe-eval'" in low_note:
                findings.append(
                    AssessmentFinding(
                        id="HDR-CSP-UNSAFE",
                        severity="MEDIUM",
                        category="headers",
                        title="Content-Security-Policy allows unsafe script/style directives",
                        evidence=hdr.note,
                        remediation=(
                            "Remove `'unsafe-inline'` and `'unsafe-eval'`; use nonces or hashes."
                        ),
                        cwe="CWE-693",
                        asvs="V14.4.3",
                    )
                )
            else:
                findings.append(
                    AssessmentFinding(
                        id="HDR-CSP-WEAK",
                        severity="LOW",
                        category="headers",
                        title="Content-Security-Policy uses permissive directives",
                        evidence=hdr.note,
                        remediation=remediation,
                        cwe="CWE-693",
                        asvs="V14.4.3",
                    )
                )
            continue

        if hdr.status == "missing":
            findings.append(
                AssessmentFinding(
                    id=base_id,
                    severity=base_sev,
                    category="headers",
                    title=f"Missing {hdr.header} header",
                    evidence=hdr.note,
                    remediation=remediation,
                    cwe=cwe,
                    asvs=asvs,
                )
            )
        elif hdr.status == "weak":
            findings.append(
                AssessmentFinding(
                    id=f"{base_id}-WEAK",
                    severity="LOW",
                    category="headers",
                    title=f"Weak {hdr.header} configuration",
                    evidence=f"{hdr.value or ''} ({hdr.note})".strip(),
                    remediation=remediation,
                    cwe=cwe,
                    asvs=asvs,
                )
            )

    if profile.headers.csp_report_only and not profile.headers.csp_directives:
        findings.append(
            AssessmentFinding(
                id="HDR-CSP-RO",
                severity="INFO",
                category="headers",
                title="Content-Security-Policy is configured in Report-Only mode",
                evidence=f"Content-Security-Policy-Report-Only: {profile.headers.csp_report_only[:120]}",
                remediation="Review CSP violation reports and transition to enforced `Content-Security-Policy`.",
                cwe="CWE-693",
                asvs="V14.4.3",
            )
        )

    # 4. CORS posture across all raw headers (handles duplicate headers consistently)
    acao_vals = [
        v.strip()
        for k, v in profile.raw_headers
        if k.lower() == "access-control-allow-origin" and v.strip()
    ]
    acac_vals = [
        v.strip().lower()
        for k, v in profile.raw_headers
        if k.lower() == "access-control-allow-credentials" and v.strip()
    ]
    vary_vals = [
        v.strip().lower() for k, v in profile.raw_headers if k.lower() == "vary" and v.strip()
    ]
    has_creds = "true" in acac_vals
    if "*" in acao_vals and has_creds:
        findings.append(
            AssessmentFinding(
                id="CORS-001",
                severity="HIGH",
                category="cors",
                title="Permissive wildcard CORS combined with credentials",
                evidence=(
                    "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true"
                ),
                remediation=(
                    "Restrict Access-Control-Allow-Origin to an explicit allowlist "
                    "of trusted origins."
                ),
                cwe="CWE-942",
                asvs="V14.5.3",
            )
        )
    elif "*" in acao_vals:
        findings.append(
            AssessmentFinding(
                id="CORS-002",
                severity="LOW",
                category="cors",
                title="Wildcard CORS policy exposed",
                evidence="Access-Control-Allow-Origin: *",
                remediation=(
                    "Verify whether public cross-origin reads are intentional; "
                    "restrict origins if sensitive."
                ),
                cwe="CWE-942",
                asvs="V14.5.3",
            )
        )
    if any(v.lower() == "null" for v in acao_vals):
        findings.append(
            AssessmentFinding(
                id="CORS-003",
                severity="HIGH",
                category="cors",
                title="CORS trusts 'null' origin",
                evidence="Access-Control-Allow-Origin: null",
                remediation="Remove 'null' from trusted CORS origins to prevent sandboxed-iframe bypasses.",
                cwe="CWE-942",
                asvs="V14.5.3",
            )
        )
    specific_acao = [v for v in acao_vals if v != "*" and v.lower() != "null"]
    if specific_acao and not any("origin" in v for v in vary_vals):
        findings.append(
            AssessmentFinding(
                id="CORS-004",
                severity="INFO",
                category="cors",
                title="Origin-specific CORS response missing `Vary: Origin`",
                evidence=f"ACAO={specific_acao[0]} without Vary: Origin",
                remediation="Add `Vary: Origin` to prevent shared cache poisoning across origins.",
                cwe="CWE-524",
                asvs="V14.5.3",
            )
        )

    # 5. Cookie security attributes (differentiating session-like vs non-session cookies)
    for cookie in profile.headers.cookies:
        if not cookie.secure:
            findings.append(
                AssessmentFinding(
                    id=f"COOKIE-SEC-{cookie.name}",
                    severity="MEDIUM" if (cookie.is_session_like or is_https) else "LOW",
                    category="cookies",
                    title=f"Cookie '{cookie.name}' missing Secure flag",
                    evidence=f"Set-Cookie `{cookie.name}` has secure=False",
                    remediation="Add the `Secure` attribute so cookies are only sent over HTTPS.",
                    cwe="CWE-614",
                    asvs="V3.4.1",
                )
            )
        if not cookie.http_only:
            findings.append(
                AssessmentFinding(
                    id=f"COOKIE-HTTPONLY-{cookie.name}",
                    severity="LOW" if cookie.is_session_like else "INFO",
                    category="cookies",
                    title=f"Cookie '{cookie.name}' missing HttpOnly flag",
                    evidence=f"Set-Cookie `{cookie.name}` has http_only=False",
                    remediation=(
                        "Add `HttpOnly` to prevent client-side script access to session cookies."
                    ),
                    cwe="CWE-1004",
                    asvs="V3.4.2",
                )
            )
        if not cookie.same_site:
            findings.append(
                AssessmentFinding(
                    id=f"COOKIE-SAMESITE-{cookie.name}",
                    severity="LOW" if cookie.is_session_like else "INFO",
                    category="cookies",
                    title=f"Cookie '{cookie.name}' missing SameSite attribute",
                    evidence=f"Set-Cookie `{cookie.name}` has same_site=None/unset",
                    remediation="Set `SameSite=Lax` or `SameSite=Strict` to reduce CSRF exposure.",
                    cwe="CWE-1275",
                    asvs="V3.4.3",
                )
            )
        if cookie.prefix_issues:
            findings.append(
                AssessmentFinding(
                    id=f"COOKIE-PREFIX-{cookie.name}",
                    severity="MEDIUM",
                    category="cookies",
                    title=f"Cookie '{cookie.name}' violates prefix or SameSite=None security rules",
                    evidence="; ".join(cookie.prefix_issues),
                    remediation=(
                        "Enforce `Secure` on `SameSite=None`/`__Secure-` cookies and "
                        "`Secure; Path=/` (no `Domain`) on `__Host-` cookies."
                    ),
                    cwe="CWE-614",
                    asvs="V3.4.4",
                )
            )

    # 6. Banner disclosures
    for banner in profile.headers.banner_disclosures:
        has_version = any(ch.isdigit() for ch in banner.value)
        if has_version:
            findings.append(
                AssessmentFinding(
                    id=f"DISC-VER-{banner.header.upper()}",
                    severity="LOW",
                    category="disclosure",
                    title=f"Software version disclosed in '{banner.header}' header",
                    evidence=f"{banner.header}: {banner.value}",
                    remediation=(
                        f"Suppress or minimize version details in `{banner.header}` responses."
                    ),
                    cwe="CWE-200",
                    asvs="V14.3.3",
                )
            )
        else:
            findings.append(
                AssessmentFinding(
                    id=f"DISC-BANNER-{banner.header.upper()}",
                    severity="INFO",
                    category="disclosure",
                    title=f"Technology banner exposed in '{banner.header}' header",
                    evidence=f"{banner.header}: {banner.value}",
                    remediation=(
                        f"Optionally strip `{banner.header}` header at the edge/reverse proxy."
                    ),
                    cwe="CWE-200",
                    asvs="V14.3.3",
                )
            )

    # 7. Passive DNS security hygiene (when enabled)
    dns = profile.dns
    if dns.security_checked:
        if dns.dangling_cnames:
            findings.append(
                AssessmentFinding(
                    id="DNS-001",
                    severity="HIGH",
                    category="dns",
                    title="Potential dangling CNAME pointing to unclaimed cloud/SaaS host",
                    evidence=f"NXDOMAIN CNAME target(s): {', '.join(dns.dangling_cnames)}",
                    remediation=(
                        "Remove stale DNS CNAME records or reclaim the target cloud resource "
                        "to prevent subdomain takeover."
                    ),
                    cwe="CWE-350",
                    asvs="V14.2.1",
                )
            )
        if not dns.caa:
            findings.append(
                AssessmentFinding(
                    id="DNS-002",
                    severity="INFO",
                    category="dns",
                    title="No DNS CAA record found",
                    evidence="CAA query returned no records for target hostname",
                    remediation="Publish DNS `CAA` records restricting authorized Certificate Authorities.",
                    cwe="CWE-295",
                    asvs="V9.2.1",
                )
            )
        if dns.spf and "+all" in dns.spf.lower():
            findings.append(
                AssessmentFinding(
                    id="DNS-003",
                    severity="MEDIUM",
                    category="dns",
                    title="Permissive SPF policy uses `+all`",
                    evidence=f"SPF: {dns.spf[:140]}",
                    remediation="Replace `+all` with `-all` (hardfail) or `~all` (softfail) in SPF.",
                    cwe="CWE-290",
                    asvs="V14.1.1",
                )
            )
        if dns.dmarc is None:
            findings.append(
                AssessmentFinding(
                    id="DNS-004",
                    severity="INFO",
                    category="dns",
                    title="No DMARC record detected on hostname",
                    evidence="TXT lookup on `_dmarc.<host>` returned no `v=DMARC1` record",
                    remediation="Publish a DMARC policy (`p=quarantine` or `p=reject`) if domain sends/receives mail.",
                    cwe="CWE-290",
                    asvs="V14.1.1",
                )
            )
        elif "p=none" in dns.dmarc.lower():
            findings.append(
                AssessmentFinding(
                    id="DNS-004-NONE",
                    severity="LOW",
                    category="dns",
                    title="DMARC policy is monitor-only (`p=none`)",
                    evidence=f"DMARC: {dns.dmarc[:140]}",
                    remediation="Advance DMARC policy from `p=none` to `p=quarantine` or `p=reject`.",
                    cwe="CWE-290",
                    asvs="V14.1.1",
                )
            )
        if dns.dnssec_present is False:
            findings.append(
                AssessmentFinding(
                    id="DNS-005",
                    severity="INFO",
                    category="dns",
                    title="DNSSEC records (DS/DNSKEY) not detected",
                    evidence="Neither DS nor DNSKEY returned for hostname",
                    remediation="Consider enabling DNSSEC signing at your DNS registrar/provider.",
                    cwe="CWE-350",
                    asvs="V9.1.1",
                )
            )

    # 8. Passive HTML body hygiene (zero extra requests)
    html = profile.html
    if html is not None and html.analyzed:
        if html.mixed_content_urls:
            findings.append(
                AssessmentFinding(
                    id="HTML-001",
                    severity="MEDIUM",
                    category="html",
                    title="HTTPS page references plain HTTP mixed-content resources",
                    evidence=f"{len(html.mixed_content_urls)} URL(s), e.g. {html.mixed_content_urls[0]}",
                    remediation="Upgrade all embedded scripts, stylesheets, images, and iframes to HTTPS.",
                    cwe="CWE-319",
                    asvs="V9.1.1",
                )
            )
        sri_total = len(html.external_scripts_without_sri) + len(html.external_styles_without_sri)
        if sri_total > 0:
            sample = (
                html.external_scripts_without_sri[0]
                if html.external_scripts_without_sri
                else html.external_styles_without_sri[0]
            )
            findings.append(
                AssessmentFinding(
                    id="HTML-002",
                    severity="LOW",
                    category="html",
                    title="External scripts or stylesheets loaded without Subresource Integrity (SRI)",
                    evidence=f"{sri_total} third-party resource(s) lack `integrity`, e.g. {sample}",
                    remediation="Add `integrity=\"sha384-...\" crossorigin=\"anonymous\"` or self-host assets.",
                    cwe="CWE-353",
                    asvs="V14.2.3",
                )
            )
        if html.insecure_forms:
            findings.append(
                AssessmentFinding(
                    id="HTML-003",
                    severity="HIGH",
                    category="html",
                    title="HTML form submits credentials or data over unencrypted HTTP",
                    evidence="; ".join(html.insecure_forms[:3]),
                    remediation="Serve forms exclusively over HTTPS and use `https://` form actions.",
                    cwe="CWE-319",
                    asvs="V9.1.1",
                )
            )

    # 9. Opt-in well-known passive hygiene (`security.txt` & `robots.txt`)
    wk = profile.well_known
    if wk is not None:
        if not wk.security_txt_present:
            findings.append(
                AssessmentFinding(
                    id="WK-001",
                    severity="INFO",
                    category="well_known",
                    title="No RFC 9116 `/.well-known/security.txt` published",
                    evidence=f"HTTP status={wk.security_txt_status}",
                    remediation="Publish `/.well-known/security.txt` with `Contact:` and `Expires:` fields.",
                    cwe="CWE-1059",
                    asvs="V1.1.1",
                )
            )
        elif wk.security_txt_expired:
            findings.append(
                AssessmentFinding(
                    id="WK-002",
                    severity="LOW",
                    category="well_known",
                    title="Published `/.well-known/security.txt` has expired",
                    evidence=f"Expires: {wk.security_txt_expires}",
                    remediation="Refresh `Expires:` date and verify disclosure contacts in `security.txt`.",
                    cwe="CWE-1059",
                    asvs="V1.1.1",
                )
            )
        if wk.robots_sensitive_hints:
            findings.append(
                AssessmentFinding(
                    id="WK-003",
                    severity="INFO",
                    category="well_known",
                    title="`/robots.txt` lists potentially sensitive administrative/internal paths",
                    evidence=f"Paths: {', '.join(wk.robots_sensitive_hints[:5])}",
                    remediation=(
                        "Do not rely on `robots.txt` for access control; protect sensitive routes "
                        "with authentication and remove sensitive path names from `robots.txt`."
                    ),
                    cwe="CWE-200",
                    asvs="V14.3.3",
                )
            )

    # 10. CVE correlation (KEV-prioritized!)
    if cve is not None and cve.records:
        kev_records = [r for r in cve.records if r.in_kev]
        if kev_records:
            kev_ids = ", ".join(r.cve_id for r in kev_records[:5])
            findings.append(
                AssessmentFinding(
                    id="CVE-KEV",
                    severity="CRITICAL",
                    category="cve",
                    title=f"Correlated {len(kev_records)} CISA Known Exploited Vulnerability (KEV) CVE(s)",
                    evidence=f"KEV IDs: {kev_ids}",
                    remediation=(
                        "Prioritize immediate patching/mitigation — these CVEs have confirmed "
                        "active exploitation in the wild (CISA KEV)."
                    ),
                    cwe="CWE-1395",
                    asvs="V14.2.1",
                )
            )

        has_versioned = any(m.version is not None for m in fingerprint.matches)
        top_ids = ", ".join(r.cve_id for r in cve.records[:5])
        if has_versioned:
            findings.append(
                AssessmentFinding(
                    id="CVE-VER",
                    severity="HIGH",
                    category="cve",
                    title=(
                        f"Correlated {len(cve.records)} CVE(s) for fingerprinted product version"
                    ),
                    evidence=f"Top CVEs: {top_ids}",
                    remediation=(
                        "Review correlated CVEs against installed package patch levels and upgrade."
                    ),
                    cwe="CWE-1395",
                    asvs="V14.2.1",
                )
            )
        else:
            findings.append(
                AssessmentFinding(
                    id="CVE-UNVER",
                    severity="INFO",
                    category="cve",
                    title=(
                        f"Matched {len(cve.records)} unversioned keyword CVE(s) "
                        "from stack fingerprint"
                    ),
                    evidence=f"Product version not disclosed; top keyword matches: {top_ids}",
                    remediation=(
                        "Confirm exact installed server/package version internally before triaging."
                    ),
                    cwe="CWE-1395",
                    asvs="V14.2.1",
                )
            )

    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f.severity, 99), f.id))

    counts = {sev: 0 for sev in _SEVERITY_ORDER}
    raw_domain_penalties: dict[str, int] = {dom: 0 for dom in _DOMAIN_PENALTY_CAPS}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        dom = _DOMAIN_MAP.get(f.category, "headers")
        raw_domain_penalties[dom] = raw_domain_penalties.get(dom, 0) + _SEVERITY_PENALTIES.get(
            f.severity, 0
        )

    total_penalty = 0
    category_scores: dict[str, int] = {}
    for dom, cap in _DOMAIN_PENALTY_CAPS.items():
        capped = min(raw_domain_penalties.get(dom, 0), cap)
        total_penalty += capped
        category_scores[dom] = max(0, round(100 * (1.0 - (capped / cap)))) if cap > 0 else 100

    score = max(0, min(100, 100 - total_penalty))
    posture = PostureScore(
        score=score,
        grade=_compute_grade(score, counts),
        risk_level=_compute_risk_level(score, counts),
        counts=counts,
        category_scores=category_scores,
    )
    return posture, findings
