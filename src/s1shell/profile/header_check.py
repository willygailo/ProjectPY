"""HTTP security header, directive-level CSP, CORS, cache, banner, and cookie analysis."""

from __future__ import annotations

import re

from s1shell.profile.models import (
    BannerDisclosure,
    CookieFinding,
    HeaderAnalysis,
    HeaderFinding,
)

_BANNER_HEADERS = (
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "Via",
    "X-Runtime",
    "X-Version",
    "X-Backend-Server",
    "X-Upstream",
    "Server-Timing",
)

_DEBUG_HEADERS = (
    "X-Debug-Token",
    "X-Debug-Token-Link",
    "X-Symfony-Cache",
    "X-Laravel-Debug",
    "X-Clockwork-Id",
    "X-Drupal-Cache-Tags",
)

_CSP_JSONP_CDN_HOSTS = (
    "ajax.googleapis.com",
    "cdnjs.cloudflare.com",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "raw.githubusercontent.com",
)

_MAX_AGE_RE = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)
_H3_ALT_SVC_RE = re.compile(r"\bh3(?:-\d+)?\s*=", re.IGNORECASE)
_NONCE_OR_HASH_RE = re.compile(r"^'(?:nonce-[^']+|sha(?:256|384|512)-[^']+)'$", re.IGNORECASE)
_SESSION_COOKIE_RE = re.compile(
    r"(?:^|[_-])(?:sess(?:ion)?|sid|ssid|phpsessid|jsessionid|auth|token|jwt|csrf|xsrf|login|account)(?:$|[_-])"
    r"|^(?:phpsessid|jsessionid|asp\.net_sessionid|connect\.sid|laravel_session|sessionid|csrftoken|__host-.*|__secure-.*)$",
    re.IGNORECASE,
)


def detect_http3_from_alt_svc(alt_svc: str | None) -> bool:
    """Return True if an Alt-Svc header advertises HTTP/3 support."""
    if not alt_svc:
        return False
    return bool(_H3_ALT_SVC_RE.search(alt_svc))


def parse_csp_directives(value: str) -> dict[str, list[str]]:
    """Parse a Content-Security-Policy string into normalized `{directive: [sources]}`."""
    directives: dict[str, list[str]] = {}
    for raw_part in value.split(";"):
        part = raw_part.strip()
        if not part:
            continue
        tokens = part.split()
        name = tokens[0].lower()
        if name not in directives:
            directives[name] = tokens[1:]
    return directives


def _parse_set_cookie(raw_cookie: str) -> CookieFinding | None:
    parts = [p.strip() for p in raw_cookie.split(";") if p.strip()]
    if not parts or "=" not in parts[0]:
        return None
    name = parts[0].split("=", 1)[0].strip()
    secure = False
    http_only = False
    same_site: str | None = None
    path: str | None = None
    domain: str | None = None
    max_age: int | None = None

    for attr in parts[1:]:
        low = attr.lower()
        if low == "secure":
            secure = True
        elif low == "httponly":
            http_only = True
        elif low.startswith("samesite="):
            same_site = attr.split("=", 1)[1].strip()
        elif low.startswith("path="):
            path = attr.split("=", 1)[1].strip()
        elif low.startswith("domain="):
            domain = attr.split("=", 1)[1].strip()
        elif low.startswith("max-age="):
            raw_age = attr.split("=", 1)[1].strip()
            try:
                max_age = int(raw_age)
            except ValueError:
                max_age = None

    prefix_issues: list[str] = []
    if name.startswith("__Host-"):
        if not secure:
            prefix_issues.append("__Host- cookie missing Secure")
        if path != "/":
            prefix_issues.append("__Host- cookie requires Path=/")
        if domain is not None:
            prefix_issues.append("__Host- cookie must not set Domain")
    elif name.startswith("__Secure-") and not secure:
        prefix_issues.append("__Secure- cookie missing Secure")

    if same_site and same_site.lower() == "none" and not secure:
        prefix_issues.append("SameSite=None requires Secure attribute")

    is_session_like = bool(_SESSION_COOKIE_RE.search(name))
    return CookieFinding(
        name=name,
        secure=secure,
        http_only=http_only,
        same_site=same_site,
        path=path,
        domain=domain,
        max_age=max_age,
        is_session_like=is_session_like,
        prefix_issues=prefix_issues,
    )


def _evaluate_hsts(value: str | None, *, is_https: bool) -> HeaderFinding:
    if not is_https:
        return HeaderFinding(
            header="Strict-Transport-Security",
            present=value is not None,
            value=value,
            status="ok" if value else "missing",
            note="Plain HTTP response; HSTS applies only over HTTPS.",
        )
    if value is None:
        return HeaderFinding(
            header="Strict-Transport-Security",
            present=False,
            value=None,
            status="missing",
            note="Missing HSTS header on HTTPS response.",
        )
    match = _MAX_AGE_RE.search(value)
    max_age = int(match.group(1)) if match else 0
    low = value.lower()
    has_subdomains = "includesubdomains" in low
    has_preload = "preload" in low

    if max_age == 0:
        return HeaderFinding(
            header="Strict-Transport-Security",
            present=True,
            value=value,
            status="weak",
            note="HSTS max-age=0 explicitly disables HSTS protection.",
        )
    if max_age < 15_552_000:
        return HeaderFinding(
            header="Strict-Transport-Security",
            present=True,
            value=value,
            status="weak",
            note=f"HSTS max-age ({max_age}s) is below recommended 15552000s (180 days).",
        )
    if has_preload and (max_age < 31_536_000 or not has_subdomains):
        return HeaderFinding(
            header="Strict-Transport-Security",
            present=True,
            value=value,
            status="weak",
            note="HSTS preload requires max-age>=31536000 and includeSubDomains.",
        )
    return HeaderFinding(
        header="Strict-Transport-Security",
        present=True,
        value=value,
        status="ok",
        note="HSTS configured.",
    )


def _has_modern_script_controls(tokens: list[str]) -> bool:
    low_tokens = [t.lower() for t in tokens]
    return "'strict-dynamic'" in low_tokens or any(_NONCE_OR_HASH_RE.match(t) for t in low_tokens)


def _evaluate_csp(
    value: str | None,
) -> tuple[HeaderFinding, dict[str, list[str]]]:
    if value is None:
        return (
            HeaderFinding(
                header="Content-Security-Policy",
                present=False,
                value=None,
                status="missing",
                note="Missing Content-Security-Policy header.",
            ),
            {},
        )
    directives = parse_csp_directives(value)
    weak_reasons: list[str] = []

    script_sources = directives.get("script-src", directives.get("default-src", []))
    script_low = [t.lower() for t in script_sources]
    modern_controls = _has_modern_script_controls(script_sources)

    if "'unsafe-inline'" in script_low and not modern_controls:
        weak_reasons.append("'unsafe-inline'")
    if "'unsafe-eval'" in script_low:
        weak_reasons.append("'unsafe-eval'")
    if "*" in script_low:
        weak_reasons.append("wildcard '*'")
    if "data:" in script_low:
        weak_reasons.append("script-src allows data:")
    if "http:" in script_low:
        weak_reasons.append("script-src allows http:")

    if not modern_controls:
        broad_cdns = [cdn for cdn in _CSP_JSONP_CDN_HOSTS if any(cdn in src for src in script_low)]
        if broad_cdns:
            weak_reasons.append(f"broad script CDN allowlist ({', '.join(broad_cdns[:2])})")

    default_low = [t.lower() for t in directives.get("default-src", [])]
    if "*" in default_low and "wildcard '*'" not in weak_reasons:
        weak_reasons.append("wildcard '*'")

    obj_sources = directives.get("object-src", directives.get("default-src", []))
    obj_low = [t.lower() for t in obj_sources]
    if (
        obj_sources
        and "'none'" not in obj_low
        and "object-src" not in directives
        and "*" in obj_low
    ):
        weak_reasons.append("unrestricted object-src")

    if weak_reasons:
        return (
            HeaderFinding(
                header="Content-Security-Policy",
                present=True,
                value=value,
                status="weak",
                note=f"CSP allows permissive directives ({', '.join(weak_reasons)}).",
            ),
            directives,
        )

    note_parts = ["CSP present."]
    if "base-uri" not in directives:
        note_parts.append("Consider adding `base-uri 'self'` or `'none'`.")
    if "object-src" not in directives and "'none'" not in default_low:
        note_parts.append("Consider setting `object-src 'none'`.")
    return (
        HeaderFinding(
            header="Content-Security-Policy",
            present=True,
            value=value,
            status="ok",
            note=" ".join(note_parts),
        ),
        directives,
    )


def _evaluate_cors(header_multi: dict[str, list[str]]) -> list[str]:
    issues: list[str] = []
    acaos = [v.strip() for v in header_multi.get("access-control-allow-origin", []) if v.strip()]
    acacs = [
        v.strip().lower()
        for v in header_multi.get("access-control-allow-credentials", [])
        if v.strip()
    ]
    varies = [v.strip().lower() for v in header_multi.get("vary", []) if v.strip()]

    has_creds = "true" in acacs
    if "*" in acaos and has_creds:
        issues.append("Access-Control-Allow-Origin: * combined with credentials=true")
    elif "*" in acaos:
        issues.append("Wildcard Access-Control-Allow-Origin: *")

    if any(v.lower() == "null" for v in acaos):
        issues.append("Access-Control-Allow-Origin: null (sandboxed iframe bypass risk)")

    specific_origins = [v for v in acaos if v != "*" and v.lower() != "null"]
    if specific_origins and not any("origin" in v for v in varies):
        issues.append("Specific Access-Control-Allow-Origin served without `Vary: Origin`")

    return issues


def _evaluate_cache(
    header_map: dict[str, str],
    cookies: list[CookieFinding],
) -> tuple[str | None, list[str]]:
    cc = header_map.get("cache-control")
    cc_low = (cc or "").lower()
    has_sensitive_state = any(c.is_session_like for c in cookies) or (
        "www-authenticate" in header_map
    )
    issues: list[str] = []
    if has_sensitive_state:
        if not cc:
            issues.append(
                "Response sets session/auth headers without `Cache-Control: no-store` or `private`."
            )
        elif "public" in cc_low:
            issues.append(
                "Response sets session/auth headers with `Cache-Control: public` "
                "(shared cache leakage risk)."
            )
        elif "no-store" not in cc_low and "private" not in cc_low:
            issues.append(
                "Response sets session/auth headers without `no-store` or `private` in "
                "`Cache-Control`."
            )
    return cc, issues


def analyze_headers(headers: list[tuple[str, str]], *, is_https: bool) -> HeaderAnalysis:
    """Evaluate defensive headers, CSP directives, CORS, cache, banners, debug, and cookies."""
    header_map: dict[str, str] = {}
    header_multi: dict[str, list[str]] = {}
    cookies: list[CookieFinding] = []
    for name, val in headers:
        low = name.lower()
        if low == "set-cookie":
            parsed_cookie = _parse_set_cookie(val)
            if parsed_cookie is not None:
                cookies.append(parsed_cookie)
        else:
            header_multi.setdefault(low, []).append(val)
            if low not in header_map:
                header_map[low] = val

    csp_finding, csp_directives = _evaluate_csp(header_map.get("content-security-policy"))
    csp_report_only = header_map.get("content-security-policy-report-only")

    findings: list[HeaderFinding] = [
        _evaluate_hsts(header_map.get("strict-transport-security"), is_https=is_https),
        csp_finding,
    ]

    xfo = header_map.get("x-frame-options")
    xfo_valid = xfo is not None and xfo.strip().upper() in {"DENY", "SAMEORIGIN"}
    has_frame_ancestors = "frame-ancestors" in csp_directives
    findings.append(
        HeaderFinding(
            header="X-Frame-Options",
            present=xfo is not None,
            value=xfo,
            status="ok" if xfo_valid else ("weak" if xfo else "missing"),
            note=(
                "Valid X-Frame-Options."
                if xfo_valid
                else (
                    "Missing X-Frame-Options (mitigated by CSP frame-ancestors)."
                    if (xfo is None and has_frame_ancestors)
                    else "Missing or non-standard X-Frame-Options."
                )
            ),
        )
    )

    xcto = header_map.get("x-content-type-options")
    xcto_ok = xcto is not None and xcto.strip().lower() == "nosniff"
    findings.append(
        HeaderFinding(
            header="X-Content-Type-Options",
            present=xcto is not None,
            value=xcto,
            status="ok" if xcto_ok else ("weak" if xcto else "missing"),
            note="nosniff enforced." if xcto_ok else "Expected 'nosniff'.",
        )
    )

    ref_pol = header_map.get("referrer-policy")
    ref_weak = ref_pol is not None and "unsafe-url" in ref_pol.lower()
    findings.append(
        HeaderFinding(
            header="Referrer-Policy",
            present=ref_pol is not None,
            value=ref_pol,
            status="weak" if ref_weak else ("ok" if ref_pol else "missing"),
            note=(
                "Referrer-Policy uses 'unsafe-url' which leaks full URLs."
                if ref_weak
                else ("Referrer-Policy present." if ref_pol else "Missing Referrer-Policy header.")
            ),
        )
    )

    perm_pol = header_map.get("permissions-policy")
    findings.append(
        HeaderFinding(
            header="Permissions-Policy",
            present=perm_pol is not None,
            value=perm_pol,
            status="ok" if perm_pol else "missing",
            note=(
                "Permissions-Policy present." if perm_pol else "Missing Permissions-Policy header."
            ),
        )
    )

    coop = header_map.get("cross-origin-opener-policy")
    coop_ok = coop is not None and coop.strip().lower() in {
        "same-origin",
        "same-origin-allow-popups",
    }
    findings.append(
        HeaderFinding(
            header="Cross-Origin-Opener-Policy",
            present=coop is not None,
            value=coop,
            status="ok" if coop_ok else ("weak" if coop else "missing"),
            note=(
                "COOP configured."
                if coop_ok
                else (
                    "Non-standard Cross-Origin-Opener-Policy value."
                    if coop
                    else "Missing Cross-Origin-Opener-Policy header."
                )
            ),
        )
    )

    corp = header_map.get("cross-origin-resource-policy")
    corp_ok = corp is not None and corp.strip().lower() in {
        "same-origin",
        "same-site",
        "cross-origin",
    }
    findings.append(
        HeaderFinding(
            header="Cross-Origin-Resource-Policy",
            present=corp is not None,
            value=corp,
            status="ok" if corp_ok else ("weak" if corp else "missing"),
            note=(
                "CORP configured."
                if corp_ok
                else (
                    "Non-standard Cross-Origin-Resource-Policy value."
                    if corp
                    else "Missing Cross-Origin-Resource-Policy header."
                )
            ),
        )
    )

    coep = header_map.get("cross-origin-embedder-policy")
    coep_ok = coep is not None and coep.strip().lower() in {
        "require-corp",
        "credentialless",
    }
    findings.append(
        HeaderFinding(
            header="Cross-Origin-Embedder-Policy",
            present=coep is not None,
            value=coep,
            status="ok" if coep_ok else ("weak" if coep else "missing"),
            note=(
                "COEP configured."
                if coep_ok
                else (
                    "Non-standard Cross-Origin-Embedder-Policy value."
                    if coep
                    else "Missing Cross-Origin-Embedder-Policy header."
                )
            ),
        )
    )

    banners: list[BannerDisclosure] = []
    seen_banners: set[tuple[str, str]] = set()
    for banner_name in _BANNER_HEADERS:
        for raw_val in header_multi.get(banner_name.lower(), []):
            cleaned = raw_val.strip()
            if cleaned and (banner_name, cleaned) not in seen_banners:
                seen_banners.add((banner_name, cleaned))
                banners.append(BannerDisclosure(header=banner_name, value=cleaned))

    debug_hdrs: list[BannerDisclosure] = []
    seen_debug: set[tuple[str, str]] = set()
    for dbg_name in _DEBUG_HEADERS:
        for raw_val in header_multi.get(dbg_name.lower(), []):
            cleaned = raw_val.strip()
            if cleaned and (dbg_name, cleaned) not in seen_debug:
                seen_debug.add((dbg_name, cleaned))
                debug_hdrs.append(BannerDisclosure(header=dbg_name, value=cleaned))

    cache_control, cache_issues = _evaluate_cache(header_map, cookies)

    return HeaderAnalysis(
        security_headers=findings,
        banner_disclosures=banners,
        cookies=cookies,
        csp_directives=csp_directives,
        csp_report_only=csp_report_only,
        cors_issues=_evaluate_cors(header_multi),
        cache_control=cache_control,
        cache_issues=cache_issues,
        debug_headers=debug_hdrs,
    )
