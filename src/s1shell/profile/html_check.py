"""Zero-extra-packet passive HTML inspection for SRI, mixed content, forms, origins, and libs."""

from __future__ import annotations

import base64
import contextlib
import json
import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlsplit

from s1shell.profile.models import HTMLPassiveAnalysis

_MAX_PARSE_BYTES = 512 * 1024  # Cap HTML DOM parse at 512 KiB for speed & safety

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("gcp_api_key", re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b")),
    ("github_token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("stripe_live_key", re.compile(r"\b(sk_live_[0-9a-zA-Z]{16,})\b")),
    ("slack_token", re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,})\b")),
    (
        "slack_webhook",
        re.compile(
            r"(https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,})"
        ),
    ),
    (
        "discord_webhook",
        re.compile(
            r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{15,22}/[A-Za-z0-9_-]{50,})"
        ),
    ),
    ("telegram_bot_token", re.compile(r"\b(\d{8,10}:AA[0-9A-Za-z_-]{33})\b")),
    ("openai_api_key", re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,})\b")),
    ("twilio_account_sid", re.compile(r"\b(AC[a-f0-9]{32})\b")),
    ("sendgrid_api_key", re.compile(r"\b(SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{35,})\b")),
    ("mailgun_api_key", re.compile(r"\b(key-[0-9a-zA-Z]{32})\b")),
    ("private_key_pem", re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)")),
    (
        "db_credentials_uri",
        re.compile(
            r"\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^/\s:@]+:[^/\s@]+@[^\s\"'<>]+)"
        ),
    ),
)

_PUBLIC_ID_AND_KEY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("google_analytics_id", re.compile(r"\b(G-[A-Z0-9]{8,12}|UA-\d{4,10}-\d{1,4})\b")),
    ("google_tag_manager_id", re.compile(r"\b(GTM-[A-Z0-9]{6,10})\b")),
    ("google_ads_id", re.compile(r"\b(AW-\d{8,12})\b")),
    ("adsense_pub_id", re.compile(r"\b(ca-pub-\d{12,16}|pub-\d{15,16})\b")),
    ("firebase_app_id", re.compile(r"\b(1:\d{8,16}:web:[a-f0-9]{12,24})\b")),
    ("firebase_project_id", re.compile(r"projectId[\"']?\s*[:=]\s*[\"']([a-z0-9-]{6,36})[\"']")),
    (
        "meta_app_or_pixel_id",
        re.compile(
            r"(?:fbq\s*\(\s*['\"]init['\"]\s*,\s*['\"]|fb:app_id['\"]\s+content=['\"]|app_id[\"']?\s*[:=]\s*[\"'])(\d{10,20})"
        ),
    ),
    ("stripe_publishable_key", re.compile(r"\b(pk_(?:live|test)_[0-9a-zA-Z]{16,64})\b")),
    ("captcha_sitekey", re.compile(r"data-sitekey\s*=\s*[\"']([0-9A-Za-z_-]{20,64})[\"']")),
    (
        "oauth_client_id",
        re.compile(r"client_id(?:=|[\"']?\s*[:=]\s*[\"'])([0-9A-Za-z._-]{10,90})"),
    ),
    (
        "config_key_or_id",
        re.compile(
            r"\b(?:appId|apiKey|api_key|keyId|clientId|tenantId|orgId|merchantId|measurementId)"
            r"[\"']?\s*[:=]\s*[\"']([0-9A-Za-z._:-]{8,64})[\"']"
        ),
    ),
    (
        "sentry_dsn",
        re.compile(r"(https://[0-9a-f]{16,40}@(?:o\d+\.ingest\.[a-z.]*sentry\.io|sentry\.io)/\d+)"),
    ),
    (
        "mapbox_public_token",
        re.compile(r"\b(pk\.eyJ[A-Za-z0-9_-]{20,120}\.[A-Za-z0-9_-]{10,80})\b"),
    ),
    (
        "supabase_project_url",
        re.compile(r"(https://[a-z0-9-]{12,36}\.supabase\.co)"),
    ),
)

_HIGH_INTEREST_PARAMS = frozenset(
    {
        "redirect",
        "redirect_uri",
        "redirect_url",
        "url",
        "next",
        "return",
        "returnurl",
        "return_url",
        "callback",
        "dest",
        "destination",
        "continue",
        "file",
        "filepath",
        "path",
        "template",
        "page",
        "include",
        "doc",
        "folder",
        "dir",
        "cmd",
        "exec",
        "command",
        "query",
        "search",
        "q",
        "id",
        "uid",
        "user",
        "user_id",
        "userid",
        "account",
        "role",
        "admin",
        "debug",
        "test",
        "token",
        "access_token",
        "api_key",
        "apikey",
        "key",
        "secret",
        "password",
        "passwd",
        "upload",
    }
)

_INTERNAL_IP_OR_HOST_RE = re.compile(
    r"\b("
    r"10\.(?:\d{1,3}\.){2}\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"localhost:\d{2,5}|"
    r"[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)+\.(?:internal|corp|local|lan|intranet)"
    r")\b"
)

_DEV_COMMENT_KEYWORDS = (
    "todo",
    "fixme",
    "bug",
    "hack",
    "staging",
    "internal",
    "admin",
    "debug",
    "password",
    "secret",
    "token",
    "api",
    "backup",
    "deprecated",
    "legacy",
    "temp",
)

_EMAIL_RE = re.compile(
    r"\b([a-zA-Z0-9._%+-]{1,64}@(?:gmail\.com|googlemail\.com|yahoo\.com|outlook\.com|"
    r"hotmail\.com|proton\.me|protonmail\.com|icloud\.com|"
    r"[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,12}))\b"
)
_EMAIL_FALSE_EXTS = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".ico",
    ".css",
    ".js",
    ".mjs",
    ".cjs",
    ".map",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
    ".mp4",
    ".mp3",
    ".pdf",
    ".zip",
)

_PHONE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"(?:(?<=\s)|(?<=[\"'(:>])|^)"
        r"(\+(?:63|1|44|61|65|60|62|66|81|82|84|86|852|886|91|971|49|33|34|39|31|41|46|47|48|52|55|7|27|64)"
        r"(?:[\s.-]?\(?\d{1,4}\)?){2,5})(?=$|[\s\"'<),.;])"
    ),
    re.compile(r"\b(09\d{2}[-\s]\d{3}[-\s]\d{4})\b"),
    re.compile(r"(\(\d{2,4}\)\s*\d{3,4}[-\s]\d{4})\b"),
)

_SOCIAL_HOST_PATTERNS = (
    "github.com/",
    "linkedin.com/",
    "facebook.com/",
    "fb.com/",
    "twitter.com/",
    "x.com/",
    "instagram.com/",
    "youtube.com/",
    "t.me/",
    "telegram.me/",
    "discord.gg/",
    "discord.com/invite/",
    "tiktok.com/",
)

_CLOUD_BUCKET_RE = re.compile(
    r"\b((?:https?://)?(?:"
    r"[a-z0-9.-]+\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com(?:/[^\s\"'<>?#]*)?|"
    r"storage\.googleapis\.com/[a-z0-9._-]+|"
    r"[a-z0-9-]+\.blob\.core\.windows\.net(?:/[^\s\"'<>?#]*)?|"
    r"[a-z0-9-]+\.firebaseio\.com|"
    r"[a-z0-9-]+\.supabase\.co|"
    r"[a-z0-9.-]+\.r2\.dev|"
    r"[a-z0-9.-]+\.digitaloceanspaces\.com"
    r"))",
    re.IGNORECASE,
)

_API_PATH_RE = re.compile(
    r"(?:(?<=[\"'\s(])|^)(/(?:api|v1|v2|v3|graphql|wp-json|swagger|openapi|rest|\.well-known)"
    r"(?:/[a-zA-Z0-9._-]+){0,5})(?=[\"'\s)?#<>]|$)"
)

_JWT_RE = re.compile(
    r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*)(?![A-Za-z0-9_-])"
)
_SOURCEMAP_RE = re.compile(r"//#\s*sourceMappingURL\s*=\s*([^\s'\"<>]+)", re.IGNORECASE)
_STACK_TRACE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("python_traceback", re.compile(r"Traceback \(most recent call last\):")),
    (
        "php_fatal_error",
        re.compile(r"<b>(?:Fatal error|Warning|Parse error)</b>:\s+.+?\s+in\s+<b>/"),
    ),
    (
        "django_debug",
        re.compile(r"You're seeing this error because you have <code>DEBUG = True</code>"),
    ),
    ("laravel_whoops", re.compile(r"Whoops! There was an error\.|Ignition\\Exceptions")),
    (
        "java_stack_trace",
        re.compile(
            r"\b(?:java\.lang\.\w+Exception|org\.springframework\.\w+Exception)\b.*\n\s+at\s+"
        ),
    ),
    ("aspnet_error", re.compile(r"Server Error in '/' Application\.")),
)


def _is_valid_email(candidate: str) -> bool:
    low = candidate.strip().lower().rstrip(".,;:")
    if not low or "@" not in low or len(low) > 120:
        return False
    if low.endswith(_EMAIL_FALSE_EXTS):
        return False
    local, domain = low.split("@", 1)
    if not local or not domain or "." not in domain:
        return False
    if re.fullmatch(r"\d+x", domain):
        return False
    tld = domain.rsplit(".", 1)[-1]
    return bool(tld.isalpha() and 2 <= len(tld) <= 12)


def _format_email_tag(email: str) -> str:
    clean = email.strip().rstrip(".,;:")
    low = clean.lower()
    if low.endswith(("@gmail.com", "@googlemail.com")):
        return f"{clean} [Gmail]"
    return clean


def _normalize_phone(raw: str) -> str | None:
    cleaned = " ".join(raw.strip().split())
    if cleaned.lower().startswith("tel:"):
        cleaned = cleaned[4:].strip()
    cleaned = cleaned.rstrip(".,;:")
    if re.match(r"^(?:19|20)\d{2}-\d{2}-\d{2}", cleaned):
        return None
    digits = re.sub(r"\D", "", cleaned)
    if len(digits) < 7 or len(digits) > 15:
        return None
    if len(set(digits)) <= 2:
        return None
    return cleaned[:40]


def _extract_jsonld_items(
    raw_scripts: list[str],
    *,
    identities: list[dict[str, str]],
    emails: list[str],
    phones: list[str],
    social_links: list[str],
) -> None:
    def _add_identity(kind: str, val: str) -> None:
        v = " ".join(val.strip().split())[:160]
        if not v:
            return
        entry = {"kind": kind, "value": v}
        if entry not in identities and len(identities) < 25:
            identities.append(entry)

    def _walk_ld(node: Any) -> None:
        if isinstance(node, list):
            for item in node[:20]:
                _walk_ld(item)
            return
        if not isinstance(node, dict):
            return
        if "@graph" in node and isinstance(node["@graph"], list):
            _walk_ld(node["@graph"])
        raw_type = node.get("@type")
        type_label = (
            str(raw_type[0])
            if isinstance(raw_type, list) and raw_type
            else str(raw_type or "Schema")
        ).strip()
        for key, label in (
            ("name", f"jsonld:{type_label}.name"),
            ("legalName", f"jsonld:{type_label}.legalName"),
            ("alternateName", f"jsonld:{type_label}.alternateName"),
            ("taxID", f"jsonld:{type_label}.taxID"),
            ("vatID", f"jsonld:{type_label}.vatID"),
            ("identifier", f"jsonld:{type_label}.id"),
        ):
            val = node.get(key)
            if isinstance(val, (str, int)) and str(val).strip():
                _add_identity(label, str(val))
        em_val = node.get("email")
        if isinstance(em_val, str) and _is_valid_email(em_val):
            formatted = _format_email_tag(em_val)
            if formatted not in emails and len(emails) < 25:
                emails.append(formatted)
        tel_val = node.get("telephone")
        if isinstance(tel_val, str):
            norm_tel = _normalize_phone(tel_val)
            if norm_tel and norm_tel not in phones and len(phones) < 20:
                phones.append(norm_tel)
        same_as = node.get("sameAs")
        same_list = same_as if isinstance(same_as, list) else ([same_as] if same_as else [])
        for link in same_list:
            if isinstance(link, str) and link.strip():
                l_clean = link.strip()[:200]
                if (
                    any(host in l_clean.lower() for host in _SOCIAL_HOST_PATTERNS)
                    and l_clean not in social_links
                    and len(social_links) < 25
                ):
                    social_links.append(l_clean)
        for sub_key in (
            "author",
            "publisher",
            "founder",
            "creator",
            "contactPoint",
            "organization",
        ):
            if sub_key in node:
                _walk_ld(node[sub_key])

    for raw in raw_scripts[:10]:
        with contextlib.suppress(Exception):
            parsed = json.loads(raw)
            _walk_ld(parsed)


def scan_passive_entities(
    text: str,
    *,
    parser: _PassiveHTMLParser,
    leaked_secrets: list[dict[str, str]],
) -> tuple[
    list[str],
    list[str],
    list[dict[str, str]],
    list[dict[str, str]],
    list[str],
    list[str],
    list[str],
    list[str],
]:
    """Passively extract emails (incl. Gmail), phones, keys/IDs, names, socials & endpoints."""
    emails: list[str] = list(parser.mailto_emails)
    phones: list[str] = list(parser.tel_numbers)
    identities: list[dict[str, str]] = list(parser.meta_identities)
    social_links: list[str] = list(parser.social_links)

    _extract_jsonld_items(
        parser.jsonld_blocks,
        identities=identities,
        emails=emails,
        phones=phones,
        social_links=social_links,
    )

    for m in _EMAIL_RE.finditer(text):
        cand = m.group(1)
        if _is_valid_email(cand):
            formatted = _format_email_tag(cand)
            if formatted not in emails and len(emails) < 25:
                emails.append(formatted)

    # Sort so [Gmail] addresses surface first while preserving discovery order within groups
    emails.sort(key=lambda e: 0 if "[Gmail]" in e else 1)

    for pat in _PHONE_PATTERNS:
        for m in pat.finditer(text):
            norm_p = _normalize_phone(m.group(1))
            if norm_p and norm_p not in phones and len(phones) < 20:
                phones.append(norm_p)

    exposed_ids_and_keys: list[dict[str, str]] = []
    seen_ids: set[tuple[str, str]] = set()
    for sec in leaked_secrets:
        s_type = sec.get("type", "secret")
        s_val = sec.get("redacted_preview", "***")
        s_loc = sec.get("location", "html")
        pair = (s_type, s_val)
        if pair not in seen_ids:
            seen_ids.add(pair)
            exposed_ids_and_keys.append({"type": s_type, "value": s_val, "location": s_loc})

    for kind, pat in _PUBLIC_ID_AND_KEY_PATTERNS:
        for m in pat.finditer(text):
            val = m.group(1).strip()[:96]
            pair = (kind, val)
            if val and pair not in seen_ids and len(exposed_ids_and_keys) < 30:
                seen_ids.add(pair)
                exposed_ids_and_keys.append({"type": kind, "value": val, "location": "html"})

    endpoints: list[str] = []
    for m in _CLOUD_BUCKET_RE.finditer(text):
        b_val = m.group(1).strip()[:160]
        if b_val and b_val not in endpoints and len(endpoints) < 25:
            endpoints.append(f"cloud:{b_val}")
    for m in _API_PATH_RE.finditer(text):
        p_val = m.group(1).strip()[:140]
        if p_val and p_val not in endpoints and len(endpoints) < 25:
            endpoints.append(p_val)

    internal_leaks: list[str] = list(parser.dev_comments)
    for m in _INTERNAL_IP_OR_HOST_RE.finditer(text):
        leak = f"internal:{m.group(1)}"
        if leak not in internal_leaks and len(internal_leaks) < 20:
            internal_leaks.append(leak)

    return (
        emails,
        phones,
        exposed_ids_and_keys,
        identities,
        social_links,
        endpoints,
        list(parser.form_endpoints),
        internal_leaks,
    )


def _redact_secret(raw: str) -> str:
    s = raw.strip()
    if "PRIVATE KEY" in s:
        return "-----BEGIN PRIVATE KEY----- [REDACTED]"
    if "://" in s and "@" in s:
        scheme, rest = s.split("://", 1)
        host_part = rest.rsplit("@", 1)[-1]
        return f"{scheme}://***:***@{host_part[:40]}"
    if len(s) <= 10:
        return "***"
    return f"{s[:4]}****{s[-4:]}"


def _decode_jwt_segment(seg: str) -> dict[str, Any] | None:
    padded = seg + "=" * ((4 - len(seg) % 4) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        obj = json.loads(raw.decode("utf-8"))
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def inspect_passive_jwt(token: str, *, location: str) -> dict[str, Any] | None:
    """Passively inspect JWT header & claims (zero cracking/tampering; never returns raw token)."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    hdr = _decode_jwt_segment(parts[0])
    payload = _decode_jwt_segment(parts[1])
    if hdr is None or payload is None:
        return None
    alg = str(hdr.get("alg") or "unknown")
    issues: list[str] = []
    if alg.lower() == "none" or not parts[2]:
        issues.append("JWT uses alg:none or unsigned empty signature")
    exp = payload.get("exp")
    iat = payload.get("iat")
    if exp is None:
        issues.append("JWT missing `exp` expiration claim")
    elif isinstance(exp, (int, float)):
        now_ts = datetime.now(timezone.utc).timestamp()
        if isinstance(iat, (int, float)) and (exp - iat) > 30 * 86400:
            issues.append(f"JWT lifetime exceeds 30 days ({int((exp - iat) // 86400)}d)")
        elif exp < now_ts:
            issues.append("JWT is already expired")
    sensitive_keys = [
        k for k in ("password", "secret", "ssn", "credit_card", "api_key") if k in payload
    ]
    if sensitive_keys:
        issues.append(f"JWT payload contains sensitive claim keys ({', '.join(sensitive_keys)})")
    return {
        "location": location,
        "alg": alg,
        "typ": str(hdr.get("typ") or "JWT"),
        "has_exp": exp is not None,
        "claim_keys": sorted(str(k) for k in payload)[:12],
        "issues": issues,
    }


def scan_passive_exposures(
    text: str,
    headers: list[tuple[str, str]],
) -> tuple[list[dict[str, str]], list[dict[str, Any]], list[str], list[str]]:
    """Zero-extra-packet passive scan for redacted secrets, JWTs, source maps, & stack traces."""
    leaked_secrets: list[dict[str, str]] = []
    seen_secrets: set[tuple[str, str]] = set()
    for kind, pat in _SECRET_PATTERNS:
        for m in pat.finditer(text):
            preview = _redact_secret(m.group(1))
            key = (kind, preview)
            if key not in seen_secrets and len(leaked_secrets) < 10:
                seen_secrets.add(key)
                leaked_secrets.append(
                    {"type": kind, "redacted_preview": preview, "location": "html"}
                )

    passive_jwts: list[dict[str, Any]] = []
    seen_jwts: set[str] = set()
    for m in _JWT_RE.finditer(text):
        tok = m.group(1)
        if tok not in seen_jwts and len(passive_jwts) < 8:
            seen_jwts.add(tok)
            info = inspect_passive_jwt(tok, location="html")
            if info is not None:
                passive_jwts.append(info)
    for h_name, h_val in headers:
        low_h = h_name.lower()
        if low_h in {"set-cookie", "location", "authorization"}:
            for m in _JWT_RE.finditer(h_val):
                tok = m.group(1)
                if tok not in seen_jwts and len(passive_jwts) < 8:
                    seen_jwts.add(tok)
                    info = inspect_passive_jwt(tok, location=f"header:{low_h}")
                    if info is not None:
                        passive_jwts.append(info)

    source_maps: list[str] = []
    for m in _SOURCEMAP_RE.finditer(text):
        sm = m.group(1).strip()[:160]
        if sm and sm not in source_maps and len(source_maps) < 10:
            source_maps.append(sm)

    stack_traces: list[str] = []
    for kind, pat in _STACK_TRACE_PATTERNS:
        if pat.search(text) and kind not in stack_traces:
            stack_traces.append(kind)

    return leaked_secrets, passive_jwts, source_maps, stack_traces


_LIB_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("jquery", re.compile(r"jquery[-/.@](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("bootstrap", re.compile(r"bootstrap[-/.@](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("lodash", re.compile(r"lodash[-/.@](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("angular", re.compile(r"angular(?:\.min)?[-/.@](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("vue", re.compile(r"vue(?:\.global)?[-/.@](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("react", re.compile(r"react(?:-dom)?[-/.@](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("moment", re.compile(r"moment[-/.@](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("dompurify", re.compile(r"(?:dom)?purify[-/.@](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("axios", re.compile(r"axios[-/.@](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("handlebars", re.compile(r"handlebars(?:\.min)?[-/.@](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("alpinejs", re.compile(r"alpine(?:js)?[-/.@](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("htmx", re.compile(r"htmx(?:\.min)?[-/.@](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("swagger-ui", re.compile(r"swagger-ui[-/.@](\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
]


def _parse_external_origin(raw_url: str, page_host: str) -> tuple[bool, str | None, str | None]:
    """Return `(is_external, scheme, origin_host)` for a resource URL relative to `page_host`."""
    cleaned = raw_url.strip()
    if not cleaned or cleaned.startswith(("#", "data:", "javascript:", "mailto:", "blob:")):
        return False, None, None
    if cleaned.startswith("//"):
        parts = urlsplit("https:" + cleaned)
        host = (parts.hostname or "").lower()
        is_ext = bool(host and host != page_host)
        return is_ext, None, (host if is_ext else None)
    parts = urlsplit(cleaned)
    if parts.scheme in {"http", "https"}:
        host = (parts.hostname or "").lower()
        is_ext = bool(host and host != page_host)
        return is_ext, parts.scheme.lower(), (host if is_ext else None)
    return False, None, None


class _PassiveHTMLParser(HTMLParser):
    """Linear-time stdlib HTML parser extracting defensive posture & passive stack hints."""

    def __init__(self, *, page_host: str, is_https: bool) -> None:
        super().__init__(convert_charrefs=True)
        self._page_host = page_host.lower()
        self._is_https = is_https
        self._in_title = False
        self._title_chunks: list[str] = []
        self._in_jsonld = False
        self._jsonld_chunks: list[str] = []
        self._in_form = False
        self._current_form_action = ""
        self._current_form_method = "get"
        self._form_has_password = False
        self._current_form_params: list[str] = []

        self.meta_generator: str | None = None
        self.meta_csp: str | None = None
        self.external_scripts_without_sri: list[str] = []
        self.external_styles_without_sri: list[str] = []
        self.mixed_content_urls: list[str] = []
        self.insecure_forms: list[str] = []
        self.detected_libraries: list[str] = []
        self.framework_hints: list[str] = []
        self.third_party_origins: list[str] = []
        self.inline_script_count: int = 0
        self.unsafe_blank_links: int = 0
        self.mailto_emails: list[str] = []
        self.tel_numbers: list[str] = []
        self.meta_identities: list[dict[str, str]] = []
        self.social_links: list[str] = []
        self.jsonld_blocks: list[str] = []
        self.form_endpoints: list[str] = []
        self.dev_comments: list[str] = []

    def _record_query_params(self, raw_url: str) -> None:
        if "?" not in raw_url:
            return
        path_part, query_part = raw_url.split("?", 1)
        query_part = query_part.split("#", 1)[0]
        flagged: list[str] = []
        for pair in query_part.split("&")[:15]:
            k = pair.split("=", 1)[0].strip()
            if not k:
                continue
            low_k = k.lower()
            if low_k in _HIGH_INTEREST_PARAMS:
                flagged.append(f"{k}*")
        if flagged:
            target_path = (path_part or "/")[:80]
            self._add_unique(
                self.form_endpoints,
                f"GET {target_path} (query: {', '.join(flagged)})",
            )

    def _add_unique(self, target: list[str], value: str, *, limit: int = 25) -> None:
        if value and value not in target and len(target) < limit:
            target.append(value)

    def _scan_library(self, url: str) -> None:
        for lib_name, pat in _LIB_PATTERNS:
            m = pat.search(url)
            if m:
                self._add_unique(self.detected_libraries, f"{lib_name}/{m.group(1)}")

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        low_tag = tag.lower()
        attr_map = {k.lower(): (v or "").strip() for k, v in attrs}

        if low_tag == "title":
            self._in_title = True
            return

        if "ng-version" in attr_map and attr_map["ng-version"]:
            self._add_unique(self.framework_hints, f"angular:{attr_map['ng-version']}")
        if "data-reactroot" in attr_map:
            self._add_unique(self.framework_hints, "react")
        if attr_map.get("id") in {"__next", "__NEXT_DATA__"}:
            self._add_unique(self.framework_hints, "nextjs")
        if attr_map.get("id") == "__nuxt":
            self._add_unique(self.framework_hints, "nuxt")
        if attr_map.get("id") == "swagger-ui":
            self._add_unique(self.framework_hints, "swagger-ui")
        if any(k.startswith("data-svelte") for k in attr_map):
            self._add_unique(self.framework_hints, "sveltekit")
        if any(k.startswith("data-astro-") for k in attr_map):
            self._add_unique(self.framework_hints, "astro")

        if low_tag == "meta":
            name = (attr_map.get("name", "") or attr_map.get("property", "")).lower()
            http_equiv = attr_map.get("http-equiv", "").lower()
            content = attr_map.get("content", "")
            if name == "generator" and content and self.meta_generator is None:
                self.meta_generator = content[:180]
            if http_equiv == "content-security-policy" and content and self.meta_csp is None:
                self.meta_csp = content[:400]
            if content:
                if name in {"og:email", "email"} and _is_valid_email(content):
                    self._add_unique(self.mailto_emails, _format_email_tag(content))
                elif name in {"og:phone_number", "telephone"}:
                    norm_tel = _normalize_phone(content)
                    if norm_tel:
                        self._add_unique(self.tel_numbers, norm_tel)
                elif name in {
                    "author",
                    "owner",
                    "publisher",
                    "copyright",
                    "application-name",
                    "og:site_name",
                    "twitter:site",
                    "twitter:creator",
                }:
                    entry = {"kind": f"meta:{name}", "value": content[:160]}
                    if entry not in self.meta_identities and len(self.meta_identities) < 20:
                        self.meta_identities.append(entry)
            return

        if low_tag == "script":
            src = attr_map.get("src", "")
            script_type = attr_map.get("type", "").lower()
            if script_type == "application/ld+json" and not src:
                self._in_jsonld = True
                self._jsonld_chunks = []
                return
            if src:
                self._scan_library(src)
                if "wp-content/" in src or "wp-includes/" in src:
                    self._add_unique(self.framework_hints, "wordpress")
                if "/_next/static/" in src:
                    self._add_unique(self.framework_hints, "nextjs")
                if "/_nuxt/" in src:
                    self._add_unique(self.framework_hints, "nuxt")
                is_ext, scheme, origin_host = _parse_external_origin(src, self._page_host)
                if origin_host:
                    self._add_unique(self.third_party_origins, origin_host, limit=40)
                if self._is_https and scheme == "http":
                    self._add_unique(self.mixed_content_urls, src[:200])
                if is_ext and not attr_map.get("integrity"):
                    self._add_unique(self.external_scripts_without_sri, src[:200])
            else:
                if not script_type or "javascript" in script_type or script_type == "module":
                    self.inline_script_count += 1
            return

        if low_tag == "link":
            rel = attr_map.get("rel", "").lower()
            href = attr_map.get("href", "")
            if href:
                self._scan_library(href)
                if "wp-content/" in href or "wp-includes/" in href:
                    self._add_unique(self.framework_hints, "wordpress")
                is_ext, scheme, origin_host = _parse_external_origin(href, self._page_host)
                if origin_host and ("stylesheet" in rel or "preload" in rel):
                    self._add_unique(self.third_party_origins, origin_host, limit=40)
                if (
                    self._is_https
                    and scheme == "http"
                    and ("stylesheet" in rel or "preload" in rel)
                ):
                    self._add_unique(self.mixed_content_urls, href[:200])
                if "stylesheet" in rel and is_ext and not attr_map.get("integrity"):
                    self._add_unique(self.external_styles_without_sri, href[:200])
            return

        if low_tag == "a":
            target_attr = attr_map.get("target", "").lower()
            href = attr_map.get("href", "")
            low_href = href.lower()
            if low_href.startswith("mailto:"):
                raw_mail = href[7:].split("?", 1)[0].strip()
                if _is_valid_email(raw_mail):
                    self._add_unique(self.mailto_emails, _format_email_tag(raw_mail))
            elif low_href.startswith("tel:"):
                norm_tel = _normalize_phone(href[4:].split("?", 1)[0])
                if norm_tel:
                    self._add_unique(self.tel_numbers, norm_tel)
            elif any(host in low_href for host in _SOCIAL_HOST_PATTERNS):
                self._add_unique(self.social_links, href[:200])
            if href and not low_href.startswith(("mailto:", "tel:", "javascript:", "#")):
                self._record_query_params(href)
            if target_attr == "_blank" and href:
                is_ext, _, _ = _parse_external_origin(href, self._page_host)
                rel_tokens = set(attr_map.get("rel", "").lower().split())
                if is_ext and "noopener" not in rel_tokens:
                    self.unsafe_blank_links += 1
            return

        if low_tag in {"img", "iframe", "audio", "video", "source"}:
            src = attr_map.get("src", "")
            if src:
                _, scheme, origin_host = _parse_external_origin(src, self._page_host)
                if origin_host:
                    self._add_unique(self.third_party_origins, origin_host, limit=40)
                if self._is_https and scheme == "http":
                    self._add_unique(self.mixed_content_urls, src[:200])
            return

        if low_tag == "form":
            self._in_form = True
            self._form_has_password = False
            self._current_form_params = []
            action = attr_map.get("action", "")
            self._current_form_action = action
            self._current_form_method = (attr_map.get("method", "get") or "get").lower()
            if action:
                self._record_query_params(action)
            if action.lower().startswith("http://"):
                self._add_unique(self.insecure_forms, f"form action over HTTP: {action[:160]}")
            return

        if low_tag in {"input", "select", "textarea"}:
            in_name = attr_map.get("name", "")
            in_type = attr_map.get("type", "").lower()
            if in_name:
                tag_param = f"{in_name}*" if in_name.lower() in _HIGH_INTEREST_PARAMS else in_name
                if (
                    tag_param not in self._current_form_params
                    and len(self._current_form_params) < 20
                ):
                    self._current_form_params.append(tag_param)
            if in_name == "csrfmiddlewaretoken":
                self._add_unique(self.framework_hints, "django")
            if in_name == "authenticity_token":
                self._add_unique(self.framework_hints, "rails")
            if in_name == "_token":
                self._add_unique(self.framework_hints, "laravel")
            if in_type == "password":
                self._form_has_password = True
                if not self._is_https and not self._current_form_action.lower().startswith(
                    "https://"
                ):
                    self._add_unique(
                        self.insecure_forms,
                        "password input served over plain HTTP",
                    )
                if self._in_form and self._current_form_method == "get":
                    self._add_unique(
                        self.insecure_forms,
                        "password form uses HTTP GET method (credentials exposed in URL/logs)",
                    )

    def handle_endtag(self, tag: str) -> None:
        low_tag = tag.lower()
        if low_tag == "title":
            self._in_title = False
        elif low_tag == "script" and self._in_jsonld:
            self._in_jsonld = False
            block = "".join(self._jsonld_chunks).strip()
            if block and len(self.jsonld_blocks) < 10:
                self.jsonld_blocks.append(block)
            self._jsonld_chunks = []
        elif low_tag == "form":
            if self._in_form:
                act = (self._current_form_action or "/")[:80]
                mth = self._current_form_method.upper()
                params_str = ", ".join(self._current_form_params) or "none"
                self._add_unique(self.form_endpoints, f"{mth} {act} (params: {params_str})")
            self._in_form = False
            self._current_form_action = ""
            self._current_form_method = "get"
            self._form_has_password = False
            self._current_form_params = []

    def handle_comment(self, data: str) -> None:
        cleaned = " ".join(data.strip().split())
        if not cleaned or len(cleaned) < 4:
            return
        low = cleaned.lower()
        if any(kw in low for kw in _DEV_COMMENT_KEYWORDS):
            self._add_unique(self.dev_comments, f"comment:{cleaned[:120]}", limit=15)

    def handle_data(self, data: str) -> None:
        if self._in_title and len("".join(self._title_chunks)) < 200:
            self._title_chunks.append(data)
        elif self._in_jsonld and len("".join(self._jsonld_chunks)) < 32768:
            self._jsonld_chunks.append(data)

    @property
    def title(self) -> str | None:
        joined = " ".join("".join(self._title_chunks).split()).strip()
        return joined[:160] if joined else None


def _looks_like_html(body: bytes, headers: list[tuple[str, str]]) -> bool:
    for k, v in headers:
        if k.lower() == "content-type":
            low = v.lower()
            if "text/html" in low or "application/xhtml+xml" in low:
                return True
            if "json" in low or "octet-stream" in low or "image/" in low or "pdf" in low:
                return False
    prefix = body[:512].lstrip().lower()
    return prefix.startswith((b"<!doctype html", b"<html", b"<head", b"<body", b"<meta", b"<title"))


def analyze_html_body(
    body: bytes,
    *,
    headers: list[tuple[str, str]],
    page_url: str,
) -> HTMLPassiveAnalysis:
    """Passively inspect an already-received HTML body with zero extra network requests."""
    if not body or not _looks_like_html(body, headers):
        return HTMLPassiveAnalysis(analyzed=False)

    parts = urlsplit(page_url)
    page_host = (parts.hostname or "").lower()
    is_https = parts.scheme.lower() == "https"

    text = body[:_MAX_PARSE_BYTES].decode("utf-8", errors="replace")
    parser = _PassiveHTMLParser(page_host=page_host, is_https=is_https)
    with contextlib.suppress(Exception):
        parser.feed(text)
        parser.close()

    hints = list(parser.framework_hints)
    if "__NEXT_DATA__" in text and "nextjs" not in hints:
        hints.append("nextjs")
    if "__NUXT__" in text and "nuxt" not in hints:
        hints.append("nuxt")
    if ("wp-content/" in text or "wp-includes/" in text) and "wordpress" not in hints:
        hints.append("wordpress")
    if ("Drupal.settings" in text or "drupal-settings-json" in text) and "drupal" not in hints:
        hints.append("drupal")

    leaked_secrets, passive_jwts, source_maps, stack_traces = scan_passive_exposures(text, headers)
    (
        emails,
        phone_numbers,
        exposed_ids_and_keys,
        identities_and_names,
        social_links,
        cloud_and_api_endpoints,
        form_endpoints,
        internal_leaks_and_comments,
    ) = scan_passive_entities(
        text,
        parser=parser,
        leaked_secrets=leaked_secrets,
    )

    return HTMLPassiveAnalysis(
        analyzed=True,
        title=parser.title,
        meta_generator=parser.meta_generator,
        meta_csp=parser.meta_csp,
        external_scripts_without_sri=parser.external_scripts_without_sri,
        external_styles_without_sri=parser.external_styles_without_sri,
        mixed_content_urls=parser.mixed_content_urls,
        insecure_forms=parser.insecure_forms,
        detected_libraries=parser.detected_libraries,
        framework_hints=hints,
        third_party_origins=parser.third_party_origins,
        inline_script_count=parser.inline_script_count,
        unsafe_blank_links=parser.unsafe_blank_links,
        leaked_secrets=leaked_secrets,
        passive_jwts=passive_jwts,
        source_maps=source_maps,
        stack_traces=stack_traces,
        emails=emails,
        phone_numbers=phone_numbers,
        exposed_ids_and_keys=exposed_ids_and_keys,
        identities_and_names=identities_and_names,
        social_links=social_links,
        cloud_and_api_endpoints=cloud_and_api_endpoints,
        form_endpoints=form_endpoints,
        internal_leaks_and_comments=internal_leaks_and_comments,
    )
