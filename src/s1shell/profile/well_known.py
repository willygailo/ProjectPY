"""Opt-in passive review of RFC well-known metadata (`security.txt`, OIDC, JWKS, OPTIONS)."""

from __future__ import annotations

import base64
import contextlib
import json
import ssl
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx

from s1shell.config import RuntimeConfig
from s1shell.errors import NetworkError
from s1shell.http import build_target_client, fetch_bounded
from s1shell.profile.models import WellKnownCheck
from s1shell.scope import ParsedTarget

_MAX_META_BYTES = 128 * 1024  # 128 KiB cap for metadata text files

_SENSITIVE_ROBOTS_TOKENS = (
    "admin",
    "backup",
    "config",
    "debug",
    "internal",
    "private",
    "secret",
    "staging",
    "phpinfo",
    ".git",
    ".env",
    "graphql",
    "swagger",
    "metrics",
    "actuator",
)

_RISKY_HTTP_METHODS = {
    "TRACE",
    "TRACK",
    "PUT",
    "DELETE",
    "CONNECT",
    "PROPFIND",
    "PROPPATCH",
    "MKCOL",
    "COPY",
    "MOVE",
}


@dataclass(frozen=True)
class ParsedSecurityTxt:
    """Normalized RFC 9116 `security.txt` fields."""

    contacts: list[str]
    expires: str | None
    expired: bool
    canonical: str | None = None
    encryption: str | None = None
    policy: str | None = None


def parse_security_txt(
    text: str,
    *,
    now: datetime | None = None,
) -> tuple[list[str], str | None, bool]:
    """Parse RFC 9116 security.txt Contact and Expires fields."""
    parsed = parse_security_txt_full(text, now=now)
    return parsed.contacts, parsed.expires, parsed.expired


def parse_security_txt_full(
    text: str,
    *,
    now: datetime | None = None,
) -> ParsedSecurityTxt:
    """Parse RFC 9116 security.txt Contact, Expires, Canonical, Encryption, and Policy fields."""
    contacts: list[str] = []
    expires: str | None = None
    expired = False
    canonical: str | None = None
    encryption: str | None = None
    policy: str | None = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, val = line.split(":", 1)
        k_low = key.strip().lower()
        cleaned = val.strip()
        if not cleaned:
            continue
        if k_low == "contact" and cleaned not in contacts:
            contacts.append(cleaned)
        elif k_low == "expires" and expires is None:
            expires = cleaned
            try:
                iso_text = cleaned[:-1] + "+00:00" if cleaned.endswith("Z") else cleaned
                dt = datetime.fromisoformat(iso_text)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                ref_now = now if now is not None else datetime.now(timezone.utc)
                expired = ref_now > dt.astimezone(timezone.utc)
            except ValueError:
                expired = False
        elif k_low == "canonical" and canonical is None:
            canonical = cleaned
        elif k_low == "encryption" and encryption is None:
            encryption = cleaned
        elif k_low == "policy" and policy is None:
            policy = cleaned

    return ParsedSecurityTxt(
        contacts=contacts,
        expires=expires,
        expired=expired,
        canonical=canonical,
        encryption=encryption,
        policy=policy,
    )


def parse_robots_txt(text: str) -> tuple[int, list[str]]:
    """Count Disallow entries and flag passively disclosed sensitive path hints."""
    count, hints, _ = parse_robots_txt_full(text)
    return count, hints


def parse_robots_txt_full(text: str) -> tuple[int, list[str], list[str]]:
    """Parse Disallow counts, sensitive path hints, and Sitemap URLs from `/robots.txt`."""
    disallow_count = 0
    sensitive: list[str] = []
    sitemaps: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, val = line.split(":", 1)
        k_low = key.strip().lower()
        cleaned = val.strip()
        if not cleaned:
            continue
        if k_low == "sitemap":
            if cleaned not in sitemaps and len(sitemaps) < 10:
                sitemaps.append(cleaned)
            continue
        if k_low != "disallow":
            continue
        disallow_count += 1
        low_path = cleaned.lower()
        if (
            any(tok in low_path for tok in _SENSITIVE_ROBOTS_TOKENS)
            and cleaned not in sensitive
            and len(sensitive) < 15
        ):
            sensitive.append(cleaned)
    return disallow_count, sensitive, sitemaps


def parse_allowed_methods(headers: list[tuple[str, str]]) -> tuple[list[str], list[str]]:
    """Extract normalized HTTP methods from `Allow` / `Access-Control-Allow-Methods` headers."""
    methods: list[str] = []
    seen: set[str] = set()
    for name, val in headers:
        if name.lower() not in {"allow", "access-control-allow-methods"}:
            continue
        for token in val.split(","):
            norm = token.strip().upper()
            if norm and norm.isalpha() and norm not in seen:
                seen.add(norm)
                methods.append(norm)
    risky = [m for m in methods if m in _RISKY_HTTP_METHODS]
    return methods, risky


def inspect_http_methods(
    cfg: RuntimeConfig,
    *,
    parsed: ParsedTarget,
    pinned_ip: str,
    pinned_ips: Sequence[str] | None = None,
    verify: ssl.SSLContext | bool = True,
    http_transport: httpx.BaseTransport | None = None,
) -> tuple[list[str], list[str]]:
    """Send 1 read-only `OPTIONS` request to inspect advertised HTTP methods passively."""
    url = parsed.to_url("https")
    with build_target_client(
        cfg,
        expected_host=parsed.host,
        pinned_ip=pinned_ip,
        pinned_ips=pinned_ips,
        verify=verify,
        transport=http_transport,
    ) as client:
        try:
            resp = fetch_bounded(client, "OPTIONS", url, max_bytes=16 * 1024)
        except NetworkError:
            return [], []
    return parse_allowed_methods(resp.headers)


def parse_oidc_configuration(payload: dict[str, Any]) -> tuple[str | None, list[str]]:
    """Passively audit `/.well-known/openid-configuration` metadata for weak auth settings."""
    issuer = str(payload.get("issuer") or "").strip() or None
    issues: list[str] = []
    if issuer and issuer.lower().startswith("http://"):
        issues.append("OIDC issuer uses plain HTTP instead of HTTPS")
    for field_name in (
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
        "userinfo_endpoint",
    ):
        val = str(payload.get(field_name) or "").strip()
        if val.lower().startswith("http://"):
            issues.append(f"OIDC `{field_name}` uses plain HTTP")

    resp_types = [str(r).strip().lower() for r in payload.get("response_types_supported", []) or []]
    if any("token" in rt for rt in resp_types):
        issues.append(
            "OIDC advertises legacy implicit/hybrid token response_types (`token` in URL fragment)"
        )

    algs = [
        str(a).strip().lower()
        for a in payload.get("id_token_signing_alg_values_supported", []) or []
    ]
    if "none" in algs:
        issues.append("OIDC advertises unsigned `none` ID token signing algorithm")

    pkce = [
        str(m).strip().upper() for m in payload.get("code_challenge_methods_supported", []) or []
    ]
    if pkce and "S256" not in pkce:
        issues.append("OIDC `code_challenge_methods_supported` omits PKCE `S256`")
    elif not pkce and "code" in resp_types:
        issues.append("OIDC supports authorization code flow without advertising PKCE (`S256`)")

    return issuer, issues


def parse_jwks_payload(payload: dict[str, Any]) -> tuple[int, list[str]]:
    """Passively audit `/.well-known/jwks.json` for private key leakage or weak key parameters."""
    raw_keys = payload.get("keys")
    if not isinstance(raw_keys, list):
        return 0, []
    keys = [k for k in raw_keys if isinstance(k, dict)]
    issues: list[str] = []
    priv_fields = {"d", "p", "q", "dp", "dq", "qi", "oth"}
    for idx, k in enumerate(keys):
        kid = str(k.get("kid") or f"key#{idx}")
        exposed_priv = sorted(f for f in priv_fields if k.get(f))
        if exposed_priv:
            issues.append(f"JWKS `{kid}` exposes private key material ({', '.join(exposed_priv)})")
        alg = str(k.get("alg") or "").strip().lower()
        if alg == "none":
            issues.append(f"JWKS `{kid}` advertises insecure `alg: none`")
        if str(k.get("kty") or "").upper() == "RSA" and isinstance(k.get("n"), str):
            mod_b64 = k["n"]
            padded = mod_b64 + "=" * ((4 - len(mod_b64) % 4) % 4)
            with contextlib.suppress(Exception):
                mod_bytes = base64.urlsafe_b64decode(padded.encode("ascii"))
                bit_len = int.from_bytes(mod_bytes, "big").bit_length()
                if 0 < bit_len < 2048:
                    issues.append(f"JWKS RSA key `{kid}` modulus is only {bit_len} bits (< 2048)")
    return len(keys), issues


def inspect_well_known(
    cfg: RuntimeConfig,
    *,
    parsed: ParsedTarget,
    pinned_ip: str,
    pinned_ips: Sequence[str] | None = None,
    verify: ssl.SSLContext | bool = True,
    http_transport: httpx.BaseTransport | None = None,
) -> WellKnownCheck:
    """Perform bounded read-only GETs on standard RFC well-known metadata endpoints."""
    scheme = parsed.effective_scheme("https")
    port = parsed.effective_port("https")
    default_port = 80 if scheme == "http" else 443
    is_v6 = parsed.is_ip and parsed.ip_obj and parsed.ip_obj.version == 6
    host_fmt = f"[{parsed.host}]" if is_v6 else parsed.host
    port_part = f":{port}" if port != default_port else ""
    origin = f"{scheme}://{host_fmt}{port_part}"

    sec_present = False
    sec_status: int | None = None
    sec_contacts: list[str] = []
    sec_expires: str | None = None
    sec_expired = False
    sec_canonical: str | None = None
    sec_encryption: str | None = None
    sec_policy: str | None = None
    sec_over_http = False

    rob_present = False
    rob_status: int | None = None
    rob_count = 0
    rob_hints: list[str] = []
    rob_sitemaps: list[str] = []

    oidc_present = False
    oidc_issuer: str | None = None
    oidc_issues: list[str] = []

    jwks_present = False
    jwks_key_count = 0
    jwks_issues: list[str] = []

    mobile_trust_files: list[str] = []

    with build_target_client(
        cfg,
        expected_host=parsed.host,
        pinned_ip=pinned_ip,
        pinned_ips=pinned_ips,
        verify=verify,
        transport=http_transport,
    ) as client:
        try:
            sec_resp = fetch_bounded(
                client,
                "GET",
                f"{origin}/.well-known/security.txt",
                max_bytes=_MAX_META_BYTES,
            )
            sec_status = sec_resp.status_code
            if sec_resp.status_code == 200:
                text = sec_resp.body.decode("utf-8", errors="replace")
                parsed_sec = parse_security_txt_full(text)
                sec_contacts = parsed_sec.contacts
                sec_expires = parsed_sec.expires
                sec_expired = parsed_sec.expired
                sec_canonical = parsed_sec.canonical
                sec_encryption = parsed_sec.encryption
                sec_policy = parsed_sec.policy
                sec_present = bool(sec_contacts or "contact:" in text.lower())
                sec_over_http = sec_present and scheme == "http"
        except NetworkError:
            pass

        try:
            rob_resp = fetch_bounded(
                client,
                "GET",
                f"{origin}/robots.txt",
                max_bytes=_MAX_META_BYTES,
            )
            rob_status = rob_resp.status_code
            if rob_resp.status_code == 200:
                text = rob_resp.body.decode("utf-8", errors="replace")
                if "user-agent" in text.lower() or "disallow" in text.lower():
                    rob_present = True
                    rob_count, rob_hints, rob_sitemaps = parse_robots_txt_full(text)
        except NetworkError:
            pass

        try:
            oidc_resp = fetch_bounded(
                client,
                "GET",
                f"{origin}/.well-known/openid-configuration",
                max_bytes=_MAX_META_BYTES,
            )
            if oidc_resp.status_code == 200:
                data = json.loads(oidc_resp.body.decode("utf-8", errors="replace"))
                if isinstance(data, dict) and (
                    "issuer" in data or "authorization_endpoint" in data
                ):
                    oidc_present = True
                    oidc_issuer, oidc_issues = parse_oidc_configuration(data)
        except (NetworkError, ValueError):
            pass

        try:
            jwks_resp = fetch_bounded(
                client,
                "GET",
                f"{origin}/.well-known/jwks.json",
                max_bytes=_MAX_META_BYTES,
            )
            if jwks_resp.status_code == 200:
                data = json.loads(jwks_resp.body.decode("utf-8", errors="replace"))
                if isinstance(data, dict) and isinstance(data.get("keys"), list):
                    jwks_present = True
                    jwks_key_count, jwks_issues = parse_jwks_payload(data)
        except (NetworkError, ValueError):
            pass

        for rel_path in (
            "/.well-known/assetlinks.json",
            "/.well-known/apple-app-site-association",
        ):
            try:
                m_resp = fetch_bounded(
                    client,
                    "GET",
                    f"{origin}{rel_path}",
                    max_bytes=64 * 1024,
                )
                if m_resp.status_code == 200:
                    m_data = json.loads(m_resp.body.decode("utf-8", errors="replace"))
                    if isinstance(m_data, (dict, list)) and m_data:
                        mobile_trust_files.append(rel_path)
            except (NetworkError, ValueError):
                pass

    return WellKnownCheck(
        security_txt_present=sec_present,
        security_txt_status=sec_status,
        security_txt_contacts=sec_contacts,
        security_txt_expires=sec_expires,
        security_txt_expired=sec_expired,
        security_txt_canonical=sec_canonical,
        security_txt_encryption=sec_encryption,
        security_txt_policy=sec_policy,
        security_txt_over_http=sec_over_http,
        robots_txt_present=rob_present,
        robots_txt_status=rob_status,
        robots_disallow_count=rob_count,
        robots_sensitive_hints=rob_hints,
        robots_sitemaps=rob_sitemaps,
        oidc_present=oidc_present,
        oidc_issuer=oidc_issuer,
        oidc_issues=oidc_issues,
        jwks_present=jwks_present,
        jwks_key_count=jwks_key_count,
        jwks_issues=jwks_issues,
        mobile_trust_files=mobile_trust_files,
    )
