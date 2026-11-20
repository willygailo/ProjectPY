"""Opt-in passive review of `security.txt`, `/robots.txt`, and HTTP `OPTIONS` methods."""

from __future__ import annotations

import ssl
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone

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


def inspect_well_known(
    cfg: RuntimeConfig,
    *,
    parsed: ParsedTarget,
    pinned_ip: str,
    pinned_ips: Sequence[str] | None = None,
    verify: ssl.SSLContext | bool = True,
    http_transport: httpx.BaseTransport | None = None,
) -> WellKnownCheck:
    """Perform at most 2 read-only GETs for `/.well-known/security.txt` and `/robots.txt`."""
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
    )
