"""Opt-in passive review of RFC 9116 `/.well-known/security.txt` and `/robots.txt`."""

from __future__ import annotations

import ssl
from collections.abc import Sequence
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
)


def parse_security_txt(text: str, *, now: datetime | None = None) -> tuple[list[str], str | None, bool]:
    """Parse RFC 9116 security.txt Contact and Expires fields."""
    contacts: list[str] = []
    expires: str | None = None
    expired = False

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, val = line.split(":", 1)
        k_low = key.strip().lower()
        cleaned = val.strip()
        if k_low == "contact" and cleaned and cleaned not in contacts:
            contacts.append(cleaned)
        elif k_low == "expires" and cleaned and expires is None:
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
    return contacts, expires, expired


def parse_robots_txt(text: str) -> tuple[int, list[str]]:
    """Count Disallow entries and flag passively disclosed sensitive path hints."""
    disallow_count = 0
    sensitive: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, val = line.split(":", 1)
        if key.strip().lower() != "disallow":
            continue
        path = val.strip()
        if not path:
            continue
        disallow_count += 1
        low_path = path.lower()
        if any(tok in low_path for tok in _SENSITIVE_ROBOTS_TOKENS):
            if path not in sensitive and len(sensitive) < 15:
                sensitive.append(path)
    return disallow_count, sensitive


def inspect_well_known(
    cfg: RuntimeConfig,
    *,
    parsed: ParsedTarget,
    pinned_ip: str,
    pinned_ips: Sequence[str] | None = None,
    verify: ssl.SSLContext | bool = True,
    http_transport: httpx.BaseTransport | None = None,
) -> WellKnownCheck:
    """Perform at most 2 bounded read-only GETs for `/.well-known/security.txt` and `/robots.txt`."""
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

    rob_present = False
    rob_status: int | None = None
    rob_count = 0
    rob_hints: list[str] = []

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
                sec_contacts, sec_expires, sec_expired = parse_security_txt(text)
                sec_present = bool(sec_contacts or "contact:" in text.lower())
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
                    rob_count, rob_hints = parse_robots_txt(text)
        except NetworkError:
            pass

    return WellKnownCheck(
        security_txt_present=sec_present,
        security_txt_status=sec_status,
        security_txt_contacts=sec_contacts,
        security_txt_expires=sec_expires,
        security_txt_expired=sec_expired,
        robots_txt_present=rob_present,
        robots_txt_status=rob_status,
        robots_disallow_count=rob_count,
        robots_sensitive_hints=rob_hints,
    )
