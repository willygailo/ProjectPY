"""Deterministic reversible telemetry redaction for NDA-safe cloud AI triage."""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(
    r"(?<![A-Za-z0-9:_])"
    r"(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?:\.\d{1,3}){0,3}"
    r"(?![A-Za-z0-9:_])"
)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_QUERY_SECRET_RE = re.compile(
    r"([?&](?:token|access_token|id_token|refresh_token|api_key|apikey|key|secret|"
    r"password|passwd|sig|signature|auth|session|session_id|jwt)=)([^&#\s\"'<>]+)",
    re.IGNORECASE,
)
_BEARER_RE = re.compile(r"\b(Bearer\s+)([A-Za-z0-9._~+/=-]{8,})", re.IGNORECASE)
_JWT_INLINE_RE = re.compile(
    r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*)(?![A-Za-z0-9_-])"
)
_SENSITIVE_KEYS = {"scope_id", "auth_ref", "owner", "operator"}
_SENSITIVE_AUTH_HEADERS = {"authorization", "proxy-authorization"}
_SENSITIVE_SECRET_HEADERS = {
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
}


class TelemetryRedactor:
    """Anonymizes client hostnames, IPs, emails, scope IDs, and cookie values before AI calls."""

    def __init__(self) -> None:
        self._forward: dict[str, str] = {}
        self._reverse: dict[str, str] = {}
        self._counters: dict[str, int] = {}

    def _token(self, kind: str, original: str) -> str:
        clean = original.strip()
        if not clean:
            return original
        existing = self._forward.get(clean)
        if existing is not None:
            return existing
        count = self._counters.get(kind, 0) + 1
        self._counters[kind] = count
        placeholder = f"[{kind}_{count}]"
        self._forward[clean] = placeholder
        self._reverse[placeholder] = clean
        return placeholder

    def _register_hosts_and_ips(self, obj: Any) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in {"url", "target"} and isinstance(v, str):
                    parts = urlsplit(v if "://" in v else f"https://{v}")
                    if parts.hostname:
                        self._register_host_or_ip(parts.hostname)
                elif k == "pinned_ip" and isinstance(v, str) and v.strip():
                    self._token("TARGET_IP", v.strip())
                elif k in _SENSITIVE_KEYS and isinstance(v, str) and v.strip():
                    self._token(k.upper(), v.strip())
                elif k == "sans" and isinstance(v, list):
                    for item in v:
                        if isinstance(item, str) and ":" in item:
                            _, val = item.split(":", 1)
                            self._register_host_or_ip(val.lstrip("*."))
                else:
                    self._register_hosts_and_ips(v)
        elif isinstance(obj, list):
            for item in obj:
                self._register_hosts_and_ips(item)

    def _register_host_or_ip(self, value: str) -> None:
        cleaned = value.strip().rstrip(".")
        if not cleaned or cleaned.lower() in {"localhost"}:
            return
        try:
            ipaddress.ip_address(cleaned)
            self._token("TARGET_IP", cleaned)
            return
        except ValueError:
            pass
        if "." in cleaned:
            self._token("TARGET_HOST", cleaned)

    def redact_text(self, text: str) -> str:
        """Replace known hosts, IPs, emails, and sensitive identifiers with placeholders."""
        out = text
        # Replace longest known originals first so subdomains don't get partially substituted
        for orig in sorted(self._forward, key=len, reverse=True):
            out = out.replace(orig, self._forward[orig])

        def _repl_ip(match: re.Match[str]) -> str:
            raw = match.group(0)
            try:
                ipaddress.IPv4Address(raw)
            except ValueError:
                return raw
            return self._token("TARGET_IP", raw)

        def _repl_ipv6(match: re.Match[str]) -> str:
            raw = match.group(0)
            if raw == "::":
                return raw
            try:
                ipaddress.IPv6Address(raw)
            except ValueError:
                return raw
            return self._token("TARGET_IP", raw)

        out = _IPV6_RE.sub(_repl_ipv6, out)
        out = _IPV4_RE.sub(_repl_ip, out)
        out = _EMAIL_RE.sub(lambda m: self._token("EMAIL", m.group(0)), out)
        out = _QUERY_SECRET_RE.sub(r"\1[REDACTED_PARAM]", out)
        out = _BEARER_RE.sub(r"\1[REDACTED_TOKEN]", out)
        out = _JWT_INLINE_RE.sub("[REDACTED_JWT]", out)
        return out

    def redact_artifact(self, data: Any) -> Any:
        """Recursively redact a JSON-parsed S1shell artifact before sending to an LLM."""
        self._register_hosts_and_ips(data)
        return self._walk(data)

    def _walk(self, obj: Any, *, key_hint: str = "") -> Any:
        if isinstance(obj, dict):
            return {k: self._walk(v, key_hint=str(k).lower()) for k, v in obj.items()}
        if isinstance(obj, list):
            if key_hint == "raw_headers":
                redacted_headers: list[Any] = []
                for pair in obj:
                    if isinstance(pair, list) and len(pair) == 2:
                        h_name, h_val = str(pair[0]), str(pair[1])
                        low_h = h_name.lower()
                        if low_h == "set-cookie" and "=" in h_val:
                            c_name, rest = h_val.split("=", 1)
                            attrs = ";" + rest.split(";", 1)[1] if ";" in rest else ""
                            h_val = f"{c_name}=[REDACTED_COOKIE_VALUE]{attrs}"
                        elif low_h == "cookie":
                            scrubbed_parts: list[str] = []
                            for seg in h_val.split(";"):
                                if "=" in seg:
                                    k_part = seg.split("=", 1)[0].strip()
                                    scrubbed_parts.append(f"{k_part}=[REDACTED_COOKIE_VALUE]")
                                elif seg.strip():
                                    scrubbed_parts.append("[REDACTED_COOKIE_VALUE]")
                            h_val = "; ".join(scrubbed_parts)
                        elif low_h in _SENSITIVE_AUTH_HEADERS:
                            parts = h_val.strip().split(None, 1)
                            h_val = (
                                f"{parts[0]} [REDACTED_AUTH_HEADER]"
                                if len(parts) == 2
                                else "[REDACTED_AUTH_HEADER]"
                            )
                        elif low_h in _SENSITIVE_SECRET_HEADERS:
                            h_val = "[REDACTED_HEADER_VALUE]"
                        redacted_headers.append([h_name, self.redact_text(h_val)])
                    else:
                        redacted_headers.append(self._walk(pair))
                return redacted_headers
            return [self._walk(item) for item in obj]
        if isinstance(obj, str):
            return self.redact_text(obj)
        return obj

    def restore_text(self, text: str) -> str:
        """Restore redacted placeholders back to their original local values."""
        out = text
        for placeholder, orig in self._reverse.items():
            out = out.replace(placeholder, orig)
        return out

    @property
    def replacement_count(self) -> int:
        """Total unique sensitive tokens anonymized."""
        return len(self._forward)
