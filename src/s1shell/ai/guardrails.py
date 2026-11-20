"""Prompt-injection defenses, nonce-tagged telemetry boundaries, and air-gap URL guards."""

from __future__ import annotations

import ipaddress
import re
import secrets
from urllib.parse import urlsplit

from s1shell.errors import ValidationError

_OPEN_TAG_RE = re.compile(r"<\s*untrusted_telemetry\b[^>]*>", re.IGNORECASE)
_CLOSE_TAG_RE = re.compile(r"<\s*/\s*untrusted_telemetry\s*>", re.IGNORECASE)

_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "delimiter_breakout",
        re.compile(r"<\s*/?\s*untrusted_telemetry\b", re.IGNORECASE),
    ),
    (
        "instruction_override",
        re.compile(
            r"\b(?:ignore|disregard|forget|override)\s+"
            r"(?:all\s+|any\s+)?(?:previous|prior|above|system)\s+"
            r"(?:instructions?|rules?|prompts?|constraints?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "role_hijack",
        re.compile(
            r"\b(?:you\s+are\s+now|act\s+as\s+an?\s+unrestricted|new\s+system\s+prompt|"
            r"enter\s+developer\s+mode)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "secret_exfiltration",
        re.compile(
            r"\b(?:reveal|print|dump|exfiltrate|output)\s+"
            r"(?:your\s+)?(?:system\s+prompt|api[_\s-]?key|environment\s+variables?)\b",
            re.IGNORECASE,
        ),
    ),
)


def detect_prompt_injection(text: str, *, source: str = "telemetry") -> list[str]:
    """Passively detect suspicious prompt-injection markers inside untrusted target telemetry."""
    warnings: list[str] = []
    for kind, pattern in _INJECTION_PATTERNS:
        if pattern.search(text):
            warnings.append(f"{source}: suspicious prompt-injection pattern ({kind})")
    return warnings


def wrap_untrusted_telemetry(
    text: str,
    *,
    source: str,
    boundary_id: str | None = None,
) -> tuple[str, list[str]]:
    """Escape delimiter breakout tags and wrap telemetry in a nonce-tagged isolation block."""
    warnings = detect_prompt_injection(text, source=source)
    escaped = _CLOSE_TAG_RE.sub("&lt;/untrusted_telemetry&gt;", text)
    escaped = _OPEN_TAG_RE.sub("&lt;untrusted_telemetry&gt;", escaped)
    nonce = boundary_id if boundary_id else f"t_{secrets.token_hex(4)}"
    safe_source = re.sub(r'["<>\r\n]+', "_", source).strip() or "artifact"
    wrapped = (
        f'<untrusted_telemetry id="{nonce}" source="{safe_source}">\n'
        f"{escaped}\n"
        f"</untrusted_telemetry>"
    )
    return wrapped, warnings


def validate_local_endpoint(url: str) -> None:
    """Enforce `--local-only` air-gap policy by rejecting any non-loopback AI endpoint URL."""
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise ValidationError(
            f"--local-only rejected invalid AI endpoint URL '{url}': missing hostname."
        )
    if host == "localhost":
        return
    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValidationError(
            f"--local-only air-gap guard refused remote AI endpoint '{host}'. "
            "Use local Ollama (127.0.0.1 / localhost) or omit --local-only."
        ) from exc
    if not ip_obj.is_loopback:
        raise ValidationError(
            f"--local-only air-gap guard refused non-loopback AI endpoint '{host}'. "
            "Use loopback (127.0.0.1 / ::1) or omit --local-only."
        )
