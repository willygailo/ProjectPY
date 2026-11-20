"""Canonical dataclasses for `s1shell fingerprint` output."""

from __future__ import annotations

from dataclasses import dataclass, field

from s1shell import __version__
from s1shell.models import SCHEMA_VERSION, utc_now_iso


@dataclass(frozen=True)
class FingerprintMatch:
    """Single passively identified software, CDN, WAF, or framework."""

    vendor: str
    product: str
    category: str  # web_server | cdn | waf | framework | runtime
    confidence: str  # high | medium | low
    version: str | None = None
    evidence: list[str] = field(default_factory=list)
    cpe: str | None = None


@dataclass(frozen=True)
class FingerprintResult:
    """Canonical output envelope for `s1shell fingerprint`."""

    target: str
    url: str
    mode: str  # live | from_profile
    scope_id: str
    auth_ref: str
    matches: list[FingerprintMatch] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "fingerprint_report"
