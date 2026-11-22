"""Canonical dataclasses for `s1shell dump` evidence bundle output."""

from __future__ import annotations

from dataclasses import dataclass, field

from s1shell import __version__
from s1shell.models import SCHEMA_VERSION, utc_now_iso


@dataclass(frozen=True)
class DumpFileEntry:
    """Single exported evidence artifact with deterministic SHA-256 digest."""

    relative_path: str
    category: str  # raw | well_known | entities | analysis | osint | report
    size_bytes: int
    sha256: str


@dataclass(frozen=True)
class DumpResult:
    """Canonical output envelope for `s1shell dump`."""

    target: str
    url: str
    pinned_ip: str
    scope_id: str
    auth_ref: str
    out_dir: str
    manifest_path: str
    posture_score: int
    posture_grade: str
    risk_level: str
    finding_count: int
    file_count: int
    total_bytes: int
    body_captured: bool
    body_redacted: bool
    body_truncated: bool
    archive_path: str | None = None
    archive_sha256: str | None = None
    files: list[DumpFileEntry] = field(default_factory=list)
    entity_counts: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "dump_report"
