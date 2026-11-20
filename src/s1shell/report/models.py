"""Canonical dataclasses for compiled assessment reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from s1shell import __version__
from s1shell.models import SCHEMA_VERSION, utc_now_iso


@dataclass(frozen=True)
class ReportMetadata:
    """Audit and attribution metadata embedded in every generated report."""

    generated_at_utc: str
    operator: str
    tool_version: str
    scope_entries: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class ReportBundle:
    """Combined assessment report payload across profile, fingerprint, cve, posture, and AI."""

    metadata: ReportMetadata
    profiles: list[dict[str, Any]] = field(default_factory=list)
    fingerprints: list[dict[str, Any]] = field(default_factory=list)
    cves: list[dict[str, Any]] = field(default_factory=list)
    intel: list[dict[str, Any]] = field(default_factory=list)
    posture: dict[str, Any] | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    ai_analysis: dict[str, Any] | None = None
    remediation_snippets: list[dict[str, Any]] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "assessment_report"
