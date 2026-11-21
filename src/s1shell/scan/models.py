"""Data models for offline secret scanning, IaC/config auditing, and CycloneDX SBOM generation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from s1shell import __version__
from s1shell.models import SCHEMA_VERSION, utc_now_iso


@dataclass(frozen=True)
class SecretFinding:
    """Single redacted secret or credential exposure detected locally."""

    rule_id: str
    title: str
    severity: str
    file_path: str
    line: int
    column: int
    match_redacted: str
    fingerprint: str
    entropy: float
    remediation: str
    context_line: str = ""
    cwe: str = "CWE-798"
    owasp: str = "A02:2021"
    nist: str = "IA-5"


@dataclass(frozen=True)
class SecretScanResult:
    """Canonical result emitted by `s1shell scan secrets`."""

    target_path: str
    scan_mode: str  # filesystem | git-staged | git-diff
    files_scanned: int
    files_skipped: int
    suppressed_count: int
    findings: list[SecretFinding] = field(default_factory=list)
    severity_counts: dict[str, int] = field(default_factory=dict)
    highest_severity: str | None = None
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "secret_scan_report"


@dataclass(frozen=True)
class ConfigFinding:
    """Single defensive IaC or service configuration security finding."""

    rule_id: str
    title: str
    severity: str
    category: str  # dockerfile | kubernetes | github_actions | docker_compose | nginx | env | sshd
    file_path: str
    line: int
    evidence: str
    remediation: str
    fix_snippet: str | None = None
    cwe: str | None = None
    owasp: str | None = None
    nist: str | None = None


@dataclass(frozen=True)
class ConfigScanResult:
    """Canonical result emitted by `s1shell scan config`."""

    target_path: str
    files_scanned: int
    file_types: dict[str, int] = field(default_factory=dict)
    suppressed_count: int = 0
    findings: list[ConfigFinding] = field(default_factory=list)
    severity_counts: dict[str, int] = field(default_factory=dict)
    highest_severity: str | None = None
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "config_scan_report"


@dataclass(frozen=True)
class SBOMGenerateResult:
    """Canonical CycloneDX 1.5 SBOM generation report."""

    target_path: str
    bom_format: str
    spec_version: str
    serial_number: str
    files_scanned: list[str] = field(default_factory=list)
    component_count: int = 0
    ecosystems: dict[str, int] = field(default_factory=dict)
    bom: dict[str, Any] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "sbom_report"
