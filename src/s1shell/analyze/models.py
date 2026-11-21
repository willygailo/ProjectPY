"""Data models for `s1shell analyze` (CSP3, Email Auth, Offline Headers, CVSS)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from s1shell import __version__
from s1shell.models import SCHEMA_VERSION, utc_now_iso


@dataclass(frozen=True)
class CSPFinding:
    """Single Content-Security-Policy weakness or bypass primitive."""

    id: str
    severity: str
    directive: str
    title: str
    evidence: str
    remediation: str
    cwe: str = "CWE-693"


@dataclass(frozen=True)
class CSPAnalysisResult:
    """Canonical result emitted by `s1shell analyze csp`."""

    raw_policy: str
    source: str
    score: int
    grade: str
    directives: dict[str, list[str]] = field(default_factory=dict)
    duplicate_directives: list[str] = field(default_factory=list)
    unknown_directives: list[str] = field(default_factory=list)
    bypass_hosts: list[str] = field(default_factory=list)
    findings: list[CSPFinding] = field(default_factory=list)
    recommended_policy: str = ""
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "csp_analysis_report"


@dataclass(frozen=True)
class EmailAuthFinding:
    """Single email authentication / anti-spoofing gap."""

    id: str
    severity: str
    protocol: str  # spf | dmarc | dkim | mta-sts | tls-rpt | bimi
    title: str
    evidence: str
    remediation: str
    cwe: str = "CWE-290"


@dataclass(frozen=True)
class EmailAuthAnalysisResult:
    """Canonical result emitted by `s1shell analyze email`."""

    domain: str
    mode: str  # offline | live_dns
    score: int
    grade: str
    spoofing_risk: str  # CRITICAL | HIGH | MODERATE | LOW | MINIMAL
    spf_record: str | None = None
    spf_all_qualifier: str | None = None
    spf_lookup_count: int = 0
    spf_void_lookups: int = 0
    spf_ipv4_blast_radius: int = 0
    dmarc_record: str | None = None
    dmarc_tags: dict[str, str] = field(default_factory=dict)
    dkim_selector: str | None = None
    dkim_record: str | None = None
    dkim_key_type: str | None = None
    dkim_key_bits: int | None = None
    mta_sts_present: bool | None = None
    tls_rpt_present: bool | None = None
    bimi_present: bool | None = None
    findings: list[EmailAuthFinding] = field(default_factory=list)
    recommended_records: list[str] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "email_auth_report"


@dataclass(frozen=True)
class HeaderOfflineResult:
    """Canonical offline HTTP response header, CSP, cookie & fingerprint audit."""

    source: str
    url: str
    status_code: int | None
    http_version: str | None
    preset: str
    score: int
    grade: str
    risk_level: str
    header_count: int
    fingerprints: list[dict[str, Any]] = field(default_factory=list)
    csp_analysis: CSPAnalysisResult | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    remediation_snippets: list[dict[str, Any]] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "header_analysis_report"


@dataclass(frozen=True)
class CVSSMetricDetail:
    """Human-readable breakdown of a single CVSS metric key/value pair."""

    group: str  # base | temporal | environmental | supplemental
    metric: str
    name: str
    code: str
    value_label: str


@dataclass(frozen=True)
class CVSSAnalysisResult:
    """Canonical CVSS vector parse, validation, and scoring breakdown."""

    vector: str
    version: str
    base_score: float | None
    base_severity: str | None
    temporal_score: float | None = None
    temporal_severity: str | None = None
    environmental_score: float | None = None
    environmental_severity: str | None = None
    exploitability_subscore: float | None = None
    impact_subscore: float | None = None
    metrics: list[CVSSMetricDetail] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "cvss_analysis_report"
