"""Canonical dataclasses for CVE search, lookup, priority triage, and dependency/SBOM audit."""

from __future__ import annotations

from dataclasses import dataclass, field

from s1shell import __version__
from s1shell.models import SCHEMA_VERSION, utc_now_iso


def compute_cve_priority(
    *,
    in_kev: bool = False,
    epss_score: float | None = None,
    cvss_score: float | None = None,
) -> str:
    """Compute SSVC-inspired remediation priority tier (`P0-IMMEDIATE` .. `P3-MONITOR`)."""
    if in_kev:
        return "P0-IMMEDIATE"
    if (epss_score is not None and epss_score >= 0.5) and (cvss_score is None or cvss_score >= 7.0):
        return "P0-IMMEDIATE"
    if (cvss_score is not None and cvss_score >= 9.0) or (
        epss_score is not None and epss_score >= 0.2
    ):
        return "P1-URGENT"
    if cvss_score is not None and cvss_score >= 7.0:
        return "P2-SCHEDULED"
    return "P3-MONITOR"


@dataclass(frozen=True)
class CVSSMetric:
    """Normalized CVSS score details."""

    version: str
    base_score: float
    severity: str
    vector: str | None = None


@dataclass(frozen=True)
class CPEAffectedRange:
    """Structured NVD CPE criteria and optional vulnerable version range bounds."""

    criteria: str
    vulnerable: bool = True
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None


@dataclass(frozen=True)
class CVERecord:
    """Normalized CVE entry combining NVD, CVE.org, CISA KEV, and FIRST EPSS metadata."""

    cve_id: str
    description: str
    published: str
    last_modified: str
    cvss: CVSSMetric | None
    cpes: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    source: str = "nvd"
    cve_org_url: str = ""
    cpe_ranges: list[CPEAffectedRange] = field(default_factory=list)
    in_kev: bool = False
    kev_due_date: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    version_verified: bool | None = None
    ghsa_id: str | None = None
    ghsa_url: str | None = None
    patched_versions: list[str] = field(default_factory=list)
    priority: str = ""

    def __post_init__(self) -> None:
        if not self.cve_org_url:
            object.__setattr__(
                self, "cve_org_url", f"https://www.cve.org/CVERecord?id={self.cve_id}"
            )
        if not self.priority:
            object.__setattr__(
                self,
                "priority",
                compute_cve_priority(
                    in_kev=self.in_kev,
                    epss_score=self.epss_score,
                    cvss_score=self.cvss.base_score if self.cvss else None,
                ),
            )


@dataclass(frozen=True)
class CVESearchFilter:
    """Query parameters and client-side triage filters."""

    keyword: str | None = None
    cpe: str | None = None
    cve_id: str | None = None
    min_cvss: float | None = None
    severity: str | None = None
    published_after: str | None = None
    published_before: str | None = None
    limit: int = 25
    kev_only: bool = False


@dataclass(frozen=True)
class CVESearchResult:
    """Canonical output envelope for `s1shell cve` commands."""

    query: dict[str, object]
    cached: bool
    records: list[CVERecord]
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "cve_report"


@dataclass(frozen=True)
class DependencyPackage:
    """Single pinned software package parsed from a lockfile or SBOM."""

    ecosystem: str  # PyPI | npm | Go | crates.io | Maven | NuGet | Packagist | RubyGems
    name: str
    version: str
    source_file: str | None = None


@dataclass(frozen=True)
class DependencyVuln:
    """Single vulnerability matched against a lockfile/SBOM package via OSV.dev."""

    package: str
    version: str
    ecosystem: str
    vuln_id: str
    aliases: list[str] = field(default_factory=list)
    cve_id: str | None = None
    severity: str = "MEDIUM"
    cvss_score: float | None = None
    summary: str = ""
    fixed_versions: list[str] = field(default_factory=list)
    in_kev: bool = False
    kev_due_date: str | None = None
    epss_score: float | None = None
    priority: str = "P3-MONITOR"
    references: list[str] = field(default_factory=list)
    source_file: str | None = None


@dataclass(frozen=True)
class DependencyAuditResult:
    """Canonical output envelope for `s1shell cve audit <lockfile-sbom-or-dir>`."""

    source_file: str
    format_detected: str
    packages_scanned: int
    vulnerable_packages: int
    cached: bool
    vulnerabilities: list[DependencyVuln] = field(default_factory=list)
    source_files: list[str] = field(default_factory=list)
    upgrade_commands: list[str] = field(default_factory=list)
    unpatched_count: int = 0
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "dependency_audit_report"
