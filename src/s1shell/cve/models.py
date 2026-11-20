"""Canonical dataclasses for CVE search, lookup, version bounds, and KEV/EPSS enrichment."""

from __future__ import annotations

from dataclasses import dataclass, field

from s1shell import __version__
from s1shell.models import SCHEMA_VERSION, utc_now_iso


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

    def __post_init__(self) -> None:
        if not self.cve_org_url:
            object.__setattr__(
                self, "cve_org_url", f"https://www.cve.org/CVERecord?id={self.cve_id}"
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
