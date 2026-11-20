"""Canonical dataclasses for passive threat intelligence and GitHub advisory feeds."""

from __future__ import annotations

from dataclasses import dataclass, field

from s1shell import __version__
from s1shell.models import SCHEMA_VERSION, utc_now_iso


@dataclass(frozen=True)
class VirusTotalIntel:
    """Normalized VirusTotal v3 passive domain or IP reputation summary."""

    indicator: str
    indicator_type: str  # domain | ip
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    reputation: int = 0
    as_owner: str | None = None
    country: str | None = None
    categories: list[str] = field(default_factory=list)
    last_analysis_utc: str | None = None
    gui_url: str = ""


@dataclass(frozen=True)
class GreyNoiseIntel:
    """Normalized GreyNoise Community passive IP context (noise vs benign RIOT)."""

    ip: str
    noise: bool = False
    riot: bool = False
    classification: str = "unknown"  # benign | malicious | unknown
    name: str | None = None
    last_seen: str | None = None
    message: str | None = None
    link: str | None = None


@dataclass(frozen=True)
class URLScanEntry:
    """Single historical passive scan record from urlscan.io search index."""

    indexed_at: str
    page_url: str
    status: int | None = None
    server: str | None = None
    ip: str | None = None
    asn: str | None = None
    title: str | None = None
    result_url: str | None = None


@dataclass(frozen=True)
class URLScanSummary:
    """Aggregated passive historical footprint from urlscan.io search API."""

    query: str
    total_results: int = 0
    recent_scans: list[URLScanEntry] = field(default_factory=list)
    observed_ips: list[str] = field(default_factory=list)
    observed_servers: list[str] = field(default_factory=list)
    observed_asns: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class GitHubAdvisory:
    """Normalized GitHub Security Advisory (GHSA) record."""

    ghsa_id: str
    cve_id: str | None
    summary: str
    severity: str
    cvss_score: float | None = None
    cwes: list[str] = field(default_factory=list)
    published_at: str = ""
    html_url: str = ""
    patched_versions: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class CTCertEntry:
    """Single passive Certificate Transparency entry parsed from crt.sh."""

    cert_id: int | None = None
    common_name: str = ""
    san_names: list[str] = field(default_factory=list)
    issuer_name: str = ""
    not_before: str | None = None
    not_after: str | None = None
    expired: bool = False


@dataclass(frozen=True)
class CTLookupResult:
    """Canonical output envelope for `s1shell intel ct <domain>`."""

    domain: str
    cached: bool = False
    total_certificates: int = 0
    unique_subdomains: list[str] = field(default_factory=list)
    wildcard_sans: list[str] = field(default_factory=list)
    issuers: list[str] = field(default_factory=list)
    active_certificates: int = 0
    expired_certificates: int = 0
    recent_certificates: list[CTCertEntry] = field(default_factory=list)
    exported_candidates_file: str | None = None
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "ct_report"


@dataclass(frozen=True)
class RDAPLookupResult:
    """Normalized RFC 7480–7484 RDAP domain or IP/ASN registration record."""

    indicator: str
    indicator_type: str  # domain | ip
    cached: bool = False
    handle: str | None = None
    name: str | None = None
    registrar: str | None = None
    organization: str | None = None
    country: str | None = None
    statuses: list[str] = field(default_factory=list)
    transfer_locked: bool | None = None
    dnssec_signed: bool | None = None
    created_at: str | None = None
    updated_at: str | None = None
    expires_at: str | None = None
    domain_age_days: int | None = None
    days_until_expiry: int | None = None
    nameservers: list[str] = field(default_factory=list)
    cidr: str | None = None
    start_address: str | None = None
    end_address: str | None = None
    abuse_contact: str | None = None
    emails: list[str] = field(default_factory=list)
    phone_numbers: list[str] = field(default_factory=list)
    entities: list[str] = field(default_factory=list)
    source_url: str | None = None
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "rdap_report"


@dataclass(frozen=True)
class IntelLookupResult:
    """Canonical output envelope for `s1shell intel lookup`."""

    indicator: str
    indicator_type: str  # domain | ip
    resolved_ip: str | None = None
    sources_queried: list[str] = field(default_factory=list)
    cached: bool = False
    virustotal: VirusTotalIntel | None = None
    greynoise: GreyNoiseIntel | None = None
    urlscan: URLScanSummary | None = None
    rdap: RDAPLookupResult | None = None
    warnings: list[str] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "intel_report"


@dataclass(frozen=True)
class GitHubAdvisoryResult:
    """Canonical output envelope for `s1shell intel advisory`."""

    query: dict[str, object]
    cached: bool
    advisories: list[GitHubAdvisory] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "ghsa_report"


@dataclass(frozen=True)
class IntelFeedKeyStatus:
    """Masked configuration status for one threat intelligence API feed."""

    feed: str
    env_var: str
    configured: bool
    masked_key: str | None
    source: str
    purpose: str


@dataclass(frozen=True)
class IntelEnvStatus:
    """Canonical output envelope for `s1shell intel env`."""

    env_file: str
    feeds: list[IntelFeedKeyStatus] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "intel_env_status"
