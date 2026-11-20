"""Canonical dataclasses for `s1shell profile` output."""

from __future__ import annotations

from dataclasses import dataclass, field

from s1shell import __version__
from s1shell.models import SCHEMA_VERSION, utc_now_iso


@dataclass(frozen=True)
class DNSRecords:
    """DNS records and optional passive DNS security posture collected for a domain target."""

    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    cname: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    caa: list[str] = field(default_factory=list)
    txt: list[str] = field(default_factory=list)
    spf: str | None = None
    dmarc: str | None = None
    dnssec_present: bool | None = None
    dangling_cnames: list[str] = field(default_factory=list)
    security_checked: bool = False
    security_errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class TLSResult:
    """TLS handshake, cipher hygiene, and X.509 certificate inspection details."""

    applicable: bool
    negotiated_version: str | None = None
    cipher_suite: str | None = None
    supported_versions: list[str] = field(default_factory=list)
    verified: bool = False
    verification_error: str | None = None
    subject: str | None = None
    issuer: str | None = None
    sans: list[str] = field(default_factory=list)
    not_before: str | None = None
    not_after: str | None = None
    days_remaining: int | None = None
    key_type: str | None = None
    key_size: int | None = None
    signature_algorithm: str | None = None
    is_self_signed: bool = False
    has_wildcard_san: bool = False
    cert_validity_days: int | None = None
    has_sct: bool | None = None
    cipher_weaknesses: list[str] = field(default_factory=list)
    client_blocked_versions: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ProtocolInfo:
    """HTTP transport protocol and single-response metadata."""

    status_code: int
    http_version: str
    alpn_protocol: str | None = None
    http3_advertised: bool = False
    alt_svc: str | None = None
    redirect_location: str | None = None
    body_truncated: bool = False


@dataclass(frozen=True)
class HeaderFinding:
    """Evaluation of an individual security header."""

    header: str
    present: bool
    value: str | None
    status: str  # ok | missing | weak
    note: str


@dataclass(frozen=True)
class BannerDisclosure:
    """Server or stack version banner observed in HTTP response headers."""

    header: str
    value: str


@dataclass(frozen=True)
class CookieFinding:
    """Security flag assessment for one Set-Cookie header."""

    name: str
    secure: bool
    http_only: bool
    same_site: str | None
    path: str | None = None
    domain: str | None = None
    max_age: int | None = None
    is_session_like: bool = False
    prefix_issues: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class HeaderAnalysis:
    """Aggregated HTTP security header, banner, cookie, CSP, and CORS findings."""

    security_headers: list[HeaderFinding] = field(default_factory=list)
    banner_disclosures: list[BannerDisclosure] = field(default_factory=list)
    cookies: list[CookieFinding] = field(default_factory=list)
    csp_directives: dict[str, list[str]] = field(default_factory=dict)
    csp_report_only: str | None = None
    cors_issues: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class HTMLPassiveAnalysis:
    """Zero-extra-packet passive inspection of an already-received HTML response body."""

    analyzed: bool = False
    title: str | None = None
    meta_generator: str | None = None
    meta_csp: str | None = None
    external_scripts_without_sri: list[str] = field(default_factory=list)
    external_styles_without_sri: list[str] = field(default_factory=list)
    mixed_content_urls: list[str] = field(default_factory=list)
    insecure_forms: list[str] = field(default_factory=list)
    detected_libraries: list[str] = field(default_factory=list)
    framework_hints: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class WellKnownCheck:
    """Opt-in read-only review of `/.well-known/security.txt` and `/robots.txt`."""

    security_txt_present: bool = False
    security_txt_status: int | None = None
    security_txt_contacts: list[str] = field(default_factory=list)
    security_txt_expires: str | None = None
    security_txt_expired: bool = False
    robots_txt_present: bool = False
    robots_txt_status: int | None = None
    robots_disallow_count: int = 0
    robots_sensitive_hints: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ProfileResult:
    """Canonical output envelope for `s1shell profile`."""

    target: str
    url: str
    pinned_ip: str
    scope_id: str
    auth_ref: str
    authorized_via: str
    dns: DNSRecords
    protocol: ProtocolInfo
    tls: TLSResult | None
    headers: HeaderAnalysis
    raw_headers: list[tuple[str, str]] = field(default_factory=list)
    html: HTMLPassiveAnalysis | None = None
    well_known: WellKnownCheck | None = None
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "profile_report"
