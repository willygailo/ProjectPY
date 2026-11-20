"""Canonical dataclasses for `s1shell profile` output."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from s1shell import __version__
from s1shell.models import SCHEMA_VERSION, utc_now_iso


@dataclass(frozen=True)
class CertChainEntry:
    """Single X.509 certificate entry within a server's presented TLS chain."""

    subject: str
    issuer: str
    not_after: str | None = None
    days_remaining: int | None = None
    key_type: str | None = None
    key_size: int | None = None
    signature_algorithm: str | None = None
    is_self_signed: bool = False


@dataclass(frozen=True)
class DNSRecords:
    """DNS records and optional passive DNS security posture collected for a domain target."""

    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    cname: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    caa: list[str] = field(default_factory=list)
    txt: list[str] = field(default_factory=list)
    spf: str | None = None
    spf_lookup_count: int | None = None
    spf_recursive_lookups: int | None = None
    spf_void_lookups: int = 0
    spf_issues: list[str] = field(default_factory=list)
    dmarc: str | None = None
    dmarc_policy: str | None = None
    mta_sts: str | None = None
    tls_rpt: str | None = None
    bimi: str | None = None
    tlsa: list[str] = field(default_factory=list)
    dnssec_present: bool | None = None
    dangling_cnames: list[str] = field(default_factory=list)
    apex_domain: str | None = None
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
    has_must_staple: bool | None = None
    serial_number: str | None = None
    sha256_fingerprint: str | None = None
    spki_sha256: str | None = None
    cipher_weaknesses: list[str] = field(default_factory=list)
    client_blocked_versions: list[str] = field(default_factory=list)
    chain: list[CertChainEntry] = field(default_factory=list)
    chain_length: int = 0
    chain_issues: list[str] = field(default_factory=list)


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
    methods_checked: bool = False
    allowed_methods: list[str] = field(default_factory=list)
    risky_methods: list[str] = field(default_factory=list)


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
    """Aggregated HTTP security header, banner, cookie, CSP, CORS, and cache findings."""

    security_headers: list[HeaderFinding] = field(default_factory=list)
    banner_disclosures: list[BannerDisclosure] = field(default_factory=list)
    cookies: list[CookieFinding] = field(default_factory=list)
    csp_directives: dict[str, list[str]] = field(default_factory=dict)
    csp_report_only: str | None = None
    cors_issues: list[str] = field(default_factory=list)
    cache_control: str | None = None
    cache_issues: list[str] = field(default_factory=list)
    debug_headers: list[BannerDisclosure] = field(default_factory=list)


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
    third_party_origins: list[str] = field(default_factory=list)
    inline_script_count: int = 0
    unsafe_blank_links: int = 0
    leaked_secrets: list[dict[str, str]] = field(default_factory=list)
    passive_jwts: list[dict[str, Any]] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    phone_numbers: list[str] = field(default_factory=list)
    exposed_ids_and_keys: list[dict[str, str]] = field(default_factory=list)
    identities_and_names: list[dict[str, str]] = field(default_factory=list)
    social_links: list[str] = field(default_factory=list)
    cloud_and_api_endpoints: list[str] = field(default_factory=list)
    source_maps: list[str] = field(default_factory=list)
    stack_traces: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class WellKnownCheck:
    """Opt-in read-only review of RFC well-known metadata (`security.txt`, OIDC, JWKS, mobile)."""

    security_txt_present: bool = False
    security_txt_status: int | None = None
    security_txt_contacts: list[str] = field(default_factory=list)
    security_txt_expires: str | None = None
    security_txt_expired: bool = False
    security_txt_canonical: str | None = None
    security_txt_encryption: str | None = None
    security_txt_policy: str | None = None
    security_txt_over_http: bool = False
    robots_txt_present: bool = False
    robots_txt_status: int | None = None
    robots_disallow_count: int = 0
    robots_sensitive_hints: list[str] = field(default_factory=list)
    robots_sitemaps: list[str] = field(default_factory=list)
    oidc_present: bool = False
    oidc_issuer: str | None = None
    oidc_issues: list[str] = field(default_factory=list)
    jwks_present: bool = False
    jwks_key_count: int = 0
    jwks_issues: list[str] = field(default_factory=list)
    mobile_trust_files: list[str] = field(default_factory=list)


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
