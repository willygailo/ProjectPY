"""DNS record and passive DNS security hygiene lookup module using dnspython."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Protocol

import dns.exception
import dns.resolver

from s1shell.profile.models import DNSRecords

_TAKEOVER_CLOUD_SUFFIXES = (
    ".github.io",
    ".azurewebsites.net",
    ".cloudapp.azure.com",
    ".herokuapp.com",
    ".s3.amazonaws.com",
    ".s3-website",
    ".cloudfront.net",
    ".pantheonsite.io",
    ".myshopify.com",
    ".fastly.net",
    ".netlify.app",
    ".vercel.app",
    ".pages.dev",
    ".ghost.io",
    ".zendesk.com",
    ".bitbucket.io",
    ".readthedocs.io",
    ".surge.sh",
    ".wpengine.com",
)

_SPF_LOOKUP_TOKEN_RE = re.compile(
    r"^[+\-~?]?(?:include:.+|a(?:[:/].*)?|mx(?:[:/].*)?|ptr(?::.*)?|exists:.+|redirect=.+)$",
    re.IGNORECASE,
)
_DMARC_TAG_RE = re.compile(r"\b([a-z]{1,4})\s*=\s*([^;\s]+)", re.IGNORECASE)
_MULTI_PART_TLDS = {
    "co.uk",
    "org.uk",
    "gov.uk",
    "ac.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.jp",
    "co.nz",
    "com.br",
    "com.sg",
    "com.hk",
    "co.in",
    "co.kr",
    "com.ph",
}


class RecordResolver(Protocol):
    """Protocol for testable DNS record resolvers."""

    def resolve(self, qname: str, rdtype: str, lifetime: float = 5.0) -> list[str]:
        """Resolve DNS records of type `rdtype` for `qname`."""
        ...


class DnspythonResolver:
    """Default dnspython-backed resolver."""

    def __init__(self, timeout: float = 5.0) -> None:
        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout

    def resolve(self, qname: str, rdtype: str, lifetime: float = 5.0) -> list[str]:
        self._resolver.lifetime = lifetime
        answer = self._resolver.resolve(qname, rdtype)
        return [rdata.to_text().rstrip(".") for rdata in answer]


def _unquote_txt(record: str) -> str:
    """Strip RFC 1035 quoted TXT chunk wrappers into a single readable string."""
    parts = [p.strip('"') for p in record.split('" "')]
    return "".join(parts).strip('"').strip()


def count_spf_lookups(spf_record: str) -> int:
    """Count RFC 7208 DNS-querying mechanisms present directly in an SPF TXT record."""
    return sum(1 for tok in spf_record.split() if _SPF_LOOKUP_TOKEN_RE.match(tok))


def parse_dmarc_policy(dmarc_record: str) -> str | None:
    """Extract normalized DMARC policy tag (`none`, `quarantine`, `reject`) if present."""
    for tag, val in _DMARC_TAG_RE.findall(dmarc_record):
        if str(tag).lower() == "p":
            return str(val).strip().lower()
    return None


def _candidate_apex(host: str) -> str | None:
    """Return likely organizational apex domain if `host` is a subdomain, else None."""
    labels = [lbl for lbl in host.lower().rstrip(".").split(".") if lbl]
    if len(labels) <= 2:
        return None
    tail2 = ".".join(labels[-2:])
    if tail2 in _MULTI_PART_TLDS:
        return ".".join(labels[-3:]) if len(labels) > 3 else None
    return tail2


def _safe_resolve(
    client: RecordResolver,
    qname: str,
    rdtype: str,
    timeout: float,
    error_bucket: list[str],
) -> tuple[list[str], bool]:
    """Resolve `(records, is_nxdomain)` without raising."""
    try:
        return client.resolve(qname, rdtype, lifetime=timeout), False
    except dns.resolver.NXDOMAIN:
        return [], True
    except dns.resolver.NoAnswer:
        return [], False
    except dns.exception.DNSException as exc:
        error_bucket.append(f"{qname}/{rdtype}: {exc}")
        return [], False


def collect_dns_records(
    host: str,
    *,
    is_ip: bool,
    timeout: float = 5.0,
    resolver: RecordResolver | None = None,
    factory: Callable[[], RecordResolver] | None = None,
    include_security: bool = False,
) -> DNSRecords:
    """Query A/AAAA/CNAME and optional passive security records (CAA, SPF, DMARC, DNSSEC, MX/NS)."""
    if is_ip:
        return DNSRecords()

    client = (
        resolver
        if resolver is not None
        else (factory() if factory is not None else DnspythonResolver(timeout=timeout))
    )

    records: dict[str, list[str]] = {"A": [], "AAAA": [], "CNAME": []}
    errors: list[str] = []

    for rdtype in ("A", "AAAA", "CNAME"):
        try:
            records[rdtype] = client.resolve(host, rdtype, lifetime=timeout)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            records[rdtype] = []
        except dns.exception.DNSException as exc:
            errors.append(f"{rdtype}: {exc}")

    if not include_security:
        return DNSRecords(
            a=records["A"],
            aaaa=records["AAAA"],
            cname=records["CNAME"],
            errors=errors,
        )

    sec_errors: list[str] = []
    apex = _candidate_apex(host)

    mx_records, _ = _safe_resolve(client, host, "MX", timeout, sec_errors)
    ns_records, _ = _safe_resolve(client, host, "NS", timeout, sec_errors)
    caa_records, _ = _safe_resolve(client, host, "CAA", timeout, sec_errors)
    txt_raw, _ = _safe_resolve(client, host, "TXT", timeout, sec_errors)
    txt_clean = [_unquote_txt(r) for r in txt_raw]
    spf = next((t for t in txt_clean if t.lower().startswith("v=spf1")), None)

    dmarc_raw, _ = _safe_resolve(client, f"_dmarc.{host}", "TXT", timeout, sec_errors)
    dmarc_clean = [_unquote_txt(r) for r in dmarc_raw]
    dmarc = next((t for t in dmarc_clean if t.lower().startswith("v=dmarc1")), None)

    mta_sts_raw, _ = _safe_resolve(client, f"_mta-sts.{host}", "TXT", timeout, sec_errors)
    mta_sts = next(
        (_unquote_txt(r) for r in mta_sts_raw if _unquote_txt(r).lower().startswith("v=stsv1")),
        None,
    )
    tls_rpt_raw, _ = _safe_resolve(client, f"_smtp._tls.{host}", "TXT", timeout, sec_errors)
    tls_rpt = next(
        (_unquote_txt(r) for r in tls_rpt_raw if _unquote_txt(r).lower().startswith("v=tlsrptv1")),
        None,
    )

    ds_records, _ = _safe_resolve(client, host, "DS", timeout, sec_errors)
    dnskey_records, _ = _safe_resolve(client, host, "DNSKEY", timeout, sec_errors)

    # Passive zone-apex fallback (prevents false positives on subdomains when policy lives at apex).
    used_apex: str | None = None
    if apex and apex != host.lower().rstrip("."):
        if not caa_records:
            apex_caa, _ = _safe_resolve(client, apex, "CAA", timeout, sec_errors)
            if apex_caa:
                caa_records = apex_caa
                used_apex = apex
        if dmarc is None:
            apex_dmarc_raw, _ = _safe_resolve(client, f"_dmarc.{apex}", "TXT", timeout, sec_errors)
            apex_dmarc = next(
                (
                    _unquote_txt(r)
                    for r in apex_dmarc_raw
                    if _unquote_txt(r).lower().startswith("v=dmarc1")
                ),
                None,
            )
            if apex_dmarc is not None:
                dmarc = apex_dmarc
                used_apex = apex
        if spf is None:
            apex_txt_raw, _ = _safe_resolve(client, apex, "TXT", timeout, sec_errors)
            apex_spf = next(
                (
                    _unquote_txt(r)
                    for r in apex_txt_raw
                    if _unquote_txt(r).lower().startswith("v=spf1")
                ),
                None,
            )
            if apex_spf is not None:
                spf = apex_spf
                used_apex = apex
        if not (ds_records or dnskey_records):
            apex_ds, _ = _safe_resolve(client, apex, "DS", timeout, sec_errors)
            apex_key, _ = _safe_resolve(client, apex, "DNSKEY", timeout, sec_errors)
            if apex_ds or apex_key:
                ds_records = apex_ds
                dnskey_records = apex_key
                used_apex = apex
        if not ns_records:
            apex_ns, _ = _safe_resolve(client, apex, "NS", timeout, sec_errors)
            if apex_ns:
                ns_records = apex_ns

    dnssec_present: bool | None = None
    if ds_records or dnskey_records:
        dnssec_present = True
    elif not any(e.endswith("DS") or "/DS:" in e or "/DNSKEY:" in e for e in sec_errors):
        dnssec_present = False

    # Passive dangling CNAME check (zero HTTP contact): flag CNAMEs targeting cloud/SaaS
    # hostnames that resolve to NXDOMAIN.
    dangling_cnames: list[str] = []
    for cname_target in records["CNAME"]:
        low_target = cname_target.lower().rstrip(".")
        if any(suf in low_target for suf in _TAKEOVER_CLOUD_SUFFIXES):
            a_vals, a_nx = _safe_resolve(client, low_target, "A", timeout, sec_errors)
            aaaa_vals, aaaa_nx = _safe_resolve(client, low_target, "AAAA", timeout, sec_errors)
            if (a_nx or aaaa_nx) and not a_vals and not aaaa_vals:
                dangling_cnames.append(low_target)

    return DNSRecords(
        a=records["A"],
        aaaa=records["AAAA"],
        cname=records["CNAME"],
        errors=errors,
        mx=mx_records,
        ns=ns_records,
        caa=caa_records,
        txt=txt_clean,
        spf=spf,
        spf_lookup_count=count_spf_lookups(spf) if spf else None,
        dmarc=dmarc,
        dmarc_policy=parse_dmarc_policy(dmarc) if dmarc else None,
        mta_sts=mta_sts,
        tls_rpt=tls_rpt,
        dnssec_present=dnssec_present,
        dangling_cnames=dangling_cnames,
        apex_domain=used_apex,
        security_checked=True,
        security_errors=sec_errors,
    )
