"""DNS record and passive DNS security hygiene lookup module using dnspython."""

from __future__ import annotations

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
)


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
    """Query A/AAAA/CNAME and optional passive security records (CAA, SPF, DMARC, DNSSEC)."""
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
    caa_records, _ = _safe_resolve(client, host, "CAA", timeout, sec_errors)
    txt_raw, _ = _safe_resolve(client, host, "TXT", timeout, sec_errors)
    txt_clean = [_unquote_txt(r) for r in txt_raw]
    spf = next((t for t in txt_clean if t.lower().startswith("v=spf1")), None)

    dmarc_raw, _ = _safe_resolve(client, f"_dmarc.{host}", "TXT", timeout, sec_errors)
    dmarc_clean = [_unquote_txt(r) for r in dmarc_raw]
    dmarc = next((t for t in dmarc_clean if t.lower().startswith("v=dmarc1")), None)

    ds_records, _ = _safe_resolve(client, host, "DS", timeout, sec_errors)
    dnskey_records, _ = _safe_resolve(client, host, "DNSKEY", timeout, sec_errors)
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
        caa=caa_records,
        txt=txt_clean,
        spf=spf,
        dmarc=dmarc,
        dnssec_present=dnssec_present,
        dangling_cnames=dangling_cnames,
        security_checked=True,
        security_errors=sec_errors,
    )
