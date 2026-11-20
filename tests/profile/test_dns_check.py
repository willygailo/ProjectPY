"""Unit tests for DNS record collection."""

from __future__ import annotations

import dns.exception
import dns.resolver

from s1shell.profile.dns_check import collect_dns_records


class FakeResolver:
    """Offline dnspython-compatible mock resolver."""

    def resolve(self, qname: str, rdtype: str, lifetime: float = 5.0) -> list[str]:
        if rdtype == "A":
            return ["93.184.216.34"]
        if rdtype == "AAAA":
            raise dns.resolver.NoAnswer()
        if rdtype == "CNAME":
            return [f"cdn.{qname}"]
        raise dns.exception.Timeout()


def test_collect_dns_records_queries_a_aaaa_cname() -> None:
    res = collect_dns_records("example.com", is_ip=False, resolver=FakeResolver())
    assert res.a == ["93.184.216.34"]
    assert res.aaaa == []
    assert res.cname == ["cdn.example.com"]
    assert res.errors == []


def test_collect_dns_records_skips_ip_targets() -> None:
    res = collect_dns_records("93.184.216.34", is_ip=True, resolver=FakeResolver())
    assert res.a == []
    assert res.aaaa == []
    assert res.cname == []
