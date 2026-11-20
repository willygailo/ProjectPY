"""Unit tests for scope governance, normalization, expiry, and DNS anti-escape checks."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from s1shell.errors import OutOfScopeError, ValidationError
from s1shell.scope import ScopeManager, parse_target


def test_parse_target_normalizes_urls_domains_and_ips() -> None:
    d = parse_target("EXAMPLE.COM.")
    assert d.host == "example.com"
    assert not d.is_ip
    assert d.to_url() == "https://example.com/"

    v6 = parse_target("2001:db8::1")
    assert v6.is_ip
    assert v6.host == "2001:db8::1"
    assert v6.to_url() == "https://[2001:db8::1]/"

    u = parse_target("http://App.Example.com:8080/v1/health")
    assert u.scheme == "http"
    assert u.host == "app.example.com"
    assert u.port == 8080
    assert u.path == "/v1/health"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        "javascript:alert(1)",
        "ftp://example.com",
        "https://user:pass@example.com",
        "https://[fe80::1%eth0]/",
        "bad host.com",
    ],
)
def test_parse_target_rejects_invalid_inputs(bad: str) -> None:
    with pytest.raises(ValidationError):
        parse_target(bad)


def test_scope_add_list_subdomain_and_exact_matching(scope_manager: ScopeManager) -> None:
    scope_manager.add(
        "example.com",
        owner="ACME IT",
        auth_ref="SOW-2026-014",
        expires="2099-12-31",
        include_subdomains=False,
    )
    assert scope_manager.check_target("https://example.com").in_scope is True
    assert scope_manager.check_target("https://app.example.com").in_scope is False

    scope_manager.add(
        "*.corp.example",
        owner="ACME IT",
        auth_ref="SOW-2026-015",
        expires="2099-12-31",
    )
    res = scope_manager.check_target("https://portal.corp.example/login")
    assert res.in_scope is True
    assert res.pinned_ip == "93.184.216.34"


def test_scope_ip_cidr_and_url_prefix_matching(scope_manager: ScopeManager) -> None:
    scope_manager.add("203.0.113.0/24", owner="NetOps", auth_ref="CHG-1", expires="2099-12-31")
    scope_manager.add(
        "https://app.example.com/api",
        owner="AppSec",
        auth_ref="CHG-2",
        expires="2099-12-31",
    )

    assert scope_manager.check_target("203.0.113.42").in_scope is True
    assert scope_manager.check_target("203.0.114.42").in_scope is False
    assert scope_manager.check_target("https://app.example.com/api/v1").in_scope is True
    assert scope_manager.check_target("https://app.example.com/apiv1").in_scope is False
    assert scope_manager.check_target("http://app.example.com/api").in_scope is False


def test_scope_rejects_expired_entries_and_prunes(scope_manager: ScopeManager) -> None:
    scope_manager.add(
        "expired.example",
        owner="Old",
        auth_ref="SOW-OLD",
        expires="2020-01-01",
    )
    check_now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    res = scope_manager.check_target("https://expired.example", now=check_now)
    assert res.in_scope is False
    assert "expired" in res.reason.lower()

    expired = scope_manager.expire(prune=True, now=check_now)
    assert len(expired) == 1
    assert scope_manager.load() == []


def test_scope_blocks_dns_rebinding_to_private_or_metadata_ips(tmp_path: Path) -> None:
    def rebinding_resolver(host: str) -> list[str]:
        if host == "metadata.example.com":
            return ["169.254.169.254"]
        if host == "evil.example.com":
            return ["127.0.0.1"]
        return ["10.1.2.3"]

    mgr = ScopeManager(tmp_path / "scope.yaml", resolver=rebinding_resolver)
    mgr.add(
        "example.com",
        include_subdomains=True,
        owner="ACME",
        auth_ref="SOW-1",
        expires="2099-12-31",
    )

    for target in (
        "https://evil.example.com",
        "https://metadata.example.com",
        "https://internal.example.com",
    ):
        res = mgr.check_target(target)
        assert res.in_scope is False
        assert "special/private ip" in res.reason.lower()

    # Explicitly adding 127.0.0.1 allows authorized local testing
    mgr.add("127.0.0.1", owner="Local Lab", auth_ref="LAB-1", expires="2099-12-31")
    assert mgr.check_target("https://evil.example.com").in_scope is True


def test_scope_fails_closed_on_dns_failure(tmp_path: Path) -> None:
    def failing_resolver(_host: str) -> list[str]:
        raise OutOfScopeError("DNS lookup failed")

    mgr = ScopeManager(tmp_path / "scope.yaml", resolver=failing_resolver)
    mgr.add("example.com", owner="ACME", auth_ref="SOW-1", expires="2099-12-31")
    res = mgr.check_target("https://example.com")
    assert res.in_scope is False
    assert "failed" in res.reason.lower()


def test_scope_specificity_duplicate_replace_and_mixed_case_remove(
    scope_manager: ScopeManager,
) -> None:
    scope_manager.add(
        "*.example.com",
        owner="ACME",
        auth_ref="WILDCARD-REF",
        expires="2099-12-31",
    )
    scope_manager.add(
        "https://app.example.com/API",
        owner="ACME",
        auth_ref="PREFIX-REF",
        expires="2099-12-31",
    )

    res = scope_manager.check_target("https://app.example.com/API/v1")
    assert res.in_scope is True
    assert res.matched_entry is not None
    assert res.matched_entry.auth_ref == "PREFIX-REF"

    with pytest.raises(ValidationError, match="already exists"):
        scope_manager.add(
            "https://app.example.com/API",
            owner="ACME",
            auth_ref="DUP-REF",
            expires="2099-12-31",
        )

    replaced = scope_manager.add(
        "https://app.example.com/API",
        owner="ACME",
        auth_ref="NEW-REF",
        expires="2099-12-31",
        replace=True,
    )
    assert replaced.auth_ref == "NEW-REF"

    removed = scope_manager.remove("https://app.example.com/API")
    assert len(removed) == 1
    assert removed[0].auth_ref == "NEW-REF"


def test_scope_blocks_cgnat_nat64_and_ipv4_mapped_exclusion_bypass(tmp_path: Path) -> None:
    import stat

    resolved_map = {
        "cgnat.example.com": ["100.64.0.1"],
        "alibaba-meta.example.com": ["100.100.100.200"],
        "nat64.example.com": ["64:ff9b::127.0.0.1"],
        "mapped-meta.example.com": ["::ffff:169.254.169.254"],
        "mapped-excluded.example.com": ["::ffff:93.184.216.34"],
        "ok.example.com": ["93.184.216.35"],
    }

    mgr = ScopeManager(
        tmp_path / "scope.yaml",
        resolver=lambda host: resolved_map[host],
    )
    mgr.add(
        "*.example.com",
        owner="ACME",
        auth_ref="SOW-SEC-1",
        expires="2099-12-31",
    )
    mgr.add(
        "93.184.216.34",
        owner="ACME",
        auth_ref="SOW-SEC-1",
        expires="2099-12-31",
        exclude=True,
    )

    # Atomic private write leaves 0600 permissions and no temporary siblings
    assert stat.S_IMODE(mgr.scope_file.stat().st_mode) == 0o600
    assert list(tmp_path.glob("*.tmp")) == []

    # CGNAT / Tailscale / cloud metadata / NAT64 / IPv4-mapped private IPs fail closed
    for host in (
        "https://cgnat.example.com",
        "https://alibaba-meta.example.com",
        "https://nat64.example.com",
        "https://mapped-meta.example.com",
    ):
        res = mgr.check_target(host)
        assert res.in_scope is False
        assert "special/private ip" in res.reason.lower()

    # IPv4-mapped IPv6 cannot bypass IPv4 --exclude (either via DNS or direct IP target)
    dns_excl = mgr.check_target("https://mapped-excluded.example.com")
    assert dns_excl.in_scope is False
    assert "excluded" in dns_excl.reason.lower()

    mgr.add("::ffff:93.184.216.0/120", owner="ACME", auth_ref="SOW-SEC-1", expires="2099-12-31")
    direct_excl = mgr.check_target("::ffff:93.184.216.34")
    assert direct_excl.in_scope is False
    assert "excluded" in direct_excl.reason.lower()

    # Explicitly authorizing CGNAT IP/CIDR allows intentional private-overlay assessment
    mgr.add("100.64.0.0/10", owner="Tailnet", auth_ref="LAB-2", expires="2099-12-31")
    assert mgr.check_target("https://cgnat.example.com").in_scope is True
    assert mgr.check_target("https://ok.example.com").in_scope is True
