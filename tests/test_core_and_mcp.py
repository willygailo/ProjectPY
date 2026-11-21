"""Core governance, remediation, EOL, ReAct allowlist & MCP JSON-RPC 2.0 tests."""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path

import pytest

from s1shell.ai.investigate import READONLY_INVESTIGATION_TOOLS
from s1shell.assess.remediate import SUPPORTED_STACKS, generate_remediation_plan
from s1shell.audit import AuditEvent, AuditLogger
from s1shell.config import RuntimeConfig
from s1shell.errors import ValidationError
from s1shell.fingerprint.eol import check_product_eol
from s1shell.mcp_server import BASE_TOOLS_SPEC, S1ShellMCPServer, is_origin_allowed
from s1shell.scope import ScopeManager, is_special_ip
from s1shell.tor import is_v3_onion_host, validate_tor_proxy_url


def test_scope_special_ip_ssrf_and_deny_first_exclusions(tmp_path: Path) -> None:
    assert is_special_ip(ipaddress.ip_address("127.0.0.1"))
    assert is_special_ip(ipaddress.ip_address("100.64.0.5"))  # CGNAT
    assert is_special_ip(ipaddress.ip_address("100.100.100.200"))  # Alibaba metadata in CGNAT
    assert is_special_ip(ipaddress.ip_address("169.254.169.254"))  # AWS/GCP/Azure IMDS
    assert is_special_ip(ipaddress.ip_address("::ffff:127.0.0.1"))  # IPv4-mapped IPv6
    assert is_special_ip(ipaddress.ip_address("64:ff9b::10.0.0.1"))  # NAT64
    assert not is_special_ip(ipaddress.ip_address("93.184.216.34"))

    mgr = ScopeManager(tmp_path / "scope.yaml", resolver=lambda _: ["93.184.216.34"])
    mgr.add(
        "*.example.com",
        owner="SecTeam",
        auth_ref="SOW-1",
        expires="2099-12-31",
        include_subdomains=True,
    )
    mgr.add(
        "admin.example.com",
        owner="SecTeam",
        auth_ref="SOW-1",
        expires="2099-12-31",
        exclude=True,
    )

    allowed = mgr.check_target("https://app.example.com")
    assert allowed.in_scope is True
    assert allowed.pinned_ip == "93.184.216.34"

    excluded = mgr.check_target("https://admin.example.com")
    assert excluded.in_scope is False

    mgr_rebind = ScopeManager(tmp_path / "scope.yaml", resolver=lambda _: ["169.254.169.254"])
    rebinding = mgr_rebind.check_target("https://app.example.com")
    assert rebinding.in_scope is False


def test_audit_log_sha256_chain_and_tamper_detection(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.log"
    logger = AuditLogger(log_path)
    logger.log(
        AuditEvent.create(
            category="scope",
            command="scope_add",
            target="example.com",
            outcome="success",
            exit_code=0,
        )
    )
    logger.log(
        AuditEvent.create(
            category="intel", command="scan_secrets", target=".", outcome="success", exit_code=0
        )
    )

    assert logger.verify().valid is True

    # Tamper with line 1 and confirm verification fails
    lines = log_path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["target"] = "evil.example"
    lines[0] = json.dumps(tampered)
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    verify = logger.verify()
    assert verify.valid is False
    assert verify.errors


def test_tor_proxy_and_v3_onion_validation() -> None:
    assert (
        validate_tor_proxy_url("socks5h://127.0.0.1:9050", require_socksio=False)
        == "socks5h://127.0.0.1:9050"
    )
    with pytest.raises(ValidationError):
        validate_tor_proxy_url("socks5://127.0.0.1:9050", require_socksio=False)
    with pytest.raises(ValidationError):
        validate_tor_proxy_url("socks5h://192.168.1.50:9050", require_socksio=False)

    valid_v3 = "a" * 56 + ".onion"
    assert is_v3_onion_host(valid_v3)
    assert not is_v3_onion_host("facebookcorewwwi.onion")  # deprecated v2


def test_remediation_stacks_and_expanded_eol_db() -> None:
    assert "cloudflare" in SUPPORTED_STACKS
    assert "traefik" in SUPPORTED_STACKS

    plan_cf = generate_remediation_plan(
        target_url="https://example.com/",
        findings=[
            {"id": "HDR-HSTS"},
            {"id": "CORS-001"},
            {"id": "OIDC-001"},
            {"id": "LEAK-SECRET"},
        ],
        fingerprint_matches=[{"product": "Cloudflare"}],
        stack="auto",
    )
    assert plan_cf.selected_stack == "cloudflare"
    titles = " ".join(s.title for s in plan_cf.snippets)
    assert "Cloudflare" in titles
    assert "CORS" in titles
    assert "OIDC" in titles
    assert "Leak" in titles

    plan_caddy = generate_remediation_plan(
        target_url="https://example.com/",
        findings=[{"id": "HDR-HSTS-WEAK"}, {"id": "HDR-CSP-UNSAFE"}],
        fingerprint_matches=[],
        stack="caddy",
    )
    assert plan_caddy.snippets and "Strict-Transport-Security" in plan_caddy.snippets[0].config

    eol_status = check_product_eol("PostgreSQL", "12.5")
    assert eol_status is not None
    assert eol_status.is_eol is True


def test_mcp_server_exposes_new_tools_and_enforces_origin_guard(tmp_path: Path) -> None:
    cfg = RuntimeConfig.from_env(home_override=tmp_path / ".s1shell")
    srv = S1ShellMCPServer(cfg)
    assert len(BASE_TOOLS_SPEC) == 30
    assert len(READONLY_INVESTIGATION_TOOLS) == 14

    list_resp = srv.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert list_resp is not None
    names = {t["name"] for t in list_resp["result"]["tools"]}
    assert {
        "s1shell_scan_secrets",
        "s1shell_scan_config",
        "s1shell_scan_sbom",
        "s1shell_analyze_csp",
        "s1shell_analyze_email",
        "s1shell_analyze_headers",
        "s1shell_analyze_cvss",
    } <= names

    call_resp = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "s1shell_analyze_cvss",
                "arguments": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            },
        }
    )
    assert call_resp is not None
    payload = json.loads(call_resp["result"]["content"][0]["text"])
    assert payload["base_score"] == 9.8

    assert is_origin_allowed("http://127.0.0.1:3000", set()) is True
    assert is_origin_allowed("https://evil.example", set()) is False
