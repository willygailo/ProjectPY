"""Offline tests for scope exclusions/import, hash-chained audit verify, redaction, and MCP."""

from __future__ import annotations

import io
import json
from pathlib import Path

from s1shell.ai.redact import TelemetryRedactor
from s1shell.audit import AuditEvent, AuditLogger
from s1shell.cli import main
from s1shell.config import RuntimeConfig
from s1shell.mcp_server import S1ShellMCPServer
from s1shell.scope import ScopeManager


def test_scope_exclude_and_bulk_import(tmp_path: Path) -> None:
    mgr = ScopeManager(tmp_path / "scope.yaml", resolver=lambda _h: ["93.184.216.34"])
    scope_txt = tmp_path / "targets.txt"
    scope_txt.write_text(
        "# Engagement targets\n*.example.com\n!billing.example.com\n203.0.113.0/24\n!203.0.113.5\n",
        encoding="utf-8",
    )

    # Dry-run validates without mutating scope.yaml
    dry = mgr.import_targets(
        scope_txt.read_text(encoding="utf-8").splitlines(),
        source=str(scope_txt),
        owner="ACME",
        auth_ref="SOW-2026-99",
        expires="2099-12-31",
        dry_run=True,
    )
    assert len(dry.added) == 4
    assert not dry.errors
    assert mgr.load() == []

    # Actual import writes allow + deny rules
    res = mgr.import_targets(
        scope_txt.read_text(encoding="utf-8").splitlines(),
        source=str(scope_txt),
        owner="ACME",
        auth_ref="SOW-2026-99",
        expires="2099-12-31",
    )
    assert len(res.added) == 4
    assert mgr.check_target("https://app.example.com").in_scope is True
    denied = mgr.check_target("https://billing.example.com")
    assert denied.in_scope is False
    assert "excluded" in denied.reason.lower()
    assert mgr.check_target("203.0.113.10").in_scope is True
    assert mgr.check_target("203.0.113.5").in_scope is False


def test_audit_log_hash_chain_verify_and_tamper_detection(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.log"
    logger = AuditLogger(log_path)
    for tgt in ("https://a.example.com", "https://b.example.com"):
        logger.log(
            AuditEvent.create(
                category="target",
                command="profile",
                target=tgt,
                outcome="success",
                exit_code=0,
            )
        )

    valid = logger.verify()
    assert valid.valid is True
    assert valid.total_entries == 2
    assert valid.chained_entries == 2

    # Tamper with first record -> verification detects broken hash
    tampered = log_path.read_text(encoding="utf-8").replace("a.example.com", "evil.example.com")
    log_path.write_text(tampered, encoding="utf-8")
    broken = logger.verify()
    assert broken.valid is False
    assert broken.errors

    # CLI `audit verify` returns exit 1 on tampered log
    code = main(
        ["--home", str(tmp_path), "audit", "verify", "--format", "json"],
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )
    assert code == 1


def test_telemetry_redactor_reversible_anonymization() -> None:
    red = TelemetryRedactor()
    sample = {
        "url": "https://secret.acme.corp/admin",
        "pinned_ip": "198.51.100.7",
        "scope_id": "abc12345",
        "auth_ref": "SOW-SECRET-1",
        "raw_headers": [
            ["Set-Cookie", "session=SUPER_SECRET_TOKEN; HttpOnly; Secure"],
            ["X-Contact", "admin@acme.corp"],
        ],
    }
    redacted = red.redact_artifact(sample)
    serialized = json.dumps(redacted)
    assert "secret.acme.corp" not in serialized
    assert "198.51.100.7" not in serialized
    assert "SUPER_SECRET_TOKEN" not in serialized
    assert "admin@acme.corp" not in serialized
    assert "[REDACTED_COOKIE_VALUE]" in serialized

    restored = red.restore_text(f"Harden {redacted['url']} ({redacted['pinned_ip']})")
    assert "secret.acme.corp" in restored
    assert "198.51.100.7" in restored


def test_telemetry_redactor_scrubs_ipv6_auth_headers_query_secrets_and_jwt() -> None:
    red = TelemetryRedactor()
    sample_jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    sample = {
        "url": "https://api.acme.corp/callback?access_token=tok_secret_123&sig=deadbeef&page=1",
        "pinned_ip": "2001:db8::42",
        "note": (
            f"Observed IPv6 fe80::1 and Bearer supersecretbearer99 and {sample_jwt} at 12:34:56"
        ),
        "raw_headers": [
            ["Authorization", "Bearer topsecret_auth_token"],
            ["Cookie", "sid=abc123; theme=dark"],
            ["X-Api-Key", "sk-live-9999999999"],
        ],
    }
    redacted = red.redact_artifact(sample)
    serialized = json.dumps(redacted)
    assert "2001:db8::42" not in serialized
    assert "fe80::1" not in serialized
    assert "12:34:56" in serialized  # timestamps must not be mistaken for IPv6
    assert "tok_secret_123" not in serialized
    assert "deadbeef" not in serialized
    assert "page=1" in serialized
    assert "topsecret_auth_token" not in serialized
    assert "abc123" not in serialized
    assert "sk-live-9999999999" not in serialized
    assert "supersecretbearer99" not in serialized
    assert sample_jwt not in serialized
    assert "Bearer [REDACTED_AUTH_HEADER]" in serialized
    assert "[REDACTED_HEADER_VALUE]" in serialized
    assert "[REDACTED_PARAM]" in serialized
    assert "[REDACTED_JWT]" in serialized

    restored = red.restore_text(f"Allow {redacted['pinned_ip']} on {redacted['url']}")
    assert "2001:db8::42" in restored
    assert "api.acme.corp" in restored


def test_readonly_mcp_server_protocol_and_tools(
    tmp_config: RuntimeConfig,
    tmp_path: Path,
) -> None:
    assess_path = tmp_path / "assess.json"
    assess_path.write_text(
        json.dumps(
            {
                "artifact_type": "assess_report",
                "url": "https://app.example.com/",
                "fingerprint": {"matches": [{"product": "nginx"}]},
                "findings": [{"id": "HDR-HSTS"}, {"id": "TLS-004"}],
            }
        ),
        encoding="utf-8",
    )

    srv = S1ShellMCPServer(tmp_config)
    req_lines = "\n".join(
        [
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "s1shell_remediate",
                        "arguments": {"assess_path": str(assess_path), "stack": "auto"},
                    },
                }
            ),
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {"name": "s1shell_audit_verify", "arguments": {}},
                }
            ),
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {"name": "nonexistent_tool", "arguments": {}},
                }
            ),
        ]
    )
    out = io.StringIO()
    assert srv.serve_stdio(stdin=io.StringIO(req_lines + "\n"), stdout=out) == 0
    responses = [json.loads(line) for line in out.getvalue().splitlines() if line.strip()]
    assert len(responses) == 5
    assert responses[0]["result"]["serverInfo"]["name"] == "s1shell-readonly-mcp"
    tool_names = {t["name"] for t in responses[1]["result"]["tools"]}
    assert {
        "s1shell_scope_check",
        "s1shell_remediate",
        "s1shell_cve_audit",
        "s1shell_codec_hash",
        "s1shell_audit_verify",
    }.issubset(tool_names)
    tools_by_name = {t["name"]: t for t in responses[1]["result"]["tools"]}
    assert "recursive" in tools_by_name["s1shell_cve_audit"]["inputSchema"]["properties"]
    assert "cve_ids" in tools_by_name["s1shell_cve_get"]["inputSchema"]["properties"]
    rem_payload = json.loads(responses[2]["result"]["content"][0]["text"])
    assert rem_payload["selected_stack"] == "nginx"
    assert responses[3]["result"]["isError"] is False
    assert responses[4]["error"]["code"] == -32601

    # Verify new read-only `s1shell_scope_check` and `s1shell_codec_hash` MCP tools
    mgr = ScopeManager(tmp_config.scope_file, resolver=lambda _h: ["93.184.216.34"])
    mgr.add("app.example.com", owner="ACME", auth_ref="SOW-1", expires="2099-12-31")
    srv2 = S1ShellMCPServer(tmp_config, scope_manager=mgr)
    sc_resp = srv2.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "s1shell_scope_check",
                "arguments": {"target": "https://app.example.com"},
            },
        }
    )
    assert sc_resp is not None and sc_resp["result"]["isError"] is False
    assert json.loads(sc_resp["result"]["content"][0]["text"])["in_scope"] is True

    ch_resp = srv2.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "s1shell_codec_hash",
                "arguments": {"text": "hello", "algos": ["md5", "sha256"]},
            },
        }
    )
    assert ch_resp is not None and ch_resp["result"]["isError"] is False
    ch_data = json.loads(ch_resp["result"]["content"][0]["text"])
    assert ch_data["hashes"]["md5"] == "5d41402abc4b2a76b9719d911017c592"
