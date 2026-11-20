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
    assert {"s1shell_remediate", "s1shell_cve_audit", "s1shell_audit_verify"}.issubset(tool_names)
    rem_payload = json.loads(responses[2]["result"]["content"][0]["text"])
    assert rem_payload["selected_stack"] == "nginx"
    assert responses[3]["result"]["isError"] is False
    assert responses[4]["error"]["code"] == -32601
