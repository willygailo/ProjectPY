"""Automated tests for S1shell's Online Streamable HTTP & Local Stdio MCP server."""

from __future__ import annotations

import io
import json
import threading
from pathlib import Path

import httpx
import pytest

from s1shell.audit import AuditLogger
from s1shell.cli import build_parser, dispatch
from s1shell.config import RuntimeConfig
from s1shell.errors import UnauthorizedError, ValidationError
from s1shell.mcp_server import (
    MCP_PROTOCOL_VERSION,
    S1ShellMCPServer,
    build_mcp_client_config,
    ping_mcp_http,
)


@pytest.fixture
def tmp_config(tmp_path: Path) -> RuntimeConfig:
    home = tmp_path / ".s1shell"
    home.mkdir(parents=True, exist_ok=True)
    return RuntimeConfig.from_env(home_override=home)


def test_mcp_protocol_tools_resources_prompts_and_scoped_opt_in(
    tmp_config: RuntimeConfig,
    tmp_path: Path,
) -> None:
    # Default server: 22 online/offline read-only tools (zero target contact)
    srv = S1ShellMCPServer(tmp_config)
    init = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": MCP_PROTOCOL_VERSION},
        }
    )
    assert init is not None
    assert init["result"]["protocolVersion"] == MCP_PROTOCOL_VERSION
    assert set(init["result"]["capabilities"]) == {"tools", "resources", "prompts"}

    tools_resp = srv.handle_request(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    )
    assert tools_resp is not None
    tool_names = [t["name"] for t in tools_resp["result"]["tools"]]
    assert len(tool_names) == 22
    assert "s1shell_ai_analyze" in tool_names
    assert "s1shell_profile" not in tool_names

    # Disabled target tool fails closed with isError=True
    denied_call = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "s1shell_profile", "arguments": {"target": "https://example.com"}},
        }
    )
    assert denied_call is not None
    assert denied_call["result"]["isError"] is True
    assert "disabled" in denied_call["result"]["content"][0]["text"].lower()

    # Native MCP Resources
    res_list = srv.handle_request(
        {"jsonrpc": "2.0", "id": 4, "method": "resources/list", "params": {}}
    )
    assert res_list is not None
    uris = {r["uri"] for r in res_list["result"]["resources"]}
    assert uris == {
        "s1shell://doctor",
        "s1shell://scope",
        "s1shell://skills",
        "s1shell://audit/recent",
    }
    res_read = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "resources/read",
            "params": {"uri": "s1shell://skills"},
        }
    )
    assert res_read is not None
    skills_payload = json.loads(res_read["result"]["contents"][0]["text"])
    assert len(skills_payload["skills"]) == 9

    # Native MCP Prompts (all 9 defensive AI skills + optional artifact context injection)
    prm_list = srv.handle_request(
        {"jsonrpc": "2.0", "id": 6, "method": "prompts/list", "params": {}}
    )
    assert prm_list is not None
    prompt_names = {p["name"] for p in prm_list["result"]["prompts"]}
    assert "attack-path-modeling" in prompt_names
    assert len(prompt_names) == 9

    sample_assess = tmp_path / "assess.json"
    sample_assess.write_text(
        json.dumps(
            {
                "artifact_type": "assess_report",
                "target": "https://portal.internal.local",
                "findings": [{"id": "HDR-HSTS", "severity": "MEDIUM"}],
            }
        ),
        encoding="utf-8",
    )
    prm_get = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "prompts/get",
            "params": {
                "name": "attack-path-modeling",
                "arguments": {"input_path": str(sample_assess), "focus": "Prioritize fixes"},
            },
        }
    )
    assert prm_get is not None
    prompt_text = prm_get["result"]["messages"][0]["content"]["text"]
    assert "Prioritize fixes" in prompt_text
    assert "portal.internal.local" not in prompt_text  # auto-redacted

    # Opt-in scoped targets without `--authorized` fails closed immediately
    with pytest.raises(UnauthorizedError):
        S1ShellMCPServer(tmp_config, allow_scoped_targets=True, authorized=False)

    # Opt-in scoped targets WITH `--authorized` exposes 25 tools and STILL enforces scope.yaml
    scoped_srv = S1ShellMCPServer(tmp_config, allow_scoped_targets=True, authorized=True)
    scoped_tools = scoped_srv.handle_request(
        {"jsonrpc": "2.0", "id": 8, "method": "tools/list", "params": {}}
    )
    assert scoped_tools is not None
    scoped_names = {t["name"] for t in scoped_tools["result"]["tools"]}
    assert len(scoped_names) == 25
    assert {"s1shell_profile", "s1shell_fingerprint", "s1shell_assess"} <= scoped_names

    # Calling s1shell_profile against an out-of-scope target is blocked & audit-logged
    blocked = scoped_srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {"name": "s1shell_profile", "arguments": {"target": "https://127.0.0.1"}},
        }
    )
    assert blocked is not None
    assert blocked["result"]["isError"] is True
    events = AuditLogger(tmp_config.audit_log).read_recent(limit=5)
    assert any(ev.outcome == "blocked_out_of_scope" for ev in events)


def test_mcp_streamable_http_server_auth_origin_ping_and_cli_config(
    tmp_config: RuntimeConfig,
) -> None:
    srv = S1ShellMCPServer(tmp_config)

    # Non-loopback bind without Bearer token fails closed
    with pytest.raises(ValidationError, match="non-loopback"):
        srv.create_http_server(host="0.0.0.0", port=0, auth_token=None)  # noqa: S104

    secret_token = "s1shell-test-bearer-token-999"  # noqa: S105
    httpd = srv.create_http_server(
        host="127.0.0.1",
        port=0,
        auth_token=secret_token,
        allowed_origins=["https://trusted-ide.example"],
    )
    port = httpd.server_address[1]
    base_url = f"http://127.0.0.1:{port}"
    mcp_url = f"{base_url}/mcp"

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        with httpx.Client(trust_env=False, timeout=5.0) as local_http:
            # 1. GET /healthz reports online server metadata
            health = local_http.get(f"{base_url}/healthz")
            assert health.status_code == 200
            hdata = health.json()
            assert hdata["status"] == "ok"
            assert hdata["transport"] == "streamable-http"
            assert hdata["tools_count"] == 22
            assert hdata["auth_required"] is True

            # 2. Missing / invalid Bearer token -> 401 Unauthorized
            unauth = local_http.post(
                mcp_url,
                json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            )
            assert unauth.status_code == 401

            # 3. Evil Origin header -> 403 Forbidden (DNS-rebinding protection)
            evil_origin = local_http.post(
                mcp_url,
                headers={
                    "Authorization": f"Bearer {secret_token}",
                    "Origin": "https://evil-rebinding.example",
                },
                json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            )
            assert evil_origin.status_code == 403

            # 4. Allowlisted Origin + valid Bearer token -> 200 OK with Mcp-Session-Id
            ok_resp = local_http.post(
                mcp_url,
                headers={
                    "Authorization": f"Bearer {secret_token}",
                    "Origin": "https://trusted-ide.example",
                },
                json={
                    "jsonrpc": "2.0",
                    "id": 10,
                    "method": "tools/call",
                    "params": {"name": "s1shell_doctor", "arguments": {}},
                },
            )
            assert ok_resp.status_code == 200
            assert "Mcp-Session-Id" in ok_resp.headers
            assert ok_resp.json()["result"]["isError"] is False

            # 5. Notification returns 202 Accepted
            notif = local_http.post(
                mcp_url,
                headers={"Authorization": f"Bearer {secret_token}"},
                json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            )
            assert notif.status_code == 202

        # 6. `ping_mcp_http` + CLI `s1shell mcp ping` succeed against live HTTP server
        ping_data = ping_mcp_http(mcp_url, token=secret_token)
        assert ping_data["healthy"] is True
        assert ping_data["tools_count"] == 22
        assert ping_data["resources_count"] == 4
        assert ping_data["prompts_count"] == 9
        assert ping_data["auth_used"] is True

        parser = build_parser()
        out_ping = io.StringIO()
        rc_ping = dispatch(
            parser.parse_args(
                [
                    "--home",
                    str(tmp_config.home_dir),
                    "--format",
                    "json",
                    "mcp",
                    "ping",
                    "--url",
                    mcp_url,
                    "--token",
                    secret_token,
                ]
            ),
            stdout=out_ping,
            stderr=io.StringIO(),
        )
        assert rc_ping == 0
        assert json.loads(out_ping.getvalue())["healthy"] is True
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=3.0)

    # 7. `build_mcp_client_config` & CLI `s1shell mcp config`
    vs_http = build_mcp_client_config("vscode", transport="http", url=mcp_url, token=secret_token)
    assert vs_http["servers"]["s1shell"]["type"] == "http"
    assert vs_http["servers"]["s1shell"]["headers"]["Authorization"] == f"Bearer {secret_token}"

    ws_http = build_mcp_client_config("windsurf", transport="http", url=mcp_url, token=secret_token)
    assert ws_http["mcpServers"]["s1shell"]["serverUrl"] == mcp_url

    stdio_cfg = build_mcp_client_config("antigravity", transport="stdio", allow_scoped_targets=True)
    assert stdio_cfg["mcpServers"]["s1shell"]["args"] == [
        "mcp",
        "serve",
        "--allow-scoped-targets",
        "--authorized",
    ]

    parser = build_parser()
    out_cfg = io.StringIO()
    rc_cfg = dispatch(
        parser.parse_args(
            [
                "--home",
                str(tmp_config.home_dir),
                "mcp",
                "config",
                "antigravity",
                "--transport",
                "http",
                "--url",
                "http://127.0.0.1:8765/mcp",
            ]
        ),
        stdout=out_cfg,
        stderr=io.StringIO(),
    )
    assert rc_cfg == 0
    assert json.loads(out_cfg.getvalue())["mcpServers"]["s1shell"]["url"] == (
        "http://127.0.0.1:8765/mcp"
    )
