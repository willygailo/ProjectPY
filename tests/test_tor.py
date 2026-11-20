"""Offline automated tests for defensive Tor SOCKS5h routing, DoH-over-Tor, and v3 .onion scope."""

from __future__ import annotations

import io
import json
import socket
import struct
import threading
from pathlib import Path

import dns.resolver
import httpx
import pytest

from s1shell.cli import build_parser, dispatch
from s1shell.config import RuntimeConfig
from s1shell.doctor import run_doctor
from s1shell.errors import NetworkError, ValidationError
from s1shell.http import build_intel_client, build_target_client
from s1shell.mcp_server import S1ShellMCPServer
from s1shell.scope import ScopeManager
from s1shell.tor import (
    TorDoHResolver,
    is_v3_onion_host,
    open_socks5h_socket,
    probe_local_tor_port,
    validate_tor_proxy_url,
    verify_tor_egress,
)

_VALID_V3_ONION = "a" * 56 + ".onion"
_DEPRECATED_V2_ONION = "abcdefghijklmnop.onion"


@pytest.fixture
def tmp_config(tmp_path: Path) -> RuntimeConfig:
    home = tmp_path / ".s1shell"
    home.mkdir(parents=True, exist_ok=True)
    return RuntimeConfig.from_env(home_override=home)


def test_tor_proxy_validation_and_v3_onion_rules() -> None:
    assert validate_tor_proxy_url("socks5h://127.0.0.1:9050") == "socks5h://127.0.0.1:9050"
    assert validate_tor_proxy_url("socks5h://localhost:9150") == "socks5h://localhost:9150"
    assert validate_tor_proxy_url("socks5h://[::1]:9050") == "socks5h://[::1]:9050"

    # Rejects DNS-leaking plain socks5:// and http:// schemes
    with pytest.raises(ValidationError, match="socks5h"):
        validate_tor_proxy_url("socks5://127.0.0.1:9050")
    with pytest.raises(ValidationError, match="socks5h"):
        validate_tor_proxy_url("http://127.0.0.1:8118")

    # Rejects remote non-loopback proxy host
    with pytest.raises(ValidationError, match="loopback"):
        validate_tor_proxy_url("socks5h://198.51.100.10:9050")

    # Strict v3 .onion validation
    assert is_v3_onion_host(_VALID_V3_ONION) is True
    assert is_v3_onion_host(f"portal.{_VALID_V3_ONION}") is True
    assert is_v3_onion_host(_DEPRECATED_V2_ONION) is False
    assert is_v3_onion_host("example.com") is False
    assert is_v3_onion_host("8" * 56 + ".onion") is False  # '8' is invalid base32


def test_socks5h_tunnel_uses_domainname_atyp_and_fails_closed() -> None:
    received: dict[str, object] = {}

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(1)
    proxy_port = server_sock.getsockname()[1]

    def _mock_socks5_server() -> None:
        conn, _ = server_sock.accept()
        with conn:
            greeting = conn.recv(3)
            received["greeting"] = greeting
            conn.sendall(b"\x05\x00")
            req_hdr = conn.recv(5)
            received["ver_cmd_rsv_atyp"] = req_hdr[:4]
            host_len = req_hdr[4]
            host_and_port = conn.recv(host_len + 2)
            received["host"] = host_and_port[:host_len].decode("ascii")
            received["port"] = struct.unpack("!H", host_and_port[host_len:])[0]
            # Reply: VER=5, REP=0 (succeeded), RSV=0, ATYP=1 (IPv4), 0.0.0.0:0
            conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            conn.sendall(b"OK_TUNNEL")

    th = threading.Thread(target=_mock_socks5_server, daemon=True)
    th.start()
    try:
        tunnel = open_socks5h_socket(
            f"socks5h://127.0.0.1:{proxy_port}",
            target_host="www.target.com",
            target_port=443,
            timeout=5.0,
        )
        with tunnel:
            assert tunnel.recv(9) == b"OK_TUNNEL"
    finally:
        th.join(timeout=3.0)
        server_sock.close()

    # Verify RFC 1928 ATYP=0x03 (DOMAINNAME -> zero local DNS leak)
    assert received["greeting"] == b"\x05\x01\x00"
    assert received["ver_cmd_rsv_atyp"] == b"\x05\x01\x00\x03"
    assert received["host"] == "www.target.com"
    assert received["port"] == 443

    # Closed port fails closed with NetworkError (never falls back to direct connection)
    with pytest.raises(NetworkError, match="fail-closed"):
        open_socks5h_socket(
            f"socks5h://127.0.0.1:{proxy_port}",
            target_host="www.target.com",
            target_port=443,
            timeout=1.0,
        )


def test_tor_doh_resolver_scope_anti_ssrf_and_v3_onion_scope(tmp_config: RuntimeConfig) -> None:
    def doh_handler(req: httpx.Request) -> httpx.Response:
        qname = req.url.params.get("name", "")
        qtype = req.url.params.get("type", "").upper()
        if qname == "www.target.com" and qtype == "A":
            return httpx.Response(
                200,
                json={"Status": 0, "Answer": [{"name": qname, "type": 1, "data": "93.184.216.34"}]},
            )
        if qname == "internal-rebind.target.com" and qtype == "A":
            return httpx.Response(
                200,
                json={"Status": 0, "Answer": [{"name": qname, "type": 1, "data": "100.64.10.5"}]},
            )
        if qname == "nx.target.com":
            return httpx.Response(200, json={"Status": 3})
        return httpx.Response(200, json={"Status": 0, "Answer": []})

    doh = TorDoHResolver(
        "socks5h://127.0.0.1:9050",
        transport=httpx.MockTransport(doh_handler),
    )
    assert doh.resolve("www.target.com", "A") == ["93.184.216.34"]
    with pytest.raises(dns.resolver.NXDOMAIN):
        doh.resolve("nx.target.com", "A")

    # ScopeManager under --tor --tor-targets resolves via Tor DoH and STILL blocks CGNAT/private
    mgr_tor = ScopeManager(
        tmp_config.scope_file,
        resolver=doh.resolve_ips,
        tor_enabled=True,
        tor_targets=True,
    )
    mgr_tor.add(
        "target.com",
        include_subdomains=True,
        owner="Target Corp",
        auth_ref="SOW-TOR-1",
        expires="2099-12-31",
    )
    ok_res = mgr_tor.check_target("https://www.target.com")
    assert ok_res.in_scope is True
    assert ok_res.pinned_ip == "93.184.216.34"

    # Even if an explicit IP entry existed, private/CGNAT IP is forbidden under --tor --tor-targets
    rebind_res = mgr_tor.check_target("https://internal-rebind.target.com")
    assert rebind_res.in_scope is False
    assert "private/special" in rebind_res.reason

    # Authorized v3 .onion scope skips DNS completely and requires --tor
    entry = mgr_tor.add(
        _VALID_V3_ONION,
        owner="Onion Org",
        auth_ref="SOW-ONION-1",
        expires="2099-12-31",
    )
    assert entry.type == "onion"

    def _never_call_dns(_host: str) -> list[str]:
        raise AssertionError("Local DNS must NEVER be called for .onion targets!")

    mgr_no_tor = ScopeManager(tmp_config.scope_file, resolver=_never_call_dns, tor_enabled=False)
    blocked_onion = mgr_no_tor.check_target(f"http://{_VALID_V3_ONION}")
    assert blocked_onion.in_scope is False
    assert "--tor" in blocked_onion.reason

    mgr_with_tor = ScopeManager(tmp_config.scope_file, resolver=_never_call_dns, tor_enabled=True)
    ok_onion = mgr_with_tor.check_target(f"http://{_VALID_V3_ONION}")
    assert ok_onion.in_scope is True
    assert ok_onion.pinned_ip == "tor-onion"

    # Deprecated v2 .onion is rejected immediately
    with pytest.raises(ValidationError, match="v3"):
        mgr_with_tor.add(
            _DEPRECATED_V2_ONION,
            owner="Legacy",
            auth_ref="SOW-OLD",
            expires="2099-12-31",
        )


def test_tor_egress_check_http_clients_cli_doctor_and_mcp(tmp_config: RuntimeConfig) -> None:
    # verify_tor_egress succeeds on IsTor=true and fails closed on IsTor=false
    ok_chk = verify_tor_egress(
        "socks5h://127.0.0.1:9050",
        transport=httpx.MockTransport(
            lambda _r: httpx.Response(200, json={"IsTor": True, "IP": "185.220.101.1"})
        ),
    )
    assert ok_chk.is_tor is True
    assert ok_chk.exit_ip == "185.220.101.1"

    with pytest.raises(NetworkError, match="IsTor=false"):
        verify_tor_egress(
            "socks5h://127.0.0.1:9050",
            transport=httpx.MockTransport(
                lambda _r: httpx.Response(200, json={"IsTor": False, "IP": "203.0.113.5"})
            ),
        )

    # build_intel_client / build_target_client configure SOCKS5h & bypass loopback when asked
    tor_cfg = RuntimeConfig.from_env(
        home_override=tmp_config.home_dir,
        tor_enabled=True,
        tor_targets=True,
        tor_proxy="socks5h://127.0.0.1:9050",
    )
    with build_intel_client(tor_cfg) as c_tor:
        assert c_tor is not None
    with build_intel_client(tor_cfg, bypass_tor=True) as c_direct:
        assert c_direct is not None
    with build_target_client(
        tor_cfg,
        expected_host="www.target.com",
        pinned_ip="93.184.216.34",
        tor_proxy=tor_cfg.tor_proxy,
    ) as c_tgt_tor:
        assert c_tgt_tor is not None

    # CLI `--tor-targets` without `--tor` fails closed with ValidationError
    parser = build_parser()
    with pytest.raises(ValidationError, match="--tor-targets"):
        dispatch(
            parser.parse_args(
                ["--home", str(tmp_config.home_dir), "--tor-targets", "tor", "status"]
            ),
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )

    # CLI `s1shell tor status --format json` works offline
    out_stat = io.StringIO()
    rc = dispatch(
        parser.parse_args(
            ["--home", str(tmp_config.home_dir), "--format", "json", "tor", "status"]
        ),
        stdout=out_stat,
        stderr=io.StringIO(),
    )
    assert rc == 0
    stat_data = json.loads(out_stat.getvalue())
    assert stat_data["artifact_type"] == "tor_status_report"
    assert stat_data["configured_proxy"] == "socks5h://127.0.0.1:9050"

    # Doctor & MCP expose Tor readiness cleanly
    doc = run_doctor(tmp_config)
    assert any(c.name == "tor_proxy" for c in doc.checks)

    mcp = S1ShellMCPServer(tmp_config)
    r_tor = mcp.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "s1shell_tor_status", "arguments": {}},
        }
    )
    assert r_tor is not None and r_tor["result"]["isError"] is False
    assert json.loads(r_tor["result"]["content"][0]["text"])["artifact_type"] == "tor_status_report"
    assert probe_local_tor_port("socks5h://127.0.0.1:1").reachable is False
