"""Integration tests for ProfileService using mocked network layers."""

from __future__ import annotations

import ssl
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import httpcore
import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from s1shell.audit import AuditLogger
from s1shell.config import RuntimeConfig
from s1shell.errors import OutOfScopeError, UnauthorizedError
from s1shell.http import PinnedSyncBackend
from s1shell.profile.models import TLSResult
from s1shell.profile.service import ProfileService
from s1shell.scope import ScopeManager


def test_profile_single_request_no_redirects_and_records_alt_svc(
    tmp_config: RuntimeConfig,
    scope_manager: ScopeManager,
    audit_logger: AuditLogger,
) -> None:
    scope_manager.add("example.com", owner="ACME", auth_ref="SOW-1", expires="2099-12-31")
    requests_seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests_seen.append(request)
        return httpx.Response(
            302,
            headers={
                "Location": "https://evil-redirect.example/login",
                "Alt-Svc": 'h3=":443"; ma=86400',
                "Server": "nginx/1.18.0",
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            },
            content=b"redirecting",
        )

    def fake_tls(**_kwargs: object) -> tuple[TLSResult, str | None]:
        return (
            TLSResult(
                applicable=True,
                negotiated_version="TLSv1.3",
                cipher_suite="TLS_AES_256_GCM_SHA384",
                supported_versions=["TLSv1.3"],
                verified=True,
                subject="CN=example.com",
                issuer="CN=Test CA",
                sans=["DNS:example.com"],
                days_remaining=90,
            ),
            "h2",
        )

    svc = ProfileService(
        tmp_config,
        scope_manager=scope_manager,
        audit_logger=audit_logger,
        tls_inspector=fake_tls,
        http_transport=httpx.MockTransport(handler),
    )
    result = svc.profile("https://example.com", authorized=True)

    assert len(requests_seen) == 1
    assert "S1shell/" in requests_seen[0].headers["user-agent"]
    assert result.protocol.status_code == 302
    assert result.protocol.redirect_location == "https://evil-redirect.example/login"
    assert result.protocol.http3_advertised is True
    assert result.protocol.alpn_protocol == "h2"
    assert result.pinned_ip == "93.184.216.34"

    events = audit_logger.read_recent()
    assert len(events) == 1
    assert events[0].outcome == "success"
    assert events[0].auth_ref == "SOW-1"


def test_profile_blocks_out_of_scope_and_unauthorized_with_zero_packets(
    tmp_config: RuntimeConfig,
    scope_manager: ScopeManager,
    audit_logger: AuditLogger,
) -> None:
    calls = [0]

    def handler(_request: httpx.Request) -> httpx.Response:
        calls[0] += 1
        return httpx.Response(200)

    svc = ProfileService(
        tmp_config,
        scope_manager=scope_manager,
        audit_logger=audit_logger,
        http_transport=httpx.MockTransport(handler),
    )

    with pytest.raises(OutOfScopeError):
        svc.profile("https://outside.example.org", authorized=True)

    scope_manager.add("example.com", owner="ACME", auth_ref="SOW-1", expires="2099-12-31")
    with pytest.raises(UnauthorizedError):
        svc.profile("https://example.com", authorized=False)

    assert calls[0] == 0


def test_profile_against_local_http_server_exercises_pinned_transport(tmp_path: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response_only(200, "OK")
            self.send_header("Server", "S1shell-LocalTest/1.0")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, format: str, *args: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        cfg = RuntimeConfig.from_env(home_override=tmp_path / ".s1shell")
        mgr = ScopeManager(cfg.scope_file, resolver=lambda _h: ["127.0.0.1"])
        mgr.add("127.0.0.1", owner="Local Lab", auth_ref="LAB-HTTP", expires="2099-12-31")
        # Also test domain pinned to 127.0.0.1 using explicitly authorized IP
        mgr.add("local.test", owner="Local Lab", auth_ref="LAB-DOM", expires="2099-12-31")

        class OfflineDnsResolver:
            def resolve(self, _qname: str, rdtype: str, lifetime: float = 5.0) -> list[str]:
                return ["127.0.0.1"] if rdtype == "A" else []

        svc = ProfileService(
            cfg,
            scope_manager=mgr,
            audit_logger=AuditLogger(cfg.audit_log),
            dns_resolver=OfflineDnsResolver(),
        )
        res = svc.profile(f"http://local.test:{port}/", authorized=True)
        assert res.protocol.status_code == 200
        assert res.pinned_ip == "127.0.0.1"
        assert res.tls is None
        assert res.dns.a == ["127.0.0.1"]
        assert res.headers.banner_disclosures[0].value == "S1shell-LocalTest/1.0"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def test_pinned_sync_backend_rejects_unpinned_host() -> None:
    backend = PinnedSyncBackend(expected_host="app.example.com", pinned_ip="93.184.216.34")
    with pytest.raises(httpcore.ConnectError, match="Refused unpinned connection"):
        backend.connect_tcp("evil.example.net", 443)


def test_profile_against_local_https_server_verifies_sni_and_pinned_ip(tmp_path: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "local.test")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("local.test")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response_only(200, "OK")
            self.send_header("Server", "nginx/1.24.0")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, format: str, *args: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        cfg = RuntimeConfig.from_env(home_override=tmp_path / ".s1shell")
        mgr = ScopeManager(cfg.scope_file, resolver=lambda _h: ["127.0.0.1"])
        mgr.add("127.0.0.1", owner="Lab", auth_ref="LAB-IP", expires="2099-12-31")
        mgr.add("local.test", owner="Lab", auth_ref="LAB-HTTPS", expires="2099-12-31")

        class OfflineDnsResolver:
            def resolve(self, _qname: str, rdtype: str, lifetime: float = 5.0) -> list[str]:
                return ["127.0.0.1"] if rdtype == "A" else []

        svc = ProfileService(
            cfg,
            scope_manager=mgr,
            audit_logger=AuditLogger(cfg.audit_log),
            dns_resolver=OfflineDnsResolver(),
            cafile=str(cert_path),
        )
        res = svc.profile(f"https://local.test:{port}/", authorized=True)
        assert res.protocol.status_code == 200
        assert res.pinned_ip == "127.0.0.1"
        assert res.tls is not None and res.tls.verified is True
        assert "DNS:local.test" in res.tls.sans
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)
