"""Offline localhost TLS handshake & X.509 parsing tests."""

from __future__ import annotations

import ipaddress
import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from s1shell.profile.tls_check import inspect_tls


def _generate_localhost_cert(tmp_path: Path) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "S1shell Test"),
        ]
    )
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
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
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
    return cert_path, key_path


def test_inspect_tls_against_ephemeral_localhost_server(tmp_path: Path) -> None:
    cert_path, key_path = _generate_localhost_cert(tmp_path)

    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    server_ctx.set_alpn_protocols(["http/1.1"])

    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv_sock.bind(("127.0.0.1", 0))
    srv_sock.listen(4)
    port = srv_sock.getsockname()[1]

    stop_event = threading.Event()

    def serve() -> None:
        srv_sock.settimeout(0.2)
        while not stop_event.is_set():
            try:
                conn, _ = srv_sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            try:
                with server_ctx.wrap_socket(conn, server_side=True) as tls_conn:
                    tls_conn.recv(64)
            except OSError:
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        res, alpn = inspect_tls(
            host="localhost",
            pinned_ip="127.0.0.1",
            port=port,
            timeout=3.0,
            cafile=str(cert_path),
            check_versions=True,
        )
        assert res.applicable is True
        assert res.verified is True
        assert res.verification_error is None
        assert alpn == "http/1.1"
        assert "CN=localhost" in (res.subject or "")
        assert "DNS:localhost" in res.sans
        assert res.days_remaining is not None and res.days_remaining >= 28
        assert len(res.supported_versions) >= 1

        # Without cafile, self-signed cert fails trust verification but still extracts cert details
        unverified_res, _ = inspect_tls(
            host="localhost",
            pinned_ip="127.0.0.1",
            port=port,
            timeout=3.0,
        )
        assert unverified_res.verified is False
        assert unverified_res.verification_error is not None
        assert "DNS:localhost" in unverified_res.sans
    finally:
        stop_event.set()
        srv_sock.close()
        thread.join(timeout=2.0)
