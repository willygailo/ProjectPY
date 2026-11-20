"""TLS handshake, cipher strength, and deep X.509 certificate inspector."""

from __future__ import annotations

import contextlib
import socket
import ssl
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID

from s1shell.errors import NetworkError
from s1shell.profile.models import TLSResult


@dataclass(frozen=True)
class _ParsedX509:
    subject: str | None = None
    issuer: str | None = None
    sans: list[str] = field(default_factory=list)
    not_before: str | None = None
    not_after: str | None = None
    days_remaining: int | None = None
    key_type: str | None = None
    key_size: int | None = None
    signature_algorithm: str | None = None
    is_self_signed: bool = False
    has_wildcard_san: bool = False
    cert_validity_days: int | None = None
    has_sct: bool | None = None


def analyze_cipher_suite(
    cipher_suite: str | None,
    negotiated_version: str | None = None,
) -> list[str]:
    """Identify cryptographic weaknesses in a negotiated TLS cipher suite name."""
    if not cipher_suite:
        return []
    upper = cipher_suite.upper()
    weaknesses: list[str] = []

    if "NULL" in upper:
        weaknesses.append("NULL encryption (no confidentiality)")
    if "EXPORT" in upper or "EXP-" in upper:
        weaknesses.append("EXPORT-grade weak cipher")
    if "ADH" in upper or "AECDH" in upper or "ANON" in upper:
        weaknesses.append("Anonymous key exchange (no authentication)")
    if "RC4" in upper:
        weaknesses.append("Deprecated RC4 stream cipher")
    if "3DES" in upper or "DES-CBC3" in upper or "-DES-" in upper:
        weaknesses.append("Deprecated DES/3DES cipher (Sweet32 risk)")
    if upper.endswith("-MD5") or "_MD5" in upper:
        weaknesses.append("Weak MD5 MAC")

    is_tls13 = (negotiated_version or "").upper() in {"TLSV1.3", "TLS1.3"} or upper.startswith(
        "TLS_"
    )
    if not is_tls13:
        if "CBC" in upper:
            weaknesses.append("Non-AEAD CBC mode cipher (prefer GCM or ChaCha20-Poly1305)")
        if upper.endswith("-SHA") or upper.endswith("_SHA"):
            weaknesses.append("Legacy SHA-1 MAC")
        if "ECDHE" not in upper and "DHE" not in upper:
            weaknesses.append("No Forward Secrecy (lacks ECDHE/DHE key exchange)")

    return weaknesses


def _extract_public_key_info(cert: x509.Certificate) -> tuple[str | None, int | None]:
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"EC({pub.curve.name})", pub.key_size
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448", 448
    if isinstance(pub, dsa.DSAPublicKey):
        return "DSA", pub.key_size
    return type(pub).__name__, None


def _parse_x509_der(der_bytes: bytes) -> _ParsedX509:
    """Parse DER-encoded X.509 certificate metadata using cryptography."""
    cert = x509.load_der_x509_certificate(der_bytes)
    sans: list[str] = []
    has_wildcard = False
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_val = san_ext.value
        if isinstance(san_val, x509.SubjectAlternativeName):
            for name in san_val:
                if isinstance(name, x509.DNSName):
                    sans.append(f"DNS:{name.value}")
                    if name.value.startswith("*."):
                        has_wildcard = True
                elif isinstance(name, x509.IPAddress):
                    sans.append(f"IP:{name.value}")
                else:
                    sans.append(str(name.value))
    except x509.ExtensionNotFound:
        pass

    has_sct = False
    try:
        cert.extensions.get_extension_for_oid(ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
        has_sct = True
    except x509.ExtensionNotFound:
        has_sct = False

    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    now = datetime.now(timezone.utc)
    days_remaining = (not_after - now).days
    validity_days = (not_after - not_before).days

    key_type, key_size = _extract_public_key_info(cert)
    sig_hash = cert.signature_hash_algorithm
    sig_alg = sig_hash.name.lower() if sig_hash is not None else "unknown"
    subject_str = cert.subject.rfc4514_string()
    issuer_str = cert.issuer.rfc4514_string()
    is_self_signed = subject_str == issuer_str

    return _ParsedX509(
        subject=subject_str,
        issuer=issuer_str,
        sans=sans,
        not_before=not_before.isoformat().replace("+00:00", "Z"),
        not_after=not_after.isoformat().replace("+00:00", "Z"),
        days_remaining=days_remaining,
        key_type=key_type,
        key_size=key_size,
        signature_algorithm=sig_alg,
        is_self_signed=is_self_signed,
        has_wildcard_san=has_wildcard,
        cert_validity_days=validity_days,
        has_sct=has_sct,
    )


def _single_handshake(
    *,
    host: str,
    pinned_ip: str,
    port: int,
    timeout: float,
    is_ip: bool,
    cafile: str | None,
    verify: bool,
    tls_version: ssl.TLSVersion | None = None,
    legacy_probe: bool = False,
) -> tuple[str | None, str | None, str | None, bytes | None]:
    ctx = (
        ssl.create_default_context(cafile=cafile)
        if verify
        else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    )
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2", "http/1.1"])

    if legacy_probe:
        # OpenSSL 3.x SECLEVEL=2 blocks TLS 1.0/1.1 client-side before sending ClientHello.
        # Lowering SECLEVEL strictly on this read-only probe context avoids false negatives.
        with contextlib.suppress(ssl.SSLError):
            ctx.set_ciphers("ALL:@SECLEVEL=0")

    if tls_version is not None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = tls_version
            ctx.maximum_version = tls_version

    server_hostname = None if is_ip else host
    with (
        socket.create_connection((pinned_ip, port), timeout=timeout) as raw_sock,
        ctx.wrap_socket(raw_sock, server_hostname=server_hostname) as tls_sock,
    ):
        cipher = tls_sock.cipher()
        cipher_name = cipher[0] if cipher else None
        return (
            tls_sock.version(),
            cipher_name,
            tls_sock.selected_alpn_protocol(),
            tls_sock.getpeercert(binary_form=True),
        )


def _probe_tls_versions(
    *,
    host: str,
    pinned_ip: str,
    port: int,
    timeout: float,
    is_ip: bool,
    cafile: str | None,
) -> tuple[list[str], list[str]]:
    """Probe TLS 1.0–1.3 support and distinguish client-side OpenSSL blocks."""
    candidates = [
        ("TLSv1", getattr(ssl.TLSVersion, "TLSv1", None), True),
        ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None), True),
        ("TLSv1.2", getattr(ssl.TLSVersion, "TLSv1_2", None), False),
        ("TLSv1.3", getattr(ssl.TLSVersion, "TLSv1_3", None), False),
    ]
    supported: list[str] = []
    client_blocked: list[str] = []
    for label, version_enum, is_legacy in candidates:
        if version_enum is None:
            client_blocked.append(label)
            continue
        try:
            negotiated, _, _, _ = _single_handshake(
                host=host,
                pinned_ip=pinned_ip,
                port=port,
                timeout=timeout,
                is_ip=is_ip,
                cafile=cafile,
                verify=False,
                tls_version=version_enum,
                legacy_probe=is_legacy,
            )
            supported.append(negotiated or label)
        except ValueError:
            client_blocked.append(label)
        except ssl.SSLError as exc:
            msg = str(exc).lower()
            if (
                "no protocols available" in msg
                or "no ciphers available" in msg
                or "cipher list" in msg
            ):
                client_blocked.append(label)
            continue
        except OSError:
            continue
    return supported, client_blocked


def inspect_tls(
    *,
    host: str,
    pinned_ip: str,
    port: int,
    timeout: float = 10.0,
    is_ip: bool = False,
    cafile: str | None = None,
    check_versions: bool = False,
) -> tuple[TLSResult, str | None]:
    """Perform a single TLS handshake (or optional bounded version checks) and parse X.509 cert."""
    verified = False
    verification_error: str | None = None
    negotiated: str | None = None
    cipher_name: str | None = None
    alpn_proto: str | None = None
    der_bytes: bytes | None = None

    try:
        negotiated, cipher_name, alpn_proto, der_bytes = _single_handshake(
            host=host,
            pinned_ip=pinned_ip,
            port=port,
            timeout=timeout,
            is_ip=is_ip,
            cafile=cafile,
            verify=True,
        )
        verified = True
    except ssl.SSLCertVerificationError as exc:
        verified = False
        verification_error = str(exc)
        try:
            negotiated, cipher_name, alpn_proto, der_bytes = _single_handshake(
                host=host,
                pinned_ip=pinned_ip,
                port=port,
                timeout=timeout,
                is_ip=is_ip,
                cafile=cafile,
                verify=False,
            )
        except (ssl.SSLError, OSError) as inner_exc:
            raise NetworkError(f"TLS handshake failed for '{host}': {inner_exc}") from inner_exc
    except (ssl.SSLError, OSError) as exc:
        raise NetworkError(f"TLS handshake failed for '{host}': {exc}") from exc

    cert_meta = _parse_x509_der(der_bytes) if der_bytes else _ParsedX509()

    client_blocked: list[str] = []
    if check_versions:
        supported_versions, client_blocked = _probe_tls_versions(
            host=host,
            pinned_ip=pinned_ip,
            port=port,
            timeout=timeout,
            is_ip=is_ip,
            cafile=cafile,
        )
    else:
        supported_versions = [negotiated] if negotiated else []

    cipher_weaknesses = analyze_cipher_suite(cipher_name, negotiated)

    result = TLSResult(
        applicable=True,
        negotiated_version=negotiated,
        cipher_suite=cipher_name,
        supported_versions=supported_versions,
        verified=verified,
        verification_error=verification_error,
        subject=cert_meta.subject,
        issuer=cert_meta.issuer,
        sans=cert_meta.sans,
        not_before=cert_meta.not_before,
        not_after=cert_meta.not_after,
        days_remaining=cert_meta.days_remaining,
        key_type=cert_meta.key_type,
        key_size=cert_meta.key_size,
        signature_algorithm=cert_meta.signature_algorithm,
        is_self_signed=cert_meta.is_self_signed,
        has_wildcard_san=cert_meta.has_wildcard_san,
        cert_validity_days=cert_meta.cert_validity_days,
        has_sct=cert_meta.has_sct,
        cipher_weaknesses=cipher_weaknesses,
        client_blocked_versions=client_blocked,
    )
    return result, alpn_proto
