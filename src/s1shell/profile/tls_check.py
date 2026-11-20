"""TLS handshake, cipher strength, and deep X.509 certificate inspector."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import socket
import ssl
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, ObjectIdentifier

from s1shell.errors import NetworkError
from s1shell.profile.models import CertChainEntry, TLSResult
from s1shell.tor import open_socks5h_socket

_TLS_FEATURE_OID = ObjectIdentifier("1.3.6.1.5.5.7.1.24")

_ISSUER_CAA_HINTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("let's encrypt", ("letsencrypt.org",)),
    ("lets encrypt", ("letsencrypt.org",)),
    ("digicert", ("digicert.com", "geotrust.com", "thawte.com", "rapidssl.com")),
    ("geotrust", ("digicert.com", "geotrust.com")),
    ("thawte", ("digicert.com", "thawte.com")),
    ("rapidssl", ("digicert.com", "rapidssl.com")),
    ("sectigo", ("sectigo.com", "comodoca.com")),
    ("comodo", ("comodoca.com", "sectigo.com")),
    ("zerossl", ("sectigo.com", "zerossl.com")),
    ("google trust", ("pki.goog",)),
    ("gts ca", ("pki.goog",)),
    ("globalsign", ("globalsign.com",)),
    ("amazon", ("amazon.com", "amazontrust.com", "awstrust.com", "amazonaws.com")),
    ("entrust", ("entrust.net", "entrust.com")),
    ("godaddy", ("godaddy.com", "starfieldtech.com")),
    ("starfield", ("starfieldtech.com", "godaddy.com")),
    ("ssl.com", ("ssl.com",)),
    ("identrust", ("identrust.com",)),
    ("buypass", ("buypass.com",)),
    ("harica", ("harica.gr",)),
    ("actalis", ("actalis.it",)),
    ("certum", ("certum.pl",)),
    ("usertrust", ("sectigo.com", "comodoca.com")),
    ("cloudflare", ("digicert.com", "letsencrypt.org", "pki.goog", "ssl.com", "sectigo.com")),
)


def check_caa_issuer_alignment(caa_records: list[str], issuer: str | None) -> list[str]:
    """Cross-check whether a TLS leaf certificate issuer aligns with DNS CAA `issue` records."""
    if not caa_records or not issuer:
        return []
    allowed_cas: list[str] = []
    deny_all = False
    for rec in caa_records:
        parts = rec.strip().split(None, 2)
        if len(parts) < 3:
            continue
        tag = parts[1].strip().lower()
        val = parts[2].strip().strip('"').strip().lower()
        ca_domain = val.split(";", 1)[0].strip()
        if tag in {"issue", "issuewild"}:
            if ca_domain == ";":
                deny_all = True
            elif ca_domain:
                allowed_cas.append(ca_domain)

    if deny_all and not allowed_cas:
        return [
            'DNS CAA policy contains `issue ";"` (forbids issuance), yet a certificate is served.'
        ]
    if not allowed_cas:
        return []

    issuer_low = issuer.lower()
    expected_domains: tuple[str, ...] | None = None
    for needle, ca_domains in _ISSUER_CAA_HINTS:
        if needle in issuer_low:
            expected_domains = ca_domains
            break

    if expected_domains is None:
        # Unknown/private CA: check if any CAA domain stem appears directly in the issuer DN.
        for ca in allowed_cas:
            stem = ca.split(".")[0]
            if len(stem) >= 4 and stem in issuer_low:
                return []
        return []

    if any(
        any(exp == ca or ca.endswith("." + exp) or exp.endswith("." + ca) for ca in allowed_cas)
        for exp in expected_domains
    ):
        return []

    return [
        f"TLS leaf issuer ({issuer[:80]}) does not match DNS CAA authorized CAs "
        f"({', '.join(sorted(set(allowed_cas))[:5])})."
    ]


def analyze_cert_chain(der_chain: list[bytes]) -> tuple[list[CertChainEntry], list[str]]:
    """Parse DER-encoded TLS cert chain and flag ordering, expiry, or weak-sig issues."""
    entries: list[CertChainEntry] = []
    issues: list[str] = []
    for idx, der in enumerate(der_chain):
        try:
            parsed = _parse_x509_der(der)
        except Exception:
            issues.append(f"Failed to parse X.509 certificate at chain index {idx}.")
            continue
        entries.append(
            CertChainEntry(
                subject=parsed.subject or "unknown",
                issuer=parsed.issuer or "unknown",
                not_after=parsed.not_after,
                days_remaining=parsed.days_remaining,
                key_type=parsed.key_type,
                key_size=parsed.key_size,
                signature_algorithm=parsed.signature_algorithm,
                is_self_signed=parsed.is_self_signed,
            )
        )

    if len(entries) == 1 and not entries[0].is_self_signed:
        issues.append("Server sent only leaf certificate without intermediate CA chain.")

    for idx, cert in enumerate(entries[1:], start=1):
        if cert.days_remaining is not None and cert.days_remaining < 0:
            issues.append(f"Chain certificate #{idx} ({cert.subject[:60]}) is expired.")
        elif cert.days_remaining is not None and cert.days_remaining < 30:
            issues.append(
                f"Chain certificate #{idx} ({cert.subject[:60]}) expires in {cert.days_remaining}d."
            )
        if cert.signature_algorithm in {"md5", "sha1"} and not cert.is_self_signed:
            alg_up = cert.signature_algorithm.upper()
            issues.append(f"Intermediate certificate #{idx} uses weak {alg_up} signature.")

    for idx in range(len(entries) - 1):
        if entries[idx].issuer != entries[idx + 1].subject:
            issues.append(f"Certificate chain order mismatch between position {idx} and {idx + 1}.")
            break

    return entries, issues


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
    has_must_staple: bool | None = None
    serial_number: str | None = None
    sha256_fingerprint: str | None = None
    spki_sha256: str | None = None


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
    """Parse DER-encoded X.509 certificate metadata, SHA-256 fingerprint, and SPKI pin."""
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

    has_must_staple = False
    try:
        tls_feat_ext = cert.extensions.get_extension_for_oid(_TLS_FEATURE_OID)
        feat_val = tls_feat_ext.value
        if isinstance(feat_val, x509.TLSFeature):
            has_must_staple = any(f == x509.TLSFeatureType.status_request for f in feat_val)
    except x509.ExtensionNotFound:
        has_must_staple = False

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

    sha256_fp = cert.fingerprint(hashes.SHA256()).hex()
    spki_der = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    spki_pin = base64.b64encode(hashlib.sha256(spki_der).digest()).decode("ascii")
    serial_hex = format(cert.serial_number, "x")

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
        has_must_staple=has_must_staple,
        serial_number=serial_hex,
        sha256_fingerprint=sha256_fp,
        spki_sha256=spki_pin,
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
    tor_proxy: str | None = None,
) -> tuple[str | None, str | None, str | None, bytes | None, list[bytes]]:
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

    # Python's ssl module validates IP SANs when `server_hostname` is an IP literal and
    # omits the RFC 6066 SNI extension automatically; passing None with check_hostname=True raises.
    server_hostname = host if (verify or not is_ip) else None
    raw_sock = (
        open_socks5h_socket(tor_proxy, target_host=host, target_port=port, timeout=timeout)
        if tor_proxy is not None
        else socket.create_connection((pinned_ip, port), timeout=timeout)
    )
    with (
        raw_sock,
        ctx.wrap_socket(raw_sock, server_hostname=server_hostname) as tls_sock,
    ):
        cipher = tls_sock.cipher()
        cipher_name = cipher[0] if cipher else None
        leaf_der = tls_sock.getpeercert(binary_form=True)
        chain_der: list[bytes] = []
        get_chain_fn = getattr(
            tls_sock, "get_verified_chain" if verify else "get_unverified_chain", None
        )
        if callable(get_chain_fn):
            with contextlib.suppress(Exception):
                raw_chain = get_chain_fn()
                if isinstance(raw_chain, list):
                    chain_der = [bytes(b) for b in raw_chain if isinstance(b, (bytes, bytearray))]
        if not chain_der and leaf_der:
            chain_der = [leaf_der]
        return (
            tls_sock.version(),
            cipher_name,
            tls_sock.selected_alpn_protocol(),
            leaf_der,
            chain_der,
        )


def _probe_tls_versions(
    *,
    host: str,
    pinned_ip: str,
    port: int,
    timeout: float,
    is_ip: bool,
    cafile: str | None,
    tor_proxy: str | None = None,
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
            negotiated, _, _, _, _ = _single_handshake(
                host=host,
                pinned_ip=pinned_ip,
                port=port,
                timeout=timeout,
                is_ip=is_ip,
                cafile=cafile,
                verify=False,
                tls_version=version_enum,
                legacy_probe=is_legacy,
                tor_proxy=tor_proxy,
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
        except (OSError, NetworkError):
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
    tor_proxy: str | None = None,
) -> tuple[TLSResult, str | None]:
    """Perform a single TLS handshake (or optional bounded version checks) and parse X.509 cert."""
    verified = False
    verification_error: str | None = None
    negotiated: str | None = None
    cipher_name: str | None = None
    alpn_proto: str | None = None
    der_bytes: bytes | None = None
    der_chain: list[bytes] = []

    try:
        negotiated, cipher_name, alpn_proto, der_bytes, der_chain = _single_handshake(
            host=host,
            pinned_ip=pinned_ip,
            port=port,
            timeout=timeout,
            is_ip=is_ip,
            cafile=cafile,
            verify=True,
            tor_proxy=tor_proxy,
        )
        verified = True
    except ssl.SSLCertVerificationError as exc:
        verified = False
        verification_error = str(exc)
        try:
            negotiated, cipher_name, alpn_proto, der_bytes, der_chain = _single_handshake(
                host=host,
                pinned_ip=pinned_ip,
                port=port,
                timeout=timeout,
                is_ip=is_ip,
                cafile=cafile,
                verify=False,
                tor_proxy=tor_proxy,
            )
        except (ssl.SSLError, OSError) as inner_exc:
            raise NetworkError(f"TLS handshake failed for '{host}': {inner_exc}") from inner_exc
    except (ssl.SSLError, OSError) as exc:
        raise NetworkError(f"TLS handshake failed for '{host}': {exc}") from exc

    cert_meta = _parse_x509_der(der_bytes) if der_bytes else _ParsedX509()
    chain_entries, chain_issues = analyze_cert_chain(der_chain) if der_chain else ([], [])

    client_blocked: list[str] = []
    if check_versions:
        supported_versions, client_blocked = _probe_tls_versions(
            host=host,
            pinned_ip=pinned_ip,
            port=port,
            timeout=timeout,
            is_ip=is_ip,
            cafile=cafile,
            tor_proxy=tor_proxy,
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
        has_must_staple=cert_meta.has_must_staple,
        serial_number=cert_meta.serial_number,
        sha256_fingerprint=cert_meta.sha256_fingerprint,
        spki_sha256=cert_meta.spki_sha256,
        cipher_weaknesses=cipher_weaknesses,
        client_blocked_versions=client_blocked,
        chain=chain_entries,
        chain_length=len(chain_entries),
        chain_issues=chain_issues,
    )
    return result, alpn_proto
