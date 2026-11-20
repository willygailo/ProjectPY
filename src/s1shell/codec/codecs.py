"""Pure-Python offline codecs, bounded decompression, SAML/JWT/X.509/hash & magic decode."""

from __future__ import annotations

import base64
import binascii
import codecs
import gzip
import hashlib
import html
import json
import math
import quopri
import re
import urllib.parse
import xml.etree.ElementTree as ET
import zlib
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID

from s1shell.errors import ValidationError

MAX_INPUT_BYTES = 2 * 1024 * 1024  # 2 MiB max input
MAX_DECOMPRESSED_BYTES = 8 * 1024 * 1024  # 8 MiB decompression-bomb cap

SUPPORTED_DECODERS = (
    "auto",
    "base64",
    "base64url",
    "base32",
    "base58",
    "base85",
    "ascii85",
    "hex",
    "url",
    "html",
    "unicode",
    "quoted-printable",
    "rot13",
    "caesar",
    "binary",
    "octal",
    "decimal",
    "morse",
    "punycode",
    "gzip",
    "zlib",
    "deflate",
    "saml",
    "jwt",
)

SUPPORTED_ENCODERS = (
    "base64",
    "base64url",
    "base32",
    "base58",
    "base85",
    "ascii85",
    "hex",
    "hex-escaped",
    "url",
    "url-all",
    "html",
    "unicode",
    "quoted-printable",
    "rot13",
    "caesar",
    "binary",
    "octal",
    "decimal",
    "morse",
    "punycode",
    "gzip",
    "zlib",
    "deflate",
    "gzip-b64",
    "zlib-b64",
)

_CODEC_ALIASES: dict[str, str] = {
    "b64": "base64",
    "b64url": "base64url",
    "b64u": "base64url",
    "b32": "base32",
    "b58": "base58",
    "b85": "base85",
    "a85": "ascii85",
    "base16": "hex",
    "b16": "hex",
    "percent": "url",
    "qp": "quoted-printable",
    "bin": "binary",
    "oct": "octal",
    "dec": "decimal",
    "idna": "punycode",
}

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {ch: idx for idx, ch in enumerate(_B58_ALPHABET)}

_MORSE_TO_CHAR: dict[str, str] = {
    ".-": "A",
    "-...": "B",
    "-.-.": "C",
    "-..": "D",
    ".": "E",
    "..-.": "F",
    "--.": "G",
    "....": "H",
    "..": "I",
    ".---": "J",
    "-.-": "K",
    ".-..": "L",
    "--": "M",
    "-.": "N",
    "---": "O",
    ".--.": "P",
    "--.-": "Q",
    ".-.": "R",
    "...": "S",
    "-": "T",
    "..-": "U",
    "...-": "V",
    ".--": "W",
    "-..-": "X",
    "-.--": "Y",
    "--..": "Z",
    "-----": "0",
    ".----": "1",
    "..---": "2",
    "...--": "3",
    "....-": "4",
    ".....": "5",
    "-....": "6",
    "--...": "7",
    "---..": "8",
    "----.": "9",
    ".-.-.-": ".",
    "--..--": ",",
    "..--..": "?",
    "-..-.": "/",
    "-....-": "-",
    "-.--.": "(",
    "-.--.-": ")",
    ".--.-.": "@",
    "---...": ":",
    "-...-": "=",
    ".-.-.": "+",
    "..--.-": "_",
}
_CHAR_TO_MORSE: dict[str, str] = {v: k for k, v in _MORSE_TO_CHAR.items()}

_JWT_FULL_RE = re.compile(r"^eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*$")
_URL_PCT_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_HTML_ENT_RE = re.compile(r"&(?:#x[0-9A-Fa-f]{1,6}|#\d{1,7}|[A-Za-z]{2,12});")
_UNICODE_ESC_RE = re.compile(r"(?:\\u[0-9A-Fa-f]{4}|\\U[0-9A-Fa-f]{8}|\\x[0-9A-Fa-f]{2})")
_PUNYCODE_RE = re.compile(r"\bxn--[a-z0-9-]{2,}\b", re.IGNORECASE)
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-([1-7])[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_HEX_ONLY_RE = re.compile(r"^[0-9a-fA-F]+$")
_B64_CHARS_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_B64URL_CHARS_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
_B32_CHARS_RE = re.compile(r"^[A-Z2-7]+={0,6}$")
_MORSE_CHARS_RE = re.compile(r"^[.\-/\s|]+$")
_SUPPORTED_HASH_ALGOS = ("md5", "sha1", "sha256", "sha384", "sha512", "blake2b", "crc32")


def normalize_codec_name(name: str) -> str:
    """Resolve short aliases (e.g. `b64`, `base16`, `qp`) into canonical codec names."""
    low = name.strip().lower().replace("_", "-")
    return _CODEC_ALIASES.get(low, low)


def shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy in bits/byte (`0.0` to `8.0`)."""
    if not data:
        return 0.0
    length = len(data)
    counts: dict[int, int] = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    ent = 0.0
    for cnt in counts.values():
        p = cnt / length
        ent -= p * math.log2(p)
    return round(ent, 4)


def _is_mostly_printable_utf8(data: bytes) -> bool:
    if not data:
        return False
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return (printable / len(text)) >= 0.90


def _decompress_bounded(data: bytes, *, wbits: int) -> bytes:
    """Decompress gzip/zlib/deflate safely with an 8 MiB anti-zip-bomb limit."""
    try:
        decomp = zlib.decompressobj(wbits)
        out = decomp.decompress(data, MAX_DECOMPRESSED_BYTES + 1)
        if len(out) > MAX_DECOMPRESSED_BYTES or decomp.unconsumed_tail:
            raise ValidationError(
                f"Decompressed payload exceeds {MAX_DECOMPRESSED_BYTES // (1024 * 1024)} MiB "
                "safety limit."
            )
        tail = decomp.flush(MAX_DECOMPRESSED_BYTES + 1 - len(out))
        combined = out + tail
        if len(combined) > MAX_DECOMPRESSED_BYTES:
            raise ValidationError(
                f"Decompressed payload exceeds {MAX_DECOMPRESSED_BYTES // (1024 * 1024)} MiB "
                "safety limit."
            )
        return combined
    except zlib.error as exc:
        raise ValidationError(f"Decompression failed: {exc}") from exc


def _base58_decode(text: str) -> bytes:
    cleaned = "".join(text.split())
    if not cleaned:
        raise ValidationError("Empty Base58 input.")
    num = 0
    for ch in cleaned:
        val = _B58_INDEX.get(ch)
        if val is None:
            raise ValidationError(f"Invalid Base58 character: {ch!r}")
        num = num * 58 + val
    leading_zeros = len(cleaned) - len(cleaned.lstrip("1"))
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num > 0 else b""
    return (b"\x00" * leading_zeros) + raw


def _base58_encode(data: bytes) -> str:
    if not data:
        return ""
    num = int.from_bytes(data, "big")
    chars: list[str] = []
    while num > 0:
        num, rem = divmod(num, 58)
        chars.append(_B58_ALPHABET[rem])
    leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    return ("1" * leading_zeros) + "".join(reversed(chars))


def _caesar_shift(text: str, shift: int) -> str:
    delta = shift % 26
    out: list[str] = []
    for ch in text:
        code = ord(ch)
        if 65 <= code <= 90:
            out.append(chr(65 + ((code - 65 + delta) % 26)))
        elif 97 <= code <= 122:
            out.append(chr(97 + ((code - 97 + delta) % 26)))
        else:
            out.append(ch)
    return "".join(out)


def caesar_all_shifts(text: str) -> list[dict[str, str]]:
    """Return all 25 Caesar backward-shift candidates for manual inspection."""
    return [{"shift": str(s), "text": _caesar_shift(text, -s)} for s in range(1, 26)]


def _decode_unicode_escapes(text: str) -> str:
    def _repl(match: re.Match[str]) -> str:
        tok = match.group(0)
        try:
            return chr(int(tok[2:], 16))
        except ValueError:
            return tok

    return _UNICODE_ESC_RE.sub(_repl, text)


def _decode_b64_segment(seg: str) -> dict[str, Any] | None:
    padded = seg + "=" * ((4 - len(seg) % 4) % 4)
    try:
        obj = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def decode_jwt_details(token: str) -> dict[str, Any] | None:
    """Decode a JWT offline with UTC timestamps, TTL, and defensive hygiene warnings."""
    cleaned = token.strip()
    if cleaned.lower().startswith("bearer "):
        cleaned = cleaned[7:].strip()
    if not _JWT_FULL_RE.match(cleaned):
        return None
    parts = cleaned.split(".")
    hdr = _decode_b64_segment(parts[0])
    payload = _decode_b64_segment(parts[1])
    if hdr is None or payload is None:
        return None

    alg = str(hdr.get("alg") or "unknown")
    sig_present = bool(parts[2])
    now_ts = datetime.now(timezone.utc).timestamp()
    timestamps: dict[str, str] = {}
    for key in ("iat", "nbf", "exp"):
        val = payload.get(key)
        if isinstance(val, (int, float)) and val > 0:
            dt = datetime.fromtimestamp(float(val), tz=timezone.utc)
            timestamps[key] = dt.isoformat().replace("+00:00", "Z")

    ttl_seconds: int | None = None
    if isinstance(payload.get("exp"), (int, float)) and isinstance(
        payload.get("iat"), (int, float)
    ):
        ttl_seconds = int(float(payload["exp"]) - float(payload["iat"]))

    warnings: list[str] = []
    if alg.lower() == "none" or not sig_present:
        warnings.append("Unsigned token (`alg: none` or empty signature segment).")
    if "exp" not in payload:
        warnings.append("Missing `exp` expiration claim.")
    elif isinstance(payload.get("exp"), (int, float)) and float(payload["exp"]) < now_ts:
        warnings.append("Token is expired (`exp` is in the past).")
    if ttl_seconds is not None and ttl_seconds > 30 * 86400:
        warnings.append(f"Long token lifetime ({ttl_seconds // 86400} days).")
    sens = [k for k in ("password", "secret", "ssn", "api_key", "credit_card") if k in payload]
    if sens:
        warnings.append(f"Sensitive claim key(s) present: {', '.join(sens)}.")

    return {
        "header": hdr,
        "payload": payload,
        "alg": alg,
        "signature_present": sig_present,
        "timestamps_utc": timestamps,
        "ttl_seconds": ttl_seconds,
        "warnings": warnings,
    }


def inspect_x509_pem_or_der(raw: bytes) -> dict[str, Any] | None:
    """Parse an X.509 PEM or DER certificate offline (returns None if not a valid cert)."""
    cert: x509.Certificate | None = None
    stripped = raw.strip()
    if b"-----BEGIN CERTIFICATE-----" in stripped:
        try:
            cert = x509.load_pem_x509_certificate(stripped)
        except Exception:
            return None
    elif stripped.startswith(b"\x30\x82"):
        try:
            cert = x509.load_der_x509_certificate(stripped)
        except Exception:
            return None
    else:
        return None

    sans: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        if isinstance(san_ext.value, x509.SubjectAlternativeName):
            for entry in san_ext.value:
                sans.append(str(entry.value))
    except x509.ExtensionNotFound:
        pass

    pub = cert.public_key()
    key_type = type(pub).__name__
    key_size: int | None = None
    if isinstance(pub, rsa.RSAPublicKey):
        key_type, key_size = "RSA", pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        key_type, key_size = f"EC({pub.curve.name})", pub.key_size
    elif isinstance(pub, ed25519.Ed25519PublicKey):
        key_type, key_size = "Ed25519", 256
    elif isinstance(pub, ed448.Ed448PublicKey):
        key_type, key_size = "Ed448", 448
    elif isinstance(pub, dsa.DSAPublicKey):
        key_type, key_size = "DSA", pub.key_size

    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    days_rem = (not_after - datetime.now(timezone.utc)).days
    sig_alg = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
    sha256_fp = cert.fingerprint(crypto_hashes.SHA256()).hex()
    spki_der = pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    spki_pin = base64.b64encode(hashlib.sha256(spki_der).digest()).decode("ascii")

    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": format(cert.serial_number, "x"),
        "not_before": not_before.isoformat().replace("+00:00", "Z"),
        "not_after": not_after.isoformat().replace("+00:00", "Z"),
        "days_remaining": days_rem,
        "key_type": key_type,
        "key_size": key_size,
        "signature_algorithm": sig_alg,
        "sans": sans[:25],
        "sha256_fingerprint": sha256_fp,
        "spki_sha256": spki_pin,
    }


def identify_hashes(text: str) -> list[dict[str, str]]:
    """Identify likely cryptographic hash or structured token formats from an offline string."""
    s = text.strip()
    if not s or "\n" in s or " " in s:
        return []
    candidates: list[dict[str, str]] = []

    if re.match(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$", s):
        candidates.append({"format": "bcrypt", "strength": "strong", "note": "Adaptive salted KDF"})
    elif s.startswith(("$argon2id$", "$argon2i$", "$argon2d$")):
        candidates.append(
            {"format": "Argon2", "strength": "strong", "note": "Modern memory-hard KDF"}
        )
    elif s.startswith("$scrypt$") or s.startswith("scrypt:"):
        candidates.append({"format": "scrypt", "strength": "strong", "note": "Memory-hard KDF"})
    elif s.startswith(("pbkdf2_sha256$", "pbkdf2:sha256:", "$pbkdf2-sha256$")):
        candidates.append({"format": "PBKDF2-SHA256", "strength": "strong", "note": "Iterated KDF"})
    elif s.startswith("$6$"):
        candidates.append(
            {"format": "Unix SHA-512 crypt ($6$)", "strength": "moderate", "note": "Salted shadow"}
        )
    elif s.startswith("$5$"):
        candidates.append(
            {"format": "Unix SHA-256 crypt ($5$)", "strength": "moderate", "note": "Salted shadow"}
        )
    elif s.startswith("$1$"):
        candidates.append(
            {"format": "Unix MD5 crypt ($1$)", "strength": "weak", "note": "Deprecated shadow hash"}
        )
    elif s.startswith("$y$"):
        candidates.append(
            {"format": "yescrypt ($y$)", "strength": "strong", "note": "Modern Linux shadow KDF"}
        )
    elif s.startswith("*") and len(s) == 41 and _HEX_ONLY_RE.match(s[1:]):
        candidates.append(
            {"format": "MySQL 4.1+ (SHA1(SHA1))", "strength": "weak", "note": "Unsalted legacy"}
        )

    uuid_m = _UUID_RE.match(s)
    if uuid_m:
        candidates.append(
            {
                "format": f"UUIDv{uuid_m.group(1)}",
                "strength": "info",
                "note": "RFC 9562 identifier",
            }
        )

    if _HEX_ONLY_RE.match(s):
        hex_len = len(s)
        if hex_len == 8:
            candidates.append(
                {"format": "CRC32 / Adler32", "strength": "weak", "note": "Non-cryptographic"}
            )
        elif hex_len == 32:
            candidates.append(
                {"format": "MD5", "strength": "weak", "note": "128-bit broken/fast hash"}
            )
            candidates.append(
                {"format": "NTLM / MD4", "strength": "weak", "note": "128-bit Windows legacy hash"}
            )
        elif hex_len == 40:
            candidates.append(
                {"format": "SHA-1 / RIPEMD-160", "strength": "weak", "note": "160-bit legacy hash"}
            )
        elif hex_len == 64:
            candidates.append(
                {
                    "format": "SHA-256 / SHA3-256 / BLAKE2s",
                    "strength": "strong",
                    "note": "256-bit cryptographic digest",
                }
            )
        elif hex_len == 96:
            candidates.append(
                {"format": "SHA-384 / SHA3-384", "strength": "strong", "note": "384-bit digest"}
            )
        elif hex_len == 128:
            candidates.append(
                {
                    "format": "SHA-512 / SHA3-512 / BLAKE2b",
                    "strength": "strong",
                    "note": "512-bit cryptographic digest",
                }
            )
    return candidates


def detect_unix_timestamp(text: str) -> str | None:
    """Convert a 10-digit (s), 13-digit (ms), or 16-digit (us) Unix epoch into UTC ISO-8601."""
    s = text.strip()
    if not s.isdigit():
        return None
    val = int(s)
    sec: float | None = None
    if len(s) == 10 and 100_000_000 <= val <= 4_102_444_800:
        sec = float(val)
    elif len(s) == 13 and 100_000_000_000 <= val <= 4_102_444_800_000:
        sec = val / 1000.0
    elif len(s) == 16 and 100_000_000_000_000 <= val <= 4_102_444_800_000_000:
        sec = val / 1_000_000.0
    if sec is None:
        return None
    return datetime.fromtimestamp(sec, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def compute_hashes(data: bytes, algos: Sequence[str] | None = None) -> dict[str, str]:
    """Compute defensive forensic/integrity checksums for `data`."""
    selected = (
        [a.strip().lower() for a in algos if a.strip()] if algos else list(_SUPPORTED_HASH_ALGOS)
    )
    out: dict[str, str] = {}
    for algo in selected:
        if algo not in _SUPPORTED_HASH_ALGOS:
            raise ValidationError(
                f"Unsupported hash algorithm '{algo}'. "
                f"Choose from {', '.join(_SUPPORTED_HASH_ALGOS)}."
            )
        if algo == "md5":
            out["md5"] = hashlib.md5(data).hexdigest()  # noqa: S324
        elif algo == "sha1":
            out["sha1"] = hashlib.sha1(data).hexdigest()  # noqa: S324
        elif algo == "sha256":
            out["sha256"] = hashlib.sha256(data).hexdigest()
        elif algo == "sha384":
            out["sha384"] = hashlib.sha384(data).hexdigest()
        elif algo == "sha512":
            out["sha512"] = hashlib.sha512(data).hexdigest()
        elif algo == "blake2b":
            out["blake2b"] = hashlib.blake2b(data).hexdigest()
        elif algo == "crc32":
            out["crc32"] = f"{zlib.crc32(data) & 0xFFFFFFFF:08x}"
    return out


def _decode_saml(data: bytes) -> tuple[bytes, str]:
    text = data.decode("utf-8", errors="replace").strip()
    if "%" in text:
        text = urllib.parse.unquote(text)
    cleaned = "".join(text.split())
    pad = "=" * ((4 - len(cleaned) % 4) % 4)
    try:
        raw = base64.b64decode(cleaned + pad, validate=False)
    except (binascii.Error, ValueError) as exc:
        raise ValidationError(f"Invalid Base64 inside SAML payload: {exc}") from exc

    xml_bytes = raw
    note = "Base64-decoded SAML XML"
    if not raw.lstrip().startswith(b"<"):
        # SAML HTTP-Redirect binding uses raw Deflate (wbits=-15); try deflate -> gzip -> zlib
        decompressed: bytes | None = None
        for wbits, label in (
            (-zlib.MAX_WBITS, "raw-deflate"),
            (16 + zlib.MAX_WBITS, "gzip"),
            (zlib.MAX_WBITS, "zlib"),
        ):
            try:
                decompressed = _decompress_bounded(raw, wbits=wbits)
                note = f"URL/Base64/{label}-decoded SAML XML"
                break
            except ValidationError:
                continue
        if decompressed is None:
            raise ValidationError("SAML payload is neither plain XML nor deflate/gzip compressed.")
        xml_bytes = decompressed

    try:
        root = ET.fromstring(xml_bytes)  # noqa: S314
        ET.indent(root, space="  ")
        pretty = ET.tostring(root, encoding="utf-8", xml_declaration=True)
        return pretty, note
    except ET.ParseError:
        return xml_bytes, note + " (raw XML)"


def decode_single(data: bytes, codec: str, *, shift: int = 13) -> tuple[bytes, str]:
    """Decode `data` using a single named offline codec, returning `(decoded_bytes, note)`."""
    norm = normalize_codec_name(codec)
    if norm not in SUPPORTED_DECODERS or norm == "auto":
        raise ValidationError(
            f"Unsupported decoder '{codec}'. Choose from {', '.join(SUPPORTED_DECODERS)}."
        )

    if norm == "base64":
        text = "".join(data.decode("utf-8", errors="strict").split())
        if not text:
            raise ValidationError("Empty Base64 input.")
        padded = text + "=" * ((4 - len(text) % 4) % 4)
        try:
            return base64.b64decode(padded, validate=True), "RFC 4648 Base64 decoded"
        except (binascii.Error, ValueError) as exc:
            raise ValidationError(f"Invalid Base64 input: {exc}") from exc

    if norm == "base64url":
        text = "".join(data.decode("utf-8", errors="strict").split())
        if not text:
            raise ValidationError("Empty Base64URL input.")
        if not _B64URL_CHARS_RE.match(text):
            raise ValidationError("Invalid Base64URL characters.")
        padded = text + "=" * ((4 - len(text) % 4) % 4)
        try:
            return base64.urlsafe_b64decode(padded.encode("ascii")), "RFC 4648 Base64URL decoded"
        except (binascii.Error, ValueError) as exc:
            raise ValidationError(f"Invalid Base64URL input: {exc}") from exc

    if norm == "base32":
        text = "".join(data.decode("utf-8", errors="strict").split()).upper()
        if not text:
            raise ValidationError("Empty Base32 input.")
        padded = text + "=" * ((8 - len(text) % 8) % 8)
        try:
            return base64.b32decode(padded, casefold=True), "RFC 4648 Base32 decoded"
        except (binascii.Error, ValueError) as exc:
            raise ValidationError(f"Invalid Base32 input: {exc}") from exc

    if norm == "base58":
        return _base58_decode(data.decode("utf-8", errors="strict")), "Base58 decoded"

    if norm == "base85":
        text = "".join(data.decode("utf-8", errors="strict").split())
        try:
            return base64.b85decode(text), "RFC 1924 Base85 decoded"
        except ValueError as exc:
            raise ValidationError(f"Invalid Base85 input: {exc}") from exc

    if norm == "ascii85":
        text = data.decode("utf-8", errors="strict").strip()
        is_adobe = text.startswith("<~") and text.endswith("~>")
        try:
            return base64.a85decode(text, adobe=is_adobe), "Ascii85 decoded"
        except ValueError as exc:
            raise ValidationError(f"Invalid Ascii85 input: {exc}") from exc

    if norm == "hex":
        text = data.decode("utf-8", errors="strict").strip()
        cleaned = re.sub(r"(?:0x|\\x|[:\-\s,])+", "", text, flags=re.IGNORECASE)
        if not cleaned or len(cleaned) % 2 != 0 or not _HEX_ONLY_RE.match(cleaned):
            raise ValidationError("Invalid hex string (must contain an even number of hex digits).")
        return bytes.fromhex(cleaned), "Hexadecimal decoded"

    if norm == "url":
        text = data.decode("utf-8", errors="replace")
        return urllib.parse.unquote_to_bytes(text), "URL percent-decoded"

    if norm == "html":
        text = data.decode("utf-8", errors="replace")
        return html.unescape(text).encode("utf-8"), "HTML entities unescaped"

    if norm == "unicode":
        text = data.decode("utf-8", errors="replace")
        return _decode_unicode_escapes(text).encode("utf-8"), "Unicode/hex escapes decoded"

    if norm == "quoted-printable":
        return quopri.decodestring(data), "Quoted-Printable decoded"

    if norm == "rot13":
        text = data.decode("utf-8", errors="replace")
        return codecs.decode(text, "rot_13").encode("utf-8"), "ROT13 decoded"

    if norm == "caesar":
        text = data.decode("utf-8", errors="replace")
        return _caesar_shift(text, -shift).encode("utf-8"), f"Caesar decoded (shift -{shift % 26})"

    if norm == "binary":
        text = data.decode("utf-8", errors="strict").strip()
        cleaned = re.sub(r"(?:0b|[\s_,-])+", "", text, flags=re.IGNORECASE)
        if not cleaned or len(cleaned) % 8 != 0 or any(c not in "01" for c in cleaned):
            raise ValidationError("Invalid binary string (expected 8-bit groups of 0 and 1).")
        out_bytes = bytes(int(cleaned[i : i + 8], 2) for i in range(0, len(cleaned), 8))
        return out_bytes, "8-bit binary decoded"

    if norm == "octal":
        text = data.decode("utf-8", errors="strict").strip()
        tokens = re.findall(r"\\([0-7]{1,3})", text) if "\\" in text else re.split(r"[\s,]+", text)
        tokens = [t for t in tokens if t]
        if not tokens:
            raise ValidationError("Empty octal input.")
        try:
            vals = [int(t, 8) for t in tokens]
            if any(v < 0 or v > 255 for v in vals):
                raise ValidationError("Octal byte value out of 0–255 range.")
            return bytes(vals), "Octal bytes decoded"
        except ValueError as exc:
            raise ValidationError(f"Invalid octal input: {exc}") from exc

    if norm == "decimal":
        text = data.decode("utf-8", errors="strict").strip()
        tokens = [t for t in re.split(r"[\s,]+", text) if t]
        if not tokens:
            raise ValidationError("Empty decimal input.")
        try:
            vals = [int(t, 10) for t in tokens]
            if any(v < 0 or v > 255 for v in vals):
                raise ValidationError("Decimal byte value out of 0–255 range.")
            return bytes(vals), "Decimal bytes decoded"
        except ValueError as exc:
            raise ValidationError(f"Invalid decimal input: {exc}") from exc

    if norm == "morse":
        text = data.decode("utf-8", errors="strict").strip()
        words = re.split(r"\s*[/|]\s*|\s{3,}", text)
        decoded_words: list[str] = []
        for word in words:
            letters: list[str] = []
            for sym in word.split():
                ch = _MORSE_TO_CHAR.get(sym)
                if ch is None:
                    raise ValidationError(f"Unknown Morse symbol: {sym!r}")
                letters.append(ch)
            if letters:
                decoded_words.append("".join(letters))
        return " ".join(decoded_words).encode("utf-8"), "International Morse decoded"

    if norm == "punycode":
        text = data.decode("utf-8", errors="strict").strip()
        try:
            decoded_dom = text.encode("ascii").decode("idna")
        except (UnicodeError, ValueError) as exc:
            raise ValidationError(f"Invalid Punycode/IDNA domain: {exc}") from exc
        return decoded_dom.encode("utf-8"), "Punycode (IDNA) decoded"

    if norm == "gzip":
        return _decompress_bounded(data, wbits=16 + zlib.MAX_WBITS), "Gzip decompressed"

    if norm == "zlib":
        return _decompress_bounded(data, wbits=zlib.MAX_WBITS), "Zlib decompressed"

    if norm == "deflate":
        try:
            return _decompress_bounded(data, wbits=-zlib.MAX_WBITS), "Raw Deflate decompressed"
        except ValidationError:
            return _decompress_bounded(data, wbits=zlib.MAX_WBITS), "Zlib-wrapped Deflate decoded"

    if norm == "saml":
        return _decode_saml(data)

    if norm == "jwt":
        details = decode_jwt_details(data.decode("utf-8", errors="strict"))
        if details is None:
            raise ValidationError("Input is not a valid JWT (`header.payload.signature`).")
        return json.dumps(details, indent=2).encode("utf-8"), f"JWT decoded (alg={details['alg']})"

    raise ValidationError(f"Unsupported decoder '{codec}'.")


def encode_single(data: bytes, codec: str, *, shift: int = 13) -> tuple[bytes, str]:
    """Encode `data` using a single named offline codec, returning `(encoded_bytes, note)`."""
    norm = normalize_codec_name(codec)
    if norm not in SUPPORTED_ENCODERS:
        raise ValidationError(
            f"Unsupported encoder '{codec}'. Choose from {', '.join(SUPPORTED_ENCODERS)}."
        )

    if norm == "base64":
        return base64.b64encode(data), "RFC 4648 Base64 encoded"
    if norm == "base64url":
        return base64.urlsafe_b64encode(data).rstrip(b"="), "RFC 4648 Base64URL encoded (unpadded)"
    if norm == "base32":
        return base64.b32encode(data), "RFC 4648 Base32 encoded"
    if norm == "base58":
        return _base58_encode(data).encode("ascii"), "Base58 encoded"
    if norm == "base85":
        return base64.b85encode(data), "RFC 1924 Base85 encoded"
    if norm == "ascii85":
        return base64.a85encode(data), "Ascii85 encoded"
    if norm == "hex":
        return data.hex().encode("ascii"), "Hexadecimal encoded"
    if norm == "hex-escaped":
        return "".join(f"\\x{b:02x}" for b in data).encode("ascii"), "Escaped hex encoded"
    if norm == "url":
        return urllib.parse.quote_from_bytes(data, safe="").encode("ascii"), "URL percent-encoded"
    if norm == "url-all":
        return "".join(f"%{b:02X}" for b in data).encode("ascii"), "Full byte URL percent-encoded"
    if norm == "html":
        text = data.decode("utf-8", errors="replace")
        return html.escape(text, quote=True).encode("utf-8"), "HTML entities escaped"
    if norm == "unicode":
        text = data.decode("utf-8", errors="replace")
        enc = "".join(f"\\u{ord(c):04x}" if ord(c) <= 0xFFFF else f"\\U{ord(c):08x}" for c in text)
        return enc.encode("ascii"), "Unicode escapes encoded"
    if norm == "quoted-printable":
        return quopri.encodestring(data), "Quoted-Printable encoded"
    if norm == "rot13":
        text = data.decode("utf-8", errors="replace")
        return codecs.encode(text, "rot_13").encode("utf-8"), "ROT13 encoded"
    if norm == "caesar":
        text = data.decode("utf-8", errors="replace")
        return _caesar_shift(text, shift).encode("utf-8"), f"Caesar encoded (shift +{shift % 26})"
    if norm == "binary":
        return " ".join(f"{b:08b}" for b in data).encode("ascii"), "8-bit binary encoded"
    if norm == "octal":
        return " ".join(f"{b:03o}" for b in data).encode("ascii"), "Octal bytes encoded"
    if norm == "decimal":
        return " ".join(str(b) for b in data).encode("ascii"), "Decimal bytes encoded"
    if norm == "morse":
        text = data.decode("utf-8", errors="replace").upper().strip()
        words_out: list[str] = []
        for word in text.split():
            syms = [_CHAR_TO_MORSE[ch] for ch in word if ch in _CHAR_TO_MORSE]
            if syms:
                words_out.append(" ".join(syms))
        return " / ".join(words_out).encode("ascii"), "International Morse encoded"
    if norm == "punycode":
        text = data.decode("utf-8", errors="strict").strip()
        try:
            return text.encode("idna"), "Punycode (IDNA) encoded"
        except UnicodeError as exc:
            raise ValidationError(f"Failed to Punycode-encode domain: {exc}") from exc
    if norm == "gzip":
        return gzip.compress(data, compresslevel=9), "Gzip compressed"
    if norm == "zlib":
        return zlib.compress(data, level=9), "Zlib compressed"
    if norm == "deflate":
        comp = zlib.compressobj(level=9, wbits=-zlib.MAX_WBITS)
        return comp.compress(data) + comp.flush(), "Raw Deflate compressed"
    if norm == "gzip-b64":
        gz = gzip.compress(data, compresslevel=9)
        return base64.b64encode(gz), "Gzip + Base64 encoded"
    if norm == "zlib-b64":
        zb = zlib.compress(data, level=9)
        return base64.b64encode(zb), "Zlib + Base64 encoded"

    raise ValidationError(f"Unsupported encoder '{codec}'.")


def _looks_like_compressed(data: bytes) -> bool:
    return data.startswith(b"\x1f\x8b") or (
        len(data) >= 2 and data[:2] in {b"\x78\x01", b"\x78\x9c", b"\x78\xda"}
    )


def auto_decode_bytes(
    data: bytes,
    *,
    max_depth: int = 6,
) -> tuple[bytes, list[tuple[str, int, int, str]]]:
    """Automatically detect and peel nested encodings up to `max_depth` layers safely."""
    current = data
    trace: list[tuple[str, int, int, str]] = []
    seen: set[str] = {hashlib.sha256(current).hexdigest()}

    for _ in range(max_depth):
        next_bytes: bytes | None = None
        chosen_codec = ""
        chosen_note = ""

        # 1. Raw Gzip / Zlib magic headers
        if current.startswith(b"\x1f\x8b"):
            try:
                next_bytes, chosen_note = decode_single(current, "gzip")
                chosen_codec = "gzip"
            except ValidationError:
                pass
        elif len(current) >= 2 and current[:2] in {b"\x78\x01", b"\x78\x9c", b"\x78\xda"}:
            try:
                next_bytes, chosen_note = decode_single(current, "zlib")
                chosen_codec = "zlib"
            except ValidationError:
                pass

        if next_bytes is None:
            try:
                text = current.decode("utf-8").strip()
            except UnicodeDecodeError:
                break
            if not text:
                break

            # 2. JWT token (terminal decode into structured JSON)
            if _JWT_FULL_RE.match(text):
                try:
                    next_bytes, chosen_note = decode_single(text.encode("utf-8"), "jwt")
                    chosen_codec = "jwt"
                    trace.append((chosen_codec, len(current), len(next_bytes), chosen_note))
                    current = next_bytes
                except ValidationError:
                    pass
                break

            # 3. URL percent-encoding
            if _URL_PCT_RE.search(text):
                cand, note = decode_single(text.encode("utf-8"), "url")
                if cand != current:
                    next_bytes, chosen_codec, chosen_note = cand, "url", note

            # 4. HTML entities
            if next_bytes is None and _HTML_ENT_RE.search(text):
                cand, note = decode_single(text.encode("utf-8"), "html")
                if cand != current:
                    next_bytes, chosen_codec, chosen_note = cand, "html", note

            # 5. Unicode / \x escape sequences
            if next_bytes is None and _UNICODE_ESC_RE.search(text):
                cand, note = decode_single(text.encode("utf-8"), "unicode")
                if cand != current:
                    next_bytes, chosen_codec, chosen_note = cand, "unicode", note

            # 6. Punycode IDNA labels (`xn--...`)
            if next_bytes is None and _PUNYCODE_RE.search(text) and " " not in text:
                try:
                    cand, note = decode_single(text.encode("utf-8"), "punycode")
                    if cand != current:
                        next_bytes, chosen_codec, chosen_note = cand, "punycode", note
                except ValidationError:
                    pass

            # 7. Binary 8-bit groups
            if next_bytes is None:
                bin_clean = re.sub(r"(?:0b|[\s_,-])+", "", text, flags=re.IGNORECASE)
                if (
                    len(bin_clean) >= 16
                    and len(bin_clean) % 8 == 0
                    and set(bin_clean) <= {"0", "1"}
                ):
                    try:
                        cand, note = decode_single(text.encode("utf-8"), "binary")
                        if _is_mostly_printable_utf8(cand) or _looks_like_compressed(cand):
                            next_bytes, chosen_codec, chosen_note = cand, "binary", note
                    except ValidationError:
                        pass

            # 8. Hexadecimal (supports 0x, colons, spaces, or even hex >= 8 chars with alpha/delims)
            if next_bytes is None:
                hex_clean = re.sub(r"(?:0x|\\x|[:\-\s,])+", "", text, flags=re.IGNORECASE)
                has_delim = bool(re.search(r"^(?:0x|\\x)|[:\s]", text, flags=re.IGNORECASE))
                if (
                    len(hex_clean) >= 8
                    and len(hex_clean) % 2 == 0
                    and _HEX_ONLY_RE.match(hex_clean)
                    and (has_delim or not hex_clean.isdigit() or len(hex_clean) >= 16)
                ):
                    try:
                        cand = bytes.fromhex(hex_clean)
                        if _is_mostly_printable_utf8(cand) or _looks_like_compressed(cand):
                            next_bytes, chosen_codec, chosen_note = (
                                cand,
                                "hex",
                                "Hexadecimal decoded",
                            )
                    except ValueError:
                        pass

            # 9. Base64 / Base64URL (requires non-trivial charset + printable or compressed output)
            if next_bytes is None and " " not in text and len(text) >= 8:
                compact = "".join(text.split())
                if _B64_CHARS_RE.match(compact) and (
                    compact.endswith("=")
                    or any(c in compact for c in "+/0123456789")
                    or (any(c.isupper() for c in compact) and any(c.islower() for c in compact))
                ):
                    try:
                        cand, note = decode_single(compact.encode("ascii"), "base64")
                        if _is_mostly_printable_utf8(cand) or _looks_like_compressed(cand):
                            next_bytes, chosen_codec, chosen_note = cand, "base64", note
                    except ValidationError:
                        pass
                if (
                    next_bytes is None
                    and _B64URL_CHARS_RE.match(compact)
                    and ("-" in compact or "_" in compact)
                ):
                    try:
                        cand, note = decode_single(compact.encode("ascii"), "base64url")
                        if _is_mostly_printable_utf8(cand) or _looks_like_compressed(cand):
                            next_bytes, chosen_codec, chosen_note = cand, "base64url", note
                    except ValidationError:
                        pass

            # 10. Base32 (uppercase A-Z2-7 with optional `=`)
            if (
                next_bytes is None
                and " " not in text
                and len(text) >= 8
                and _B32_CHARS_RE.match(text)
                and (text.endswith("=") or any(c in "234567" for c in text))
            ):
                try:
                    cand, note = decode_single(text.encode("ascii"), "base32")
                    if _is_mostly_printable_utf8(cand) or _looks_like_compressed(cand):
                        next_bytes, chosen_codec, chosen_note = cand, "base32", note
                except ValidationError:
                    pass

            # 11. International Morse code
            if (
                next_bytes is None
                and _MORSE_CHARS_RE.match(text)
                and "." in text
                and "-" in text
                and len(text.split()) >= 2
            ):
                try:
                    cand, note = decode_single(text.encode("ascii"), "morse")
                    if _is_mostly_printable_utf8(cand):
                        next_bytes, chosen_codec, chosen_note = cand, "morse", note
                except ValidationError:
                    pass

        if next_bytes is None:
            break
        digest = hashlib.sha256(next_bytes).hexdigest()
        if digest in seen:
            break
        seen.add(digest)
        trace.append((chosen_codec, len(current), len(next_bytes), chosen_note))
        current = next_bytes

    return current, trace
