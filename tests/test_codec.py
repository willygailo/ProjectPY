"""Offline unit, CLI, stdin/file, and MCP tests for `s1shell codec`."""

from __future__ import annotations

import base64
import gzip
import io
import json
import urllib.parse
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from s1shell.cli import build_parser, dispatch
from s1shell.codec.codecs import (
    MAX_DECOMPRESSED_BYTES,
    decode_single,
    encode_single,
)
from s1shell.codec.service import CodecService
from s1shell.config import RuntimeConfig
from s1shell.errors import ValidationError
from s1shell.mcp_server import S1ShellMCPServer


def test_all_codecs_roundtrip_and_flexible_hex_formats() -> None:
    sample = b"Hello S1shell 2026!"
    for name in (
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
        "binary",
        "octal",
        "decimal",
        "gzip",
        "zlib",
        "deflate",
    ):
        enc, _ = encode_single(sample, name)
        dec, _ = decode_single(enc, name)
        assert dec == sample, f"Roundtrip mismatch for {name}"

    # Aliases & flexible hex formats (0x, colons, spaces, \x escapes)
    assert decode_single(b"0x48 0x69", "b16")[0] == b"Hi"
    assert decode_single(b"48:65:6c:6c:6f", "hex")[0] == b"Hello"
    assert decode_single(b"\\x41\\x42\\x43", "hex")[0] == b"ABC"
    # Base64 unpadded tolerance
    assert decode_single(b"SGVsbG8", "b64")[0] == b"Hello"
    # Morse & Punycode & Caesar
    morse_enc, _ = encode_single(b"SOS 42", "morse")
    assert decode_single(morse_enc, "morse")[0] == b"SOS 42"
    puny_enc, _ = encode_single("münchen.de".encode(), "punycode")
    assert puny_enc == b"xn--mnchen-3ya.de"
    assert decode_single(puny_enc, "idna")[0] == "münchen.de".encode()
    caesar_enc, _ = encode_single(b"AttackAtDawn", "caesar", shift=5)
    assert decode_single(caesar_enc, "caesar", shift=5)[0] == b"AttackAtDawn"


def test_magic_auto_decode_nested_layers_and_chained_pipeline() -> None:
    svc = CodecService()
    secret_json = b'{"service":"s1shell","status":"ok"}'
    # Build 3 nested layers: gzip -> base64 -> url
    enc = svc.encode(secret_json, chain=["gzip", "base64", "url"])
    assert [s.codec for s in enc.steps] == ["gzip", "base64", "url"]

    # Magic auto-decoder peels all 3 layers automatically with trace!
    auto_res = svc.decode(enc.output_text.encode("utf-8"), encoding="auto")
    assert auto_res.output_text == secret_json.decode("utf-8")
    assert [s.codec for s in auto_res.steps] == ["url", "base64", "gzip"]
    assert auto_res.is_utf8 is True

    # Explicit --chain decode matches
    chained = svc.decode(enc.output_text.encode("utf-8"), chain=["url", "base64", "gzip"])
    assert chained.output_text == secret_json.decode("utf-8")

    # Plain English sentence is NOT mangled by auto-decode
    plain = svc.decode(b"Hello world from defensive security", encoding="auto")
    assert plain.output_text == "Hello world from defensive security"
    assert plain.steps[0].codec == "none"


def test_saml_jwt_and_decompression_bomb_and_binary_safety() -> None:
    svc = CodecService()

    # SAML HTTP-Redirect style payload: raw Deflate -> Base64 -> URL-encode
    saml_xml = b'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_1"/>'
    comp = zlib.compressobj(level=9, wbits=-zlib.MAX_WBITS)
    deflated = comp.compress(saml_xml) + comp.flush()
    saml_param = urllib.parse.quote(base64.b64encode(deflated).decode("ascii"))
    saml_res = svc.decode(saml_param.encode("utf-8"), encoding="saml")
    assert "AuthnRequest" in saml_res.output_text

    # JWT decode with alg:none warning & timestamps
    hdr = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
    pay = (
        base64.urlsafe_b64encode(b'{"sub":"alice","iat":1700000000,"exp":1700003600}')
        .decode()
        .rstrip("=")
    )
    jwt_tok = f"{hdr}.{pay}."
    jwt_res = svc.decode(jwt_tok.encode("utf-8"), encoding="jwt")
    parsed_jwt = json.loads(jwt_res.output_text)
    assert parsed_jwt["alg"] == "none"
    assert parsed_jwt["ttl_seconds"] == 3600
    assert any("Unsigned token" in w for w in parsed_jwt["warnings"])

    # Binary non-UTF-8 output handled safely without crashing
    bin_res = svc.decode(b"fffe0080", encoding="hex")
    assert bin_res.is_utf8 is False
    assert bin_res.output_hex == "fffe0080"
    assert bin_res.byte_length == 4

    # Decompression bomb guard (> 8 MiB decompressed raises ValidationError)
    huge = b"A" * (MAX_DECOMPRESSED_BYTES + 4096)
    bomb = gzip.compress(huge, compresslevel=9)
    with pytest.raises(ValidationError, match="safety limit"):
        svc.decode(bomb, encoding="gzip")


def test_smart_inspect_x509_hashes_epoch_and_hash_command() -> None:
    svc = CodecService()

    # 1. X.509 PEM certificate inspection
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "app.example.com")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Example CA")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=60))
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    cert_ins = svc.inspect(pem)
    assert "x509_certificate" in cert_ins.detected_types
    assert cert_ins.x509 is not None
    assert "app.example.com" in cert_ins.x509["subject"]
    assert cert_ins.x509["key_size"] == 2048
    assert cert_ins.x509["spki_sha256"]

    # 2. Hash identification (MD5, bcrypt, SHA-256)
    md5_ins = svc.inspect(b"5d41402abc4b2a76b9719d911017c592")
    assert any(c["format"] == "MD5" for c in md5_ins.hash_candidates)
    bcrypt_ins = svc.inspect(b"$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW")
    assert any(c["format"] == "bcrypt" for c in bcrypt_ins.hash_candidates)

    # 3. Unix epoch timestamp detection
    ts_ins = svc.inspect(b"1700000000")
    assert "unix_timestamp" in ts_ins.detected_types
    assert ts_ins.timestamp_utc == "2023-11-14T22:13:20Z"

    # 4. Multi-algorithm hash calculation
    h_res = svc.hash_data(b"hello")
    assert h_res.hashes["md5"] == "5d41402abc4b2a76b9719d911017c592"
    assert (
        h_res.hashes["sha256"] == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    )
    assert h_res.hashes["crc32"] == "3610a686"


def test_codec_cli_stdin_file_raw_caesar_and_mcp(
    tmp_config: RuntimeConfig,
    tmp_path: Path,
) -> None:
    parser = build_parser()

    # Inline --raw decode
    out = io.StringIO()
    rc = dispatch(
        parser.parse_args(["codec", "decode", "SGVsbG8gUzFzaGVsbA==", "--raw"]),
        stdout=out,
        stderr=io.StringIO(),
    )
    assert rc == 0
    assert out.getvalue().strip() == "Hello S1shell"

    # Piped stdin (`-`) JSON decode
    out_stdin = io.StringIO()
    rc_in = dispatch(
        parser.parse_args(["--format", "json", "codec", "decode", "-", "-e", "hex"]),
        stdin=io.StringIO("53317368656c6c"),
        stdout=out_stdin,
        stderr=io.StringIO(),
    )
    assert rc_in == 0
    assert json.loads(out_stdin.getvalue())["output_text"] == "S1shell"

    # Caesar --all-shifts
    out_c = io.StringIO()
    rc_c = dispatch(
        parser.parse_args(
            ["--format", "json", "codec", "decode", "Uryyb", "-e", "caesar", "--all-shifts"]
        ),
        stdout=out_c,
        stderr=io.StringIO(),
    )
    assert rc_c == 0
    c_doc = json.loads(out_c.getvalue())
    assert len(c_doc["variants"]) == 25
    assert any(v["text"] == "Hello" for v in c_doc["variants"])

    # File hashing (`codec hash --file`)
    sample_f = tmp_path / "sample.txt"
    sample_f.write_bytes(b"hello")
    out_h = io.StringIO()
    rc_h = dispatch(
        parser.parse_args(["--format", "json", "codec", "hash", "--file", str(sample_f)]),
        stdout=out_h,
        stderr=io.StringIO(),
    )
    assert rc_h == 0
    assert json.loads(out_h.getvalue())["hashes"]["md5"] == "5d41402abc4b2a76b9719d911017c592"

    # MCP server exposes all 4 codec tools (19 read-only tools total)
    mcp = S1ShellMCPServer(tmp_config)
    list_resp = mcp.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert list_resp is not None
    names = [t["name"] for t in list_resp["result"]["tools"]]
    assert len(names) == 19
    assert {
        "s1shell_codec_decode",
        "s1shell_codec_encode",
        "s1shell_codec_inspect",
        "s1shell_codec_hash",
    } <= set(names)

    enc_resp = mcp.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "s1shell_codec_encode",
                "arguments": {"text": "S1shell", "chain": ["gzip", "base64"]},
            },
        }
    )
    assert enc_resp is not None and enc_resp["result"]["isError"] is False
    enc_text = json.loads(enc_resp["result"]["content"][0]["text"])["output_text"]

    dec_resp = mcp.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "s1shell_codec_decode",
                "arguments": {"text": enc_text, "encoding": "auto"},
            },
        }
    )
    assert dec_resp is not None and dec_resp["result"]["isError"] is False
    assert json.loads(dec_resp["result"]["content"][0]["text"])["output_text"] == "S1shell"
