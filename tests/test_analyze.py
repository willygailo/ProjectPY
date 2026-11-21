"""Offline unit & CLI tests for `s1shell analyze` (CSP3, Email Auth, Headers & CVSS)."""

from __future__ import annotations

import base64
import io
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from s1shell.analyze.csp import analyze_csp
from s1shell.analyze.cvss_tool import analyze_cvss_vector
from s1shell.analyze.email_auth import analyze_email_auth
from s1shell.analyze.headers import analyze_raw_headers
from s1shell.cli import main
from s1shell.errors import ExitCode


def _make_dkim_rsa_b64(bits: int) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(der).decode("ascii")


def test_analyze_csp_detects_bypasses_duplicates_and_typos() -> None:
    weak_csp = (
        "default-src 'self'; "
        "script-src 'unsafe-inline' 'unsafe-eval' "
        "https://cdn.jsdelivr.net https://ajax.googleapis.com; "
        "script-src 'self'; "
        "scripts-src 'none'"
    )
    res = analyze_csp(weak_csp)
    fids = {f.id for f in res.findings}
    assert {
        "CSP-002",
        "CSP-003",
        "CSP-006",
        "CSP-007",
        "CSP-008",
        "CSP-009",
        "CSP-012",
        "CSP-013",
    } <= fids
    assert "cdn.jsdelivr.net" in res.bypass_hosts
    assert "ajax.googleapis.com" in res.bypass_hosts
    assert "script-src" in res.duplicate_directives
    assert "scripts-src" in res.unknown_directives
    assert res.grade in {"C", "D", "F"}

    strong_csp = (
        "default-src 'none'; "
        "script-src 'nonce-abcdef0123456789ABCDEF' 'strict-dynamic'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; "
        "require-trusted-types-for 'script'"
    )
    strong = analyze_csp(strong_csp)
    assert strong.score == 100
    assert strong.grade == "A"
    assert strong.findings == []


def test_analyze_email_spf_dmarc_and_dkim_key_strength() -> None:
    weak_rsa_1024 = _make_dkim_rsa_b64(1024)
    res = analyze_email_auth(
        "example.com",
        spf_record="v=spf1 ip4:10.0.0.0/8 ptr +all",
        dmarc_record="v=DMARC1; p=quarantine; sp=none; pct=50",
        dkim_record=f"v=DKIM1; k=rsa; t=y; p={weak_rsa_1024}",
        dkim_selector="s1",
        offline=True,
    )
    ids = {f.id for f in res.findings}
    assert {
        "EMAIL-SPF-PASSALL",
        "EMAIL-SPF-PTR",
        "EMAIL-SPF-BLAST",
        "EMAIL-DMARC-SUB",
        "EMAIL-DMARC-PCT",
        "EMAIL-DMARC-RUA",
        "EMAIL-DKIM-TEST",
        "EMAIL-DKIM-WEAK",
    } <= ids
    assert res.spf_ipv4_blast_radius == 16_777_216
    assert res.dkim_key_type == "RSA"
    assert res.dkim_key_bits == 1024
    assert res.spoofing_risk == "CRITICAL"

    strong_rsa_2048 = _make_dkim_rsa_b64(2048)
    strong = analyze_email_auth(
        "example.com",
        spf_record="v=spf1 -all",
        dmarc_record="v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; rua=mailto:dmarc@example.com",
        dkim_record=f"v=DKIM1; k=rsa; p={strong_rsa_2048}",
        dkim_selector="s2",
        offline=True,
    )
    assert strong.dkim_key_bits == 2048
    assert strong.score == 100
    assert strong.grade == "A"
    assert strong.spoofing_risk == "MINIMAL"


def test_analyze_raw_headers_offline_scores_fingerprints_and_remediates() -> None:
    raw = (
        "HTTP/1.1 200 OK\r\n"
        "Server: nginx/1.18.0\r\n"
        "X-Powered-By: PHP/7.4.33\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Credentials: true\r\n"
        "Set-Cookie: PHPSESSID=abc123; Path=/\r\n"
        "Content-Security-Policy: default-src *; script-src 'unsafe-inline'\r\n\r\n"
        "<html>ignored body</html>"
    )
    res = analyze_raw_headers(raw, url="https://app.example.com/")
    fids = {f["id"] for f in res.findings}
    assert "HDR-HSTS" in fids
    assert "CORS-001" in fids
    assert "EOL-001" in fids
    assert any(fp["product"] == "nginx" for fp in res.fingerprints)
    assert res.csp_analysis is not None
    assert res.remediation_snippets


def test_analyze_cvss_v31_base_temporal_environmental_and_v40() -> None:
    crit = analyze_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert crit.base_score == 9.8
    assert crit.base_severity == "CRITICAL"
    assert crit.exploitability_subscore == 3.9
    assert crit.impact_subscore == 5.9

    changed = analyze_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    assert changed.base_score == 10.0

    temp_env = analyze_cvss_vector(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C/CR:L/IR:L/AR:L"
    )
    assert temp_env.temporal_score == 8.8
    assert temp_env.temporal_severity == "HIGH"
    assert temp_env.environmental_score is not None
    assert temp_env.environmental_score < 8.8

    v4 = analyze_cvss_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
    assert v4.version == "4.0"
    assert len(v4.metrics) == 11


def test_cli_analyze_cvss_json(tmp_path: Path) -> None:
    out = io.StringIO()
    err = io.StringIO()
    code = main(
        [
            "--home",
            str(tmp_path / ".home"),
            "analyze",
            "cvss",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "--format",
            "json",
        ],
        stdout=out,
        stderr=err,
    )
    assert code == int(ExitCode.SUCCESS)
    data = json.loads(out.getvalue())
    assert data["base_score"] == 9.8
    assert data["base_severity"] == "CRITICAL"
