"""Offline unit & integration tests for `s1shell dump` and `assess --dump-evidence`."""

from __future__ import annotations

import csv
import datetime
import hashlib
import io
import json
import stat
import tarfile
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from s1shell.analyze.service import AnalyzeService
from s1shell.assess.service import AssessService
from s1shell.audit import AuditLogger
from s1shell.cli import build_parser, dispatch
from s1shell.codec.service import CodecService
from s1shell.completion import generate_completion
from s1shell.config import RuntimeConfig
from s1shell.dump.service import DumpService
from s1shell.errors import ExitCode, OutOfScopeError, UnauthorizedError, ValidationError
from s1shell.intel.models import CTLookupResult
from s1shell.intel.service import IntelService
from s1shell.profile.models import TLSResult
from s1shell.profile.service import ProfileService
from s1shell.profile.tls_check import der_chain_to_pem
from s1shell.scope import ScopeManager


def _make_self_signed_der_cert(cn: str = "dump-lab.example") -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Dump Lab Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cn), x509.DNSName(f"www.{cn}")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


class _StubDNSResolver:
    def __init__(self, mapping: dict[tuple[str, str], list[str]]) -> None:
        self._mapping = mapping

    def resolve(self, qname: str, rdtype: str, *, lifetime: float = 5.0) -> list[str]:
        del lifetime
        key = (qname.lower().rstrip("."), rdtype.upper())
        return list(self._mapping.get(key, []))


def _make_sample_html(secret_token: str) -> bytes:
    html = f"""<!doctype html>
<html lang="en">
<head>
  <title>Dump Lab Portal</title>
  <meta name="author" content="Dump Lab Security Team">
  <script type="application/ld+json">
    {{"@context":"https://schema.org","@type":"Organization","name":"Dump Lab Corp",
      "email":"security@dump-lab.example","telephone":"+63 917 555 0199"}}
  </script>
</head>
<body>
  <a href="mailto:ops@dump-lab.example">Contact Ops</a>
  <a href="https://github.com/dumplab">GitHub</a>
  <form action="/api/v1/login" method="post">
    <input name="redirect_uri" value="/dashboard" />
  </form>
  <script>
    const gaId = "G-DUMP123456";
    const apiBase = "https://api.dump-lab.example/v1/items";
    const leaked = "{secret_token}";
  </script>
</body>
</html>
"""
    return html.encode("utf-8")


def _build_mock_env(
    tmp_path: Path, secret_token: str
) -> tuple[
    RuntimeConfig,
    ScopeManager,
    AuditLogger,
    ProfileService,
    IntelService,
    str,
]:
    home = tmp_path / "home"
    cfg = RuntimeConfig.from_env(home_override=home)
    scope_mgr = ScopeManager(
        cfg.scope_file,
        resolver=lambda host: ["93.184.216.34"] if host.endswith("dump-lab.example") else [],
    )
    scope_mgr.add(
        "dump-lab.example",
        owner="Lab Owner",
        auth_ref="SOW-DUMP-01",
        expires="2029-12-31",
        include_subdomains=True,
    )
    audit_log = AuditLogger(cfg.audit_log)

    cert_der = _make_self_signed_der_cert("dump-lab.example")
    cert_pem = der_chain_to_pem([cert_der])

    def _tls_inspector(**kwargs: object) -> tuple[TLSResult, str | None]:
        out_bucket = kwargs.get("chain_pem_out")
        if isinstance(out_bucket, list):
            out_bucket.append(cert_pem)
        return (
            TLSResult(
                applicable=True,
                negotiated_version="TLSv1.3",
                cipher_suite="TLS_AES_256_GCM_SHA384",
                supported_versions=["TLSv1.2", "TLSv1.3"],
                verified=True,
                subject="CN=dump-lab.example,O=Dump Lab Org",
                issuer="CN=dump-lab.example,O=Dump Lab Org",
                sans=["DNS:dump-lab.example", "DNS:www.dump-lab.example"],
                days_remaining=89,
                key_type="RSA",
                key_size=2048,
                chain_length=1,
            ),
            "h2",
        )

    html_body = _make_sample_html(secret_token)

    def _handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "OPTIONS":
            return httpx.Response(200, headers={"Allow": "GET, HEAD, OPTIONS"})
        if path == "/.well-known/security.txt":
            return httpx.Response(
                200,
                content=b"Contact: mailto:sec@dump-lab.example\nExpires: 2029-12-31T00:00:00Z\n",
                headers={"Content-Type": "text/plain"},
            )
        if path == "/robots.txt":
            return httpx.Response(
                200,
                content=b"User-agent: *\nDisallow: /admin-portal\nSitemap: https://dump-lab.example/sitemap.xml\n",
                headers={"Content-Type": "text/plain"},
            )
        if path == "/.well-known/openid-configuration":
            return httpx.Response(
                200,
                json={
                    "issuer": "https://dump-lab.example",
                    "jwks_uri": "https://dump-lab.example/.well-known/jwks.json",
                },
            )
        if path == "/.well-known/jwks.json":
            return httpx.Response(
                200,
                json={"keys": [{"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256"}]},
            )
        if path in {"/", ""}:
            return httpx.Response(
                200,
                content=html_body,
                headers=[
                    ("Content-Type", "text/html; charset=utf-8"),
                    ("Server", "nginx/1.18.0"),
                    (
                        "Content-Security-Policy",
                        "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net",
                    ),
                    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
                    ("X-Content-Type-Options", "nosniff"),
                    ("Set-Cookie", "sid=abc123; HttpOnly; Secure; SameSite=Lax"),
                ],
            )
        return httpx.Response(404)

    dns_stub = _StubDNSResolver(
        {
            ("dump-lab.example", "A"): ["93.184.216.34"],
            ("dump-lab.example", "MX"): ["10 mail.dump-lab.example."],
            ("dump-lab.example", "NS"): ["ns1.dump-lab.example."],
            ("dump-lab.example", "CAA"): ['0 issue "letsencrypt.org"'],
            ("dump-lab.example", "TXT"): ['"v=spf1 ip4:93.184.216.34 ~all"'],
            ("_dmarc.dump-lab.example", "TXT"): [
                '"v=DMARC1; p=quarantine; rua=mailto:dmarc@dump-lab.example"'
            ],
        }
    )

    profile_svc = ProfileService(
        cfg,
        scope_manager=scope_mgr,
        audit_logger=audit_log,
        dns_resolver=dns_stub,
        tls_inspector=_tls_inspector,
        http_transport=httpx.MockTransport(_handler),
    )

    class _StubIntelService(IntelService):
        def ct_lookup(
            self,
            raw_domain: str,
            *,
            offline: bool = False,
            refresh: bool = False,
            export_candidates: Path | None = None,
        ) -> CTLookupResult:
            del offline, refresh, export_candidates
            return CTLookupResult(
                domain=raw_domain,
                cached=True,
                total_certificates=2,
                unique_subdomains=["api.dump-lab.example", "admin.dump-lab.example"],
                active_certificates=2,
                issuers=["Let's Encrypt"],
            )

    intel_svc = _StubIntelService(cfg, audit_logger=audit_log)
    return cfg, scope_mgr, audit_log, profile_svc, intel_svc, cert_pem


def test_dump_out_of_scope_fails_closed_with_zero_files(tmp_path: Path) -> None:
    cfg, scope_mgr, audit_log, profile_svc, intel_svc, _ = _build_mock_env(
        tmp_path, "ghp_Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3h2"
    )
    dump_svc = DumpService(
        cfg,
        scope_manager=scope_mgr,
        audit_logger=audit_log,
        profile_service=profile_svc,
        intel_service=intel_svc,
    )
    out_dir = tmp_path / "should-not-exist-oos"
    with pytest.raises(OutOfScopeError):
        dump_svc.dump("https://not-authorized.invalid", authorized=True, out_dir=out_dir, fast=True)

    assert not out_dir.exists()
    assert audit_log.verify().valid is True


def test_dump_unauthorized_fails_closed_with_zero_files(tmp_path: Path) -> None:
    cfg, scope_mgr, audit_log, profile_svc, intel_svc, _ = _build_mock_env(
        tmp_path, "ghp_Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3h2"
    )
    dump_svc = DumpService(
        cfg,
        scope_manager=scope_mgr,
        audit_logger=audit_log,
        profile_service=profile_svc,
        intel_service=intel_svc,
    )
    out_dir = tmp_path / "should-not-exist-unauth"
    with pytest.raises(UnauthorizedError):
        dump_svc.dump("https://dump-lab.example", authorized=False, out_dir=out_dir, fast=True)

    assert not out_dir.exists()
    assert audit_log.verify().valid is True


def test_dump_full_bundle_manifest_permissions_and_roundtrips(tmp_path: Path) -> None:
    # Synthetic non-placeholder token to test redaction in entities + body
    secret_token = "ghp_Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3h2"
    cfg, scope_mgr, audit_log, profile_svc, intel_svc, _ = _build_mock_env(tmp_path, secret_token)
    dump_svc = DumpService(
        cfg,
        scope_manager=scope_mgr,
        audit_logger=audit_log,
        profile_service=profile_svc,
        intel_service=intel_svc,
    )
    out_dir = tmp_path / "dump-bundle"
    res = dump_svc.dump(
        "https://dump-lab.example",
        authorized=True,
        out_dir=out_dir,
        skip_cve=True,
        run_intel=False,
        run_ct=True,
        archive=True,
        operator="Tester",
    )

    assert res.artifact_type == "dump_report"
    assert res.body_captured is True
    assert res.body_redacted is False
    assert res.archive_path is not None
    assert res.archive_sha256 is not None

    expected_files = [
        "raw/response_headers.txt",
        "raw/response_body.html",
        "raw/tls_chain.pem",
        "raw/dns_records.json",
        "well_known/security.txt",
        "well_known/robots.txt",
        "well_known/openid-configuration.json",
        "well_known/jwks.json",
        "entities/entities.json",
        "entities/entities.csv",
        "analysis/csp_analysis.json",
        "analysis/email_auth.json",
        "analysis/hardening.md",
        "osint/ct.json",
        "osint/ct_subdomains.txt",
        "reports/profile.json",
        "reports/fingerprint.json",
        "reports/assess.json",
        "reports/report.md",
        "reports/report.html",
        "reports/report.sarif",
    ]
    for rel in expected_files:
        fpath = out_dir / rel
        assert fpath.is_file(), f"Missing dumped file: {rel}"
        assert stat.S_IMODE(fpath.stat().st_mode) == 0o600

    assert stat.S_IMODE(out_dir.stat().st_mode) == 0o700

    # Verify SHA-256 chain-of-custody manifest matches every file byte-for-byte
    manifest_path = out_dir / "evidence_manifest.json"
    assert manifest_path.is_file()
    assert stat.S_IMODE(manifest_path.stat().st_mode) == 0o600
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["artifact_type"] == "evidence_manifest"
    assert manifest["scope_id"] == res.scope_id
    assert manifest["file_count"] == len(manifest["files"])
    for entry in manifest["files"]:
        fp = out_dir / entry["relative_path"]
        raw_bytes = fp.read_bytes()
        assert len(raw_bytes) == entry["size_bytes"]
        assert hashlib.sha256(raw_bytes).hexdigest() == entry["sha256"]

    # Verify archive (.tar.gz) integrity and 0600 permissions
    arch = Path(res.archive_path)
    assert arch.is_file()
    assert stat.S_IMODE(arch.stat().st_mode) == 0o600
    assert hashlib.sha256(arch.read_bytes()).hexdigest() == res.archive_sha256
    with tarfile.open(arch, "r:gz") as tf:
        names = tf.getnames()
        assert any(n.endswith("evidence_manifest.json") for n in names)

    # Verify entities.csv contains extracted surface entities & redacts raw secrets
    csv_text = (out_dir / "entities" / "entities.csv").read_text(encoding="utf-8")
    assert secret_token not in csv_text
    rows = list(csv.DictReader(io.StringIO(csv_text)))
    cats = {r["category"] for r in rows}
    assert {"email", "tls_san", "ct_subdomain", "client_id_or_key", "technology"} <= cats

    # Round-trip 1: `analyze headers --file raw/response_headers.txt`
    an_svc = AnalyzeService(cfg)
    hdr_res = an_svc.headers(
        file_path=out_dir / "raw" / "response_headers.txt",
        url="https://dump-lab.example/",
    )
    assert hdr_res.header_count >= 5
    assert hdr_res.csp_analysis is not None
    assert "cdn.jsdelivr.net" in hdr_res.csp_analysis.bypass_hosts

    # Round-trip 2: `codec inspect --file raw/tls_chain.pem`
    codec_res = CodecService().inspect((out_dir / "raw" / "tls_chain.pem").read_bytes())
    assert "x509_certificate" in codec_res.detected_types
    assert codec_res.x509 is not None
    assert "dump-lab.example" in str(codec_res.x509.get("subject", ""))

    # Verify audit log chain integrity & `dump` record presence
    verify = audit_log.verify()
    assert verify.valid is True
    recent = audit_log.read_recent(limit=10)
    assert any(ev.command == "dump" and ev.outcome == "success" for ev in recent)


def test_dump_no_body_and_redact_body_options(tmp_path: Path) -> None:
    secret_token = "ghp_Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3h2"
    cfg, scope_mgr, audit_log, profile_svc, intel_svc, _ = _build_mock_env(tmp_path, secret_token)
    dump_svc = DumpService(
        cfg,
        scope_manager=scope_mgr,
        audit_logger=audit_log,
        profile_service=profile_svc,
        intel_service=intel_svc,
    )

    no_body_dir = tmp_path / "dump-no-body"
    res_nb = dump_svc.dump(
        "https://dump-lab.example",
        authorized=True,
        out_dir=no_body_dir,
        include_body=False,
        fast=True,
    )
    assert res_nb.body_captured is False
    assert not list((no_body_dir / "raw").glob("response_body.*"))
    assert (no_body_dir / "raw" / "response_headers.txt").is_file()

    redact_dir = tmp_path / "dump-redacted"
    res_rd = dump_svc.dump(
        "https://dump-lab.example",
        authorized=True,
        out_dir=redact_dir,
        include_body=True,
        redact_body=True,
        fast=True,
    )
    assert res_rd.body_captured is True
    assert res_rd.body_redacted is True
    saved_body = (redact_dir / "raw" / "response_body.html").read_text(encoding="utf-8")
    assert "ops@dump-lab.example" not in saved_body
    assert secret_token not in saved_body
    assert "[EMAIL_" in saved_body


def test_assess_dump_evidence_flag_and_validation(tmp_path: Path) -> None:
    secret_token = "ghp_Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3h2"
    cfg, scope_mgr, audit_log, profile_svc, intel_svc, _ = _build_mock_env(tmp_path, secret_token)
    assess_svc = AssessService(
        cfg,
        scope_manager=scope_mgr,
        audit_logger=audit_log,
        profile_service=profile_svc,
        intel_service=intel_svc,
    )

    with pytest.raises(ValidationError):
        assess_svc.assess(
            "https://dump-lab.example",
            authorized=True,
            skip_cve=True,
            dump_evidence=True,
            out_dir=None,
        )

    out_dir = tmp_path / "assess-ev"
    res = assess_svc.assess(
        "https://dump-lab.example",
        authorized=True,
        check_well_known=True,
        skip_cve=True,
        out_dir=out_dir,
        dump_evidence=True,
    )
    assert (out_dir / "assess.json").is_file()
    assert (out_dir / "raw" / "response_headers.txt").is_file()
    assert (out_dir / "raw" / "response_body.html").is_file()
    assert (out_dir / "raw" / "tls_chain.pem").is_file()
    assert (out_dir / "entities" / "entities.csv").is_file()
    assert (out_dir / "evidence_manifest.json").is_file()
    assert any(p.endswith("evidence_manifest.json") for p in res.saved_files)

    manifest = json.loads((out_dir / "evidence_manifest.json").read_text(encoding="utf-8"))
    manifest_paths = {e["relative_path"] for e in manifest["files"]}
    assert "assess.json" in manifest_paths
    assert "raw/response_headers.txt" in manifest_paths
    for entry in manifest["files"]:
        raw_bytes = (out_dir / entry["relative_path"]).read_bytes()
        assert hashlib.sha256(raw_bytes).hexdigest() == entry["sha256"]


def test_cli_dump_dispatch_and_completions(tmp_path: Path) -> None:
    secret_token = "ghp_Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3h2"
    cfg, scope_mgr, audit_log, profile_svc, intel_svc, _ = _build_mock_env(tmp_path, secret_token)
    dump_svc = DumpService(
        cfg,
        scope_manager=scope_mgr,
        audit_logger=audit_log,
        profile_service=profile_svc,
        intel_service=intel_svc,
    )

    parser = build_parser()
    # Verify help text formats cleanly under Python 3.14 argparse
    assert "dump" in parser.format_help()
    for fmt in ("json", "md", "table"):
        out_dir = tmp_path / f"cli-{fmt}"
        buf = io.StringIO()
        args = parser.parse_args(
            [
                "--home",
                str(cfg.home_dir),
                "--no-color",
                "--format",
                fmt,
                "dump",
                "https://dump-lab.example",
                "--authorized",
                "--fast",
                "--out-dir",
                str(out_dir),
            ]
        )
        rc = dispatch(
            args,
            parser=parser,
            scope_manager=scope_mgr,
            dump_service=dump_svc,
            stdout=buf,
        )
        assert rc == int(ExitCode.SUCCESS)
        rendered = buf.getvalue()
        if fmt == "json":
            payload = json.loads(rendered)
            assert payload["artifact_type"] == "dump_report"
            assert payload["file_count"] >= 10
        elif fmt == "md":
            assert "# S1shell Authorized Evidence Dump" in rendered
        else:
            assert "evidence_manifest.json" in rendered

    for shell in ("bash", "zsh", "fish"):
        script = generate_completion(shell)
        assert "dump" in script
