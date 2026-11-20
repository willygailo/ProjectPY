"""Permanent offline 40-command full CLI audit covering happy paths, HTTPS TLS, tamper & gates."""

from __future__ import annotations

import argparse
import base64
import datetime
import io
import ipaddress
import json
import os
import ssl
import stat
import threading
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from s1shell.ai.service import AIService
from s1shell.assess.service import AssessService
from s1shell.audit import AuditLogger
from s1shell.cli import build_parser, dispatch
from s1shell.config import RuntimeConfig
from s1shell.cve.audit_deps import DependencyAuditService, OSVClient
from s1shell.cve.cveorg import CVEOrgClient
from s1shell.cve.enrichment import EPSSClient, KEVClient
from s1shell.cve.nvd import NVDClient
from s1shell.cve.service import CVEService
from s1shell.errors import ExitCode, PolicyGateError, UnauthorizedError
from s1shell.fingerprint.service import FingerprintService
from s1shell.intel.clients import (
    CrtShClient,
    GitHubAdvisoryClient,
    GreyNoiseClient,
    RDAPClient,
    URLScanClient,
    VirusTotalClient,
)
from s1shell.intel.service import IntelService
from s1shell.mcp_server import S1ShellMCPServer, ping_mcp_http
from s1shell.profile.service import ProfileService
from s1shell.scope import ScopeManager
from s1shell.tor import TorCheckResult


@pytest.fixture
def tmp_config(tmp_path: Path) -> RuntimeConfig:
    home = tmp_path / ".s1shell"
    home.mkdir(parents=True, exist_ok=True)
    return RuntimeConfig.from_env(home_override=home)


def _generate_self_signed_cert(cert_path: Path, key_path: Path) -> str:
    """Generate an ephemeral self-signed RSA-2048 cert for 127.0.0.1 and return PEM text."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "S1shell Local Audit Lab"),
            x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key_pem)
    return cert_pem.decode("utf-8")


def _build_unified_intel_transport() -> httpx.MockTransport:
    """Mock transport covering NVD, CVE.org, KEV, EPSS, OSV, VT, GN, urlscan, GHSA, CT, & RDAP."""

    def handler(req: httpx.Request) -> httpx.Response:
        url = str(req.url)
        if "services.nvd.nist.gov" in url:
            return httpx.Response(
                200,
                json={
                    "vulnerabilities": [
                        {
                            "cve": {
                                "id": "CVE-2021-23017",
                                "published": "2021-06-01T13:15:00.000",
                                "lastModified": "2024-01-01T00:00:00.000",
                                "descriptions": [
                                    {"lang": "en", "value": "NGINX DNS resolver off-by-one write."}
                                ],
                                "metrics": {
                                    "cvssMetricV31": [
                                        {
                                            "cvssData": {
                                                "version": "3.1",
                                                "baseScore": 7.7,
                                                "baseSeverity": "HIGH",
                                                "vectorString": (
                                                    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
                                                ),
                                            }
                                        }
                                    ]
                                },
                                "configurations": [
                                    {
                                        "nodes": [
                                            {
                                                "cpeMatch": [
                                                    {
                                                        "vulnerable": True,
                                                        "criteria": (
                                                            "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"
                                                        ),
                                                        "versionStartIncluding": "0.6.18",
                                                        "versionEndExcluding": "1.20.1",
                                                    }
                                                ]
                                            }
                                        ]
                                    }
                                ],
                                "references": [
                                    {"url": "https://nginx.org/en/security_advisories.html"}
                                ],
                            }
                        }
                    ]
                },
            )
        if "cveawg.mitre.org" in url:
            cve_id = url.rstrip("/").split("/")[-1]
            return httpx.Response(
                200,
                json={
                    "cveMetadata": {
                        "cveId": cve_id,
                        "datePublished": "2021-06-01T13:15:00Z",
                    },
                    "containers": {
                        "cna": {
                            "descriptions": [{"lang": "en", "value": f"CNA record for {cve_id}"}],
                            "references": [{"url": "https://cve.org/example"}],
                        }
                    },
                },
            )
        if "known_exploited_vulnerabilities.json" in url:
            return httpx.Response(
                200,
                json={
                    "vulnerabilities": [
                        {
                            "cveID": "CVE-2021-23017",
                            "dateAdded": "2022-05-01",
                            "dueDate": "2022-05-22",
                            "knownRansomwareCampaignUse": "Unknown",
                        }
                    ]
                },
            )
        if "api.first.org/data/v1/epss" in url:
            return httpx.Response(
                200,
                json={
                    "data": [
                        {"cve": "CVE-2021-23017", "epss": "0.84200", "percentile": "0.98500"},
                        {"cve": "CVE-2023-44487", "epss": "0.91000", "percentile": "0.99200"},
                    ]
                },
            )
        if "api.osv.dev/v1/querybatch" in url:
            body = json.loads(req.content.decode("utf-8"))
            queries = body.get("queries", [])
            results = []
            for q in queries:
                pkg = (q.get("package") or {}).get("name", "")
                if pkg in {"requests", "lodash", "serde"}:
                    results.append(
                        {
                            "vulns": [
                                {
                                    "id": "GHSA-9wx4-h78v-vm56",
                                    "aliases": ["CVE-2021-23017"],
                                    "summary": f"High-severity advisory affecting {pkg}",
                                    "severity": [
                                        {
                                            "type": "CVSS_V3",
                                            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                                        }
                                    ],
                                    "affected": [
                                        {
                                            "ranges": [
                                                {
                                                    "type": "ECOSYSTEM",
                                                    "events": [
                                                        {"introduced": "0"},
                                                        {"fixed": "2.32.4"},
                                                    ],
                                                }
                                            ]
                                        }
                                    ],
                                    "references": [{"url": "https://osv.dev/vulnerability/GHSA-1"}],
                                }
                            ]
                        }
                    )
                else:
                    results.append({"vulns": []})
            return httpx.Response(200, json={"results": results})
        if "api.github.com/advisories" in url:
            return httpx.Response(
                200,
                json=[
                    {
                        "ghsa_id": "GHSA-9wx4-h78v-vm56",
                        "cve_id": "CVE-2021-23017",
                        "severity": "high",
                        "summary": "Mock GHSA security advisory",
                        "html_url": "https://github.com/advisories/GHSA-9wx4-h78v-vm56",
                        "published_at": "2024-05-20T00:00:00Z",
                        "vulnerabilities": [
                            {
                                "package": {"ecosystem": "pip", "name": "requests"},
                                "first_patched_version": "2.32.4",
                            }
                        ],
                    }
                ],
            )
        if "virustotal.com/api/v3" in url:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 0,
                                "suspicious": 0,
                                "harmless": 72,
                                "undetected": 15,
                            },
                            "reputation": 10,
                            "as_owner": "Example Cloud ASN",
                            "country": "US",
                            "categories": {"vendor": "business"},
                            "last_analysis_date": 1730000000,
                        }
                    }
                },
            )
        if "api.greynoise.io" in url:
            return httpx.Response(
                200,
                json={
                    "ip": "93.184.216.34",
                    "noise": False,
                    "riot": True,
                    "classification": "benign",
                    "name": "Edgecast CDN",
                },
            )
        if "urlscan.io/api/v1/search" in url:
            return httpx.Response(
                200,
                json={
                    "total": 1,
                    "results": [
                        {
                            "task": {"time": "2026-10-01T00:00:00Z", "url": "https://example.com/"},
                            "page": {
                                "ip": "93.184.216.34",
                                "server": "nginx/1.18.0",
                                "asnname": "EDGECAST",
                                "status": "200",
                            },
                            "result": "https://urlscan.io/result/mock/",
                        }
                    ],
                },
            )
        if "crt.sh" in url:
            return httpx.Response(
                200,
                json=[
                    {
                        "id": 1001,
                        "name_value": "www.example.com\napi.example.com\n*.example.com",
                        "issuer_name": "C=US, O=Let's Encrypt, CN=R10",
                        "not_before": "2026-01-01T00:00:00",
                        "not_after": "2029-12-31T23:59:59",
                    }
                ],
            )
        if "rdap.org" in url:
            if "/ip/" in url:
                return httpx.Response(
                    200,
                    json={
                        "handle": "NET-93-184-216-0-1",
                        "name": "EDGECAST-NETBLK",
                        "startAddress": "93.184.216.0",
                        "endAddress": "93.184.216.255",
                        "cidr0_cidrs": [{"v4prefix": "93.184.216.0", "length": 24}],
                        "country": "US",
                    },
                )
            return httpx.Response(
                200,
                json={
                    "ldhName": "example.com",
                    "status": ["client transfer prohibited"],
                    "secureDNS": {"delegationSigned": True},
                    "nameservers": [{"ldhName": "ns1.example.com"}],
                    "events": [
                        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
                        {"eventAction": "expiration", "eventDate": "2029-08-13T04:00:00Z"},
                    ],
                    "entities": [
                        {
                            "roles": ["registrar"],
                            "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
                        }
                    ],
                },
            )
        if "api.anthropic.com" in url or "11434" in url:
            return httpx.Response(
                200,
                json={
                    "choices": [
                        {
                            "message": {
                                "content": (
                                    "Defensive summary: patch EOL-001 and CVE-2021-23017 on "
                                    "[TARGET_IP_1]."
                                )
                            }
                        }
                    ],
                    "usage": {"prompt_tokens": 90, "completion_tokens": 30},
                },
            )
        return httpx.Response(404, json={"error": f"Unhandled mock URL: {url}"})

    return httpx.MockTransport(handler)


def _make_mocked_services(
    cfg: RuntimeConfig,
    transport: httpx.MockTransport,
) -> tuple[CVEService, DependencyAuditService, IntelService, AIService]:
    audit_log = AuditLogger(cfg.audit_log)
    kev = KEVClient(cfg, transport=transport)
    epss = EPSSClient(cfg, transport=transport)
    gh = GitHubAdvisoryClient(cfg, transport=transport, sleeper=lambda _: None)
    cve_svc = CVEService(
        cfg,
        nvd_client=NVDClient(cfg, transport=transport, sleeper=lambda _: None),
        cveorg_client=CVEOrgClient(cfg, transport=transport),
        kev_client=kev,
        epss_client=epss,
        github_client=gh,
        audit_logger=audit_log,
    )
    dep_svc = DependencyAuditService(
        cfg,
        osv_client=OSVClient(cfg, transport=transport),
        kev_client=kev,
        epss_client=epss,
        audit_logger=audit_log,
    )
    intel_svc = IntelService(
        cfg,
        vt_client=VirusTotalClient(cfg, transport=transport, sleeper=lambda _: None),
        greynoise_client=GreyNoiseClient(cfg, transport=transport, sleeper=lambda _: None),
        urlscan_client=URLScanClient(cfg, transport=transport, sleeper=lambda _: None),
        github_client=gh,
        crtsh_client=CrtShClient(cfg, transport=transport, sleeper=lambda _: None),
        rdap_client=RDAPClient(cfg, transport=transport, sleeper=lambda _: None),
        audit_logger=audit_log,
    )
    ai_svc = AIService(
        cfg,
        audit_logger=audit_log,
        transport=transport,
        sleeper=lambda _: None,
    )
    return cve_svc, dep_svc, intel_svc, ai_svc


def test_all_cve_and_intel_happy_paths_caching_and_0600_env(
    tmp_config: RuntimeConfig,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Close all 6 CVE & Intel happy-path gaps (search, get, audit, advisory, ct, rdap + env)."""
    for env_key in (
        "NVD_API_KEY",
        "GITHUB_TOKEN",
        "VIRUSTOTAL_API_KEY",
        "GREYNOISE_API_KEY",
        "URLSCAN_API_KEY",
    ):
        monkeypatch.delenv(env_key, raising=False)

    parser = build_parser()
    home_args = ["--home", str(tmp_config.home_dir), "--no-color"]

    # 1. `intel env --set-*` writes atomic 0600 `.env` and masks keys in output
    out_env = io.StringIO()
    rc = dispatch(
        parser.parse_args(
            [
                *home_args,
                "intel",
                "env",
                "--set-nvd-key",
                "nvd-secret-1234567890abcd",
                "--set-github-key",
                "ghp_secret1234567890abcd",
                "--set-vt-key",
                "vt-secret-1234567890abcd",
                "--set-greynoise-key",
                "gn-secret-1234567890abcd",
                "--set-urlscan-key",
                "us-secret-1234567890abcd",
            ]
        ),
        stdout=out_env,
        stderr=io.StringIO(),
    )
    assert rc == 0
    assert "nvd-secret-1234567890abcd" not in out_env.getvalue()
    assert stat.S_IMODE(os.stat(tmp_config.env_file).st_mode) == 0o600

    transport = _build_unified_intel_transport()
    cve_svc, dep_svc, intel_svc, _ = _make_mocked_services(tmp_config, transport)

    # 2. `cve search` happy path (`table`, `json`, `md`) + `--kev-only` + `--offline` cache hit
    for fmt in ("table", "json", "md"):
        buf = io.StringIO()
        rc = dispatch(
            parser.parse_args(
                [
                    *home_args,
                    "--format",
                    fmt,
                    "cve",
                    "search",
                    "--keyword",
                    "nginx",
                    "--min-cvss",
                    "7.0",
                    "--enrich",
                    "--kev-only",
                ]
            ),
            cve_service=cve_svc,
            stdout=buf,
            stderr=io.StringIO(),
        )
        assert rc == 0
        assert "CVE-2021-23017" in buf.getvalue()

    buf_off = io.StringIO()
    rc = dispatch(
        parser.parse_args(
            [
                *home_args,
                "--format",
                "json",
                "cve",
                "search",
                "--keyword",
                "nginx",
                "--min-cvss",
                "7.0",
                "--kev-only",
                "--offline",
            ]
        ),
        cve_service=cve_svc,
        stdout=buf_off,
        stderr=io.StringIO(),
    )
    assert rc == 0
    assert json.loads(buf_off.getvalue())["cached"] is True

    # 3. `cve get` single + batch `--enrich` (`table`, `json`, `md`)
    for fmt in ("table", "json", "md"):
        buf = io.StringIO()
        rc = dispatch(
            parser.parse_args(
                [
                    *home_args,
                    "--format",
                    fmt,
                    "cve",
                    "get",
                    "CVE-2021-23017",
                    "CVE-2023-44487",
                    "--enrich",
                ]
            ),
            cve_service=cve_svc,
            stdout=buf,
            stderr=io.StringIO(),
        )
        assert rc == 0
        assert "CVE-2021-23017" in buf.getvalue()

    # 4. `cve audit` across requirements.txt, SPDX 2.3, `--recursive`, SARIF, & `--fail-on`
    repo = tmp_path / "client_repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    (repo / "sbom.spdx.json").write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "packages": [
                    {
                        "name": "lodash",
                        "versionInfo": "4.17.20",
                        "externalRefs": [
                            {
                                "referenceType": "purl",
                                "referenceLocator": "pkg:npm/lodash@4.17.20",
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    buf_sarif = io.StringIO()
    rc = dispatch(
        parser.parse_args(
            [
                *home_args,
                "--format",
                "sarif",
                "cve",
                "audit",
                str(repo),
                "--recursive",
                "--enrich",
            ]
        ),
        dep_audit_service=dep_svc,
        stdout=buf_sarif,
        stderr=io.StringIO(),
    )
    assert rc == 0
    sarif_obj = json.loads(buf_sarif.getvalue())
    assert sarif_obj["version"] == "2.1.0"
    assert len(sarif_obj["runs"][0]["results"]) >= 1

    with pytest.raises(PolicyGateError):
        dispatch(
            parser.parse_args(
                [
                    *home_args,
                    "cve",
                    "audit",
                    str(repo / "requirements.txt"),
                    "--enrich",
                    "--fail-on",
                    "HIGH",
                ]
            ),
            dep_audit_service=dep_svc,
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )

    # 5. `intel lookup` (IP), `intel advisory`, `intel ct --export-candidates`, & `intel rdap`
    buf_lk = io.StringIO()
    assert (
        dispatch(
            parser.parse_args(
                [
                    *home_args,
                    "--format",
                    "json",
                    "intel",
                    "lookup",
                    "93.184.216.34",
                    "--sources",
                    "vt,greynoise,urlscan,rdap",
                ]
            ),
            intel_service=intel_svc,
            stdout=buf_lk,
            stderr=io.StringIO(),
        )
        == 0
    )
    lk_data = json.loads(buf_lk.getvalue())
    assert lk_data["greynoise"]["riot"] is True
    assert lk_data["rdap"]["cidr"] == "93.184.216.0/24"

    for adv_args in (
        ["--cve", "CVE-2021-23017"],
        ["--ecosystem", "pip", "--package", "requests"],
    ):
        buf_adv = io.StringIO()
        assert (
            dispatch(
                parser.parse_args([*home_args, "--format", "md", "intel", "advisory", *adv_args]),
                intel_service=intel_svc,
                stdout=buf_adv,
                stderr=io.StringIO(),
            )
            == 0
        )
        assert "GHSA-9wx4-h78v-vm56" in buf_adv.getvalue()

    cand_file = tmp_path / "ct_candidates.txt"
    buf_ct = io.StringIO()
    assert (
        dispatch(
            parser.parse_args(
                [
                    *home_args,
                    "--format",
                    "json",
                    "intel",
                    "ct",
                    "example.com",
                    "--export-candidates",
                    str(cand_file),
                ]
            ),
            intel_service=intel_svc,
            stdout=buf_ct,
            stderr=io.StringIO(),
        )
        == 0
    )
    assert "api.example.com" in cand_file.read_text(encoding="utf-8")

    buf_rdap = io.StringIO()
    assert (
        dispatch(
            parser.parse_args([*home_args, "--format", "table", "intel", "rdap", "example.com"]),
            intel_service=intel_svc,
            stdout=buf_rdap,
            stderr=io.StringIO(),
        )
        == 0
    )
    assert "Example Registrar" in buf_rdap.getvalue()

    # 6. `cve cache clear`
    assert (
        dispatch(
            parser.parse_args([*home_args, "cve", "cache", "clear"]),
            cve_service=cve_svc,
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )
        == 0
    )


def test_real_https_tls_assess_all_remediate_stacks_diff_regression_and_audit_tamper(
    tmp_config: RuntimeConfig,
    tmp_path: Path,
) -> None:
    """Exercise local HTTPS TLS/X.509, assess+CVE+intel+AI, 6 stacks, diff exit 4, & tamper."""
    cert_path = tmp_path / "local.pem"
    key_path = tmp_path / "local.key"
    _generate_self_signed_cert(cert_path, key_path)

    class _HTTPSAuditHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        def _reply(
            self,
            code: int,
            body: bytes,
            *,
            ctype: str = "text/html; charset=utf-8",
            extra: dict[str, str] | None = None,
        ) -> None:
            self.send_response(code)
            self.send_header("Server", "nginx/1.18.0")
            self.send_header("X-Powered-By", "Express")
            self.send_header("Set-Cookie", "sessionid=xyz; Path=/")
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            if extra:
                for k, v in extra.items():
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self) -> None:
            self._reply(204, b"", extra={"Allow": "GET, HEAD, OPTIONS, TRACE"})

        def do_GET(self) -> None:
            if self.path == "/.well-known/security.txt":
                self._reply(
                    200,
                    b"Contact: mailto:sec@local.test\nExpires: 2029-12-31T23:59:59Z\n",
                    ctype="text/plain",
                )
                return
            if self.path == "/.well-known/openid-configuration":
                self._reply(
                    200,
                    json.dumps(
                        {
                            "issuer": "http://127.0.0.1",
                            "response_types_supported": ["code", "id_token token"],
                        }
                    ).encode("utf-8"),
                    ctype="application/json",
                )
                return
            if self.path == "/.well-known/jwks.json":
                self._reply(
                    200,
                    json.dumps({"keys": [{"kty": "RSA", "kid": "k1", "alg": "none"}]}).encode(),
                    ctype="application/json",
                )
                return
            if self.path == "/robots.txt":
                self._reply(200, b"User-agent: *\nDisallow: /admin\n", ctype="text/plain")
                return
            self._reply(
                200,
                b"<html><head><title>HTTPS Audit</title>"
                b'<script src="/js/jquery-3.4.1.min.js"></script></head><body>ok</body></html>',
            )

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _HTTPSAuditHandler)
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    httpd.socket = ssl_ctx.wrap_socket(httpd.socket, server_side=True)
    port = httpd.server_address[1]
    https_url = f"https://127.0.0.1:{port}"

    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    try:
        parser = build_parser()
        home_args = ["--home", str(tmp_config.home_dir), "--no-color"]
        scope_mgr = ScopeManager(tmp_config.scope_file)
        scope_mgr.add("127.0.0.1", owner="Audit Lab", auth_ref="AUDIT-TLS", expires="2099-12-31")

        transport = _build_unified_intel_transport()
        cve_svc, _, intel_svc, ai_svc = _make_mocked_services(tmp_config, transport)
        audit_log = AuditLogger(tmp_config.audit_log)
        prof_svc = ProfileService(
            tmp_config,
            scope_manager=scope_mgr,
            audit_logger=audit_log,
            cafile=str(cert_path),
        )
        fp_svc = FingerprintService(
            tmp_config,
            scope_manager=scope_mgr,
            audit_logger=audit_log,
            cafile=str(cert_path),
        )
        assess_svc = AssessService(
            tmp_config,
            scope_manager=scope_mgr,
            audit_logger=audit_log,
            profile_service=prof_svc,
            fingerprint_service=fp_svc,
            cve_service=cve_svc,
            intel_service=intel_svc,
            ai_service=ai_svc,
        )

        # 1. Real HTTPS `profile` with `--tls-versions --dns-security --well-known --check-methods`
        prof_file = tmp_path / "https_profile.json"
        rc = dispatch(
            parser.parse_args(
                [
                    *home_args,
                    "--format",
                    "json",
                    "--out",
                    str(prof_file),
                    "profile",
                    https_url,
                    "--authorized",
                    "--tls-versions",
                    "--dns-security",
                    "--well-known",
                    "--check-methods",
                ]
            ),
            scope_manager=scope_mgr,
            profile_service=prof_svc,
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )
        assert rc == 0
        prof_data = json.loads(prof_file.read_text(encoding="utf-8"))
        assert prof_data["tls"]["applicable"] is True
        assert prof_data["tls"]["is_self_signed"] is True
        assert prof_data["tls"]["spki_sha256"]
        assert prof_data["well_known"]["oidc_present"] is True
        assert prof_data["well_known"]["jwks_present"] is True
        assert "TRACE" in prof_data["protocol"]["risky_methods"]

        # 2. Full `assess` with `--enrich-cve --intel --well-known --check-methods --ai-triage`
        out_dir = tmp_path / "full_assess"
        rc = dispatch(
            parser.parse_args(
                [
                    *home_args,
                    "assess",
                    https_url,
                    "--authorized",
                    "--enrich-cve",
                    "--intel",
                    "--well-known",
                    "--check-methods",
                    "--ai",
                    "--ai-provider",
                    "ollama",
                    "--ai-skill",
                    "attack-path-modeling",
                    "--redact",
                    "--restore",
                    "--ignore-finding",
                    "HDR-XFO",
                    "--out-dir",
                    str(out_dir),
                ]
            ),
            scope_manager=scope_mgr,
            assess_service=assess_svc,
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )
        assert rc == 0
        for expected_file in (
            "assess.json",
            "profile.json",
            "fingerprint.json",
            "cves.json",
            "intel.json",
            "report.html",
            "report.md",
            "report.sarif",
        ):
            assert (out_dir / expected_file).is_file()
        assess_data = json.loads((out_dir / "assess.json").read_text(encoding="utf-8"))
        assert assess_data["ai_analysis"] is not None
        assert "127.0.0.1" in assess_data["ai_analysis"]["analysis"]

        # `--min-score 99` breaches CI policy gate -> PolicyGateError (exit 4)
        with pytest.raises(PolicyGateError):
            dispatch(
                parser.parse_args(
                    [
                        *home_args,
                        "assess",
                        https_url,
                        "--authorized",
                        "--skip-cve",
                        "--min-score",
                        "99",
                    ]
                ),
                scope_manager=scope_mgr,
                assess_service=assess_svc,
                stdout=io.StringIO(),
                stderr=io.StringIO(),
            )

        # 3. `remediate` across ALL 6 stacks (auto, nginx, apache, caddy, express, generic)
        for stack in ("auto", "nginx", "apache", "caddy", "express", "generic"):
            buf_rem = io.StringIO()
            rc_rem = dispatch(
                parser.parse_args(
                    [
                        *home_args,
                        "--format",
                        "table" if stack == "auto" else "md",
                        "remediate",
                        str(out_dir / "assess.json"),
                        "--stack",
                        stack,
                    ]
                ),
                stdout=buf_rem,
                stderr=io.StringIO(),
            )
            assert rc_rem == 0
            assert buf_rem.getvalue().strip()

        # 4. `diff --fail-on-regression` triggers PolicyGateError (exit 4) on actual score drop
        degraded = json.loads((out_dir / "assess.json").read_text(encoding="utf-8"))
        degraded["posture"]["score"] = max(0, int(degraded["posture"]["score"]) - 25)
        degraded["findings"].append(
            {
                "id": "SYNTH-CRIT-999",
                "severity": "CRITICAL",
                "category": "tls",
                "title": "Synthetic regression finding",
                "evidence": "test",
                "remediation": "fix",
            }
        )
        degraded_path = tmp_path / "degraded_assess.json"
        degraded_path.write_text(json.dumps(degraded), encoding="utf-8")
        with pytest.raises(PolicyGateError):
            dispatch(
                parser.parse_args(
                    [
                        *home_args,
                        "--format",
                        "json",
                        "diff",
                        str(out_dir / "assess.json"),
                        str(degraded_path),
                        "--fail-on-regression",
                    ]
                ),
                stdout=io.StringIO(),
                stderr=io.StringIO(),
            )

        # 5. `report build` across json, md, html, sarif (including legacy flags)
        for fmt in ("json", "md", "html", "sarif"):
            buf_rep = io.StringIO()
            rc_rep = dispatch(
                parser.parse_args(
                    [
                        *home_args,
                        "--format",
                        fmt,
                        "report",
                        "build",
                        "--profile",
                        str(out_dir / "profile.json"),
                        "--fingerprint",
                        str(out_dir / "fingerprint.json"),
                        "--cve",
                        str(out_dir / "cves.json"),
                    ]
                ),
                stdout=buf_rep,
                stderr=io.StringIO(),
            )
            assert rc_rep == 0
            assert buf_rep.getvalue().strip()

        # 6. `audit verify` passes on intact chain, then FAILS (exit 1) when 1 byte is tampered!
        buf_av = io.StringIO()
        assert dispatch(
            parser.parse_args([*home_args, "audit", "verify"]),
            stdout=buf_av,
            stderr=io.StringIO(),
        ) == int(ExitCode.SUCCESS)
        assert "VALID" in buf_av.getvalue()

        raw_log = tmp_config.audit_log.read_text(encoding="utf-8")
        tampered = raw_log.replace('"outcome":"success"', '"outcome":"tampered"', 1)
        tmp_config.audit_log.write_text(tampered, encoding="utf-8")
        buf_tamper = io.StringIO()
        rc_tamper = dispatch(
            parser.parse_args([*home_args, "audit", "verify"]),
            stdout=buf_tamper,
            stderr=io.StringIO(),
        )
        assert rc_tamper == int(ExitCode.ERROR)
    finally:
        httpd.shutdown()
        httpd.server_close()
        th.join(timeout=3.0)


def test_codec_jwt_x509_saml_and_ai_env_0600_write(
    tmp_config: RuntimeConfig,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify deep codec inspection (JWT, X.509 PEM, SAML XML) and `ai env --set-key` 0600 write."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    parser = build_parser()
    home_args = ["--home", str(tmp_config.home_dir), "--no-color"]

    # 1. JWT with `alg: none` warning via `codec inspect`
    hdr = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
    pld = base64.urlsafe_b64encode(b'{"sub":"alice","exp":1700000000}').decode().rstrip("=")
    jwt_tok = f"{hdr}.{pld}."
    buf_jwt = io.StringIO()
    assert (
        dispatch(
            parser.parse_args([*home_args, "--format", "json", "codec", "inspect", jwt_tok]),
            stdout=buf_jwt,
            stderr=io.StringIO(),
        )
        == 0
    )
    jwt_res = json.loads(buf_jwt.getvalue())
    assert jwt_res["jwt"] is not None
    assert any("none" in w.lower() for w in jwt_res["jwt"]["warnings"])

    # 2. X.509 PEM cert via `codec inspect --file`
    cert_path = tmp_path / "inspect.pem"
    _generate_self_signed_cert(cert_path, tmp_path / "inspect.key")
    buf_x509 = io.StringIO()
    assert (
        dispatch(
            parser.parse_args(
                [*home_args, "--format", "json", "codec", "inspect", "--file", str(cert_path)]
            ),
            stdout=buf_x509,
            stderr=io.StringIO(),
        )
        == 0
    )
    assert json.loads(buf_x509.getvalue())["x509"]["spki_sha256"]

    # 3. SAML AuthnRequest (raw deflate -> base64 -> URL-encoded) via `codec decode -e saml`
    saml_xml = b'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>'
    co = zlib.compressobj(level=9, wbits=-15)
    deflated = co.compress(saml_xml) + co.flush()
    saml_param = quote(base64.b64encode(deflated).decode("ascii"))
    buf_saml = io.StringIO()
    assert (
        dispatch(
            parser.parse_args([*home_args, "codec", "decode", saml_param, "-e", "saml", "--raw"]),
            stdout=buf_saml,
            stderr=io.StringIO(),
        )
        == 0
    )
    assert "AuthnRequest" in buf_saml.getvalue()

    # 4. `ai env --set-key` persists 0600 `.env` and masks secret
    buf_ai_env = io.StringIO()
    secret_key = "sk-ant-api03-testsecretkey99999"
    assert (
        dispatch(
            parser.parse_args(
                [
                    *home_args,
                    "ai",
                    "env",
                    "--provider",
                    "anthropic",
                    "--set-key",
                    secret_key,
                    "--model",
                    "claude-sonnet-4-20250514",
                ]
            ),
            stdout=buf_ai_env,
            stderr=io.StringIO(),
        )
        == 0
    )
    assert secret_key not in buf_ai_env.getvalue()
    assert stat.S_IMODE(os.stat(tmp_config.env_file).st_mode) == 0o600


def test_tor_check_happy_path_cli_and_live_scoped_http_mcp(
    tmp_config: RuntimeConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Close `tor check` happy-path gap and live HTTP MCP `--allow-scoped-targets --authorized`."""
    parser = build_parser()
    home_args = ["--home", str(tmp_config.home_dir), "--no-color"]

    # 1. `s1shell tor check` happy path across table/json/md + audit log write
    monkeypatch.setattr(
        "s1shell.cli.verify_tor_egress",
        lambda proxy_url, timeout=15.0: TorCheckResult(
            proxy_url=proxy_url,
            is_tor=True,
            exit_ip="185.220.101.42",
            latency_ms=112,
            detail="Confirmed Tor exit egress (185.220.101.42) in 112 ms.",
        ),
    )
    for fmt in ("table", "json", "md"):
        buf_tc = io.StringIO()
        rc_tc = dispatch(
            parser.parse_args([*home_args, "--format", fmt, "tor", "check"]),
            stdout=buf_tc,
            stderr=io.StringIO(),
        )
        assert rc_tc == 0
        assert "185.220.101.42" in buf_tc.getvalue()

    events = AuditLogger(tmp_config.audit_log).read_recent(limit=5)
    assert any(ev.command == "tor_check" and ev.outcome == "success" for ev in events)

    # 2. Live HTTP MCP with `--allow-scoped-targets --authorized` calling real local target
    class _MiniTarget(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        def do_GET(self) -> None:
            body = b"<html><title>Scoped MCP Target</title></html>"
            self.send_response(200)
            self.send_header("Server", "nginx/1.26.0")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    tgt_srv = ThreadingHTTPServer(("127.0.0.1", 0), _MiniTarget)
    tgt_url = f"http://127.0.0.1:{tgt_srv.server_address[1]}"
    threading.Thread(target=tgt_srv.serve_forever, daemon=True).start()

    ScopeManager(tmp_config.scope_file).add(
        "127.0.0.1", owner="MCP Lab", auth_ref="MCP-1", expires="2099-12-31"
    )
    with pytest.raises(UnauthorizedError):
        S1ShellMCPServer(tmp_config, allow_scoped_targets=True, authorized=False)

    mcp_srv = S1ShellMCPServer(tmp_config, allow_scoped_targets=True, authorized=True)
    tok = "scoped-mcp-token-777"
    mcp_httpd = mcp_srv.create_http_server(host="127.0.0.1", port=0, auth_token=tok)
    mcp_url = f"http://127.0.0.1:{mcp_httpd.server_address[1]}/mcp"
    threading.Thread(target=mcp_httpd.serve_forever, daemon=True).start()
    try:
        ping = ping_mcp_http(mcp_url, token=tok)
        assert ping["scoped_targets_enabled"] is True
        assert ping["tools_count"] == 26

        with httpx.Client(trust_env=False, timeout=10.0) as client:
            ok_call = client.post(
                mcp_url,
                headers={"Authorization": f"Bearer {tok}"},
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "s1shell_profile", "arguments": {"target": tgt_url}},
                },
            )
            assert ok_call.status_code == 200
            res_body = ok_call.json()["result"]
            assert res_body["isError"] is False
            assert "nginx/1.26.0" in res_body["content"][0]["text"]

            denied_call = client.post(
                mcp_url,
                headers={"Authorization": f"Bearer {tok}"},
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "s1shell_profile",
                        "arguments": {"target": "https://192.0.2.44"},
                    },
                },
            )
            assert denied_call.status_code == 200
            assert denied_call.json()["result"]["isError"] is True
    finally:
        mcp_httpd.shutdown()
        mcp_httpd.server_close()
        tgt_srv.shutdown()
        tgt_srv.server_close()


def test_all_40_cli_leaf_commands_registered_and_audited() -> None:
    """Guardrail inventory asserting all 40 registered leaf CLI commands remain accounted for."""
    parser = build_parser()
    discovered: set[str] = set()

    def _walk(p: argparse.ArgumentParser, prefix: str = "s1shell") -> None:
        subs = [a for a in p._actions if isinstance(a, argparse._SubParsersAction)]
        if not subs:
            discovered.add(prefix)
            return
        for sp in subs:
            for name, subp in sp.choices.items():
                _walk(subp, f"{prefix} {name}")

    _walk(parser)
    expected_40 = {
        "s1shell scope add",
        "s1shell scope import",
        "s1shell scope list",
        "s1shell scope check",
        "s1shell scope remove",
        "s1shell scope expire",
        "s1shell cve search",
        "s1shell cve get",
        "s1shell cve audit",
        "s1shell cve cache clear",
        "s1shell profile",
        "s1shell fingerprint",
        "s1shell report build",
        "s1shell audit list",
        "s1shell audit verify",
        "s1shell doctor",
        "s1shell completion",
        "s1shell ai env",
        "s1shell ai analyze",
        "s1shell ai skills list",
        "s1shell ai skills show",
        "s1shell ai investigate",
        "s1shell ai chat",
        "s1shell assess",
        "s1shell diff",
        "s1shell remediate",
        "s1shell intel env",
        "s1shell intel lookup",
        "s1shell intel advisory",
        "s1shell intel ct",
        "s1shell intel rdap",
        "s1shell codec decode",
        "s1shell codec encode",
        "s1shell codec inspect",
        "s1shell codec hash",
        "s1shell mcp serve",
        "s1shell mcp config",
        "s1shell mcp ping",
        "s1shell tor status",
        "s1shell tor check",
    }
    assert discovered == expected_40
    assert len(discovered) == 40
