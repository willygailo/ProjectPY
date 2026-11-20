"""Offline unit, CLI, assessment, report, and MCP tests for `s1shell intel` (v0.3.0)."""

from __future__ import annotations

import io
import json
import stat
from pathlib import Path

import httpx
import pytest

from s1shell.assess.scorer import evaluate_posture_with_suppressions
from s1shell.assess.service import AssessService
from s1shell.audit import AuditLogger
from s1shell.cli import build_parser, dispatch
from s1shell.config import RuntimeConfig
from s1shell.cve.nvd import NVDClient
from s1shell.cve.rate_limit import RateLimiter
from s1shell.cve.service import CVEService
from s1shell.doctor import run_doctor
from s1shell.fingerprint.models import FingerprintResult
from s1shell.intel.clients import (
    GitHubAdvisoryClient,
    GreyNoiseClient,
    URLScanClient,
    VirusTotalClient,
)
from s1shell.intel.models import GreyNoiseIntel, IntelLookupResult, VirusTotalIntel
from s1shell.intel.service import IntelService
from s1shell.mcp_server import S1ShellMCPServer
from s1shell.profile.header_check import analyze_headers
from s1shell.profile.models import DNSRecords, ProfileResult, ProtocolInfo, TLSResult
from s1shell.profile.service import ProfileService
from s1shell.scope import ScopeManager

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_intel_env_save_masks_keys_enforces_0600_and_doctor(
    tmp_config: RuntimeConfig,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for var in (
        "NVD_API_KEY",
        "GITHUB_TOKEN",
        "VIRUSTOTAL_API_KEY",
        "GREYNOISE_API_KEY",
        "URLSCAN_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)

    svc = IntelService(tmp_config)
    saved = svc.save_env(
        nvd_key="test-nvd-key-1234567890",
        github_token="ghp_testtoken1234567890abcdef",
        vt_key="test-vt-key-0000111122223333",
        greynoise_key="test-gn-key-aaaa-bbbb-cccc",
        urlscan_key="test-us-key-9999-8888-7777",
    )
    assert stat.S_IMODE(tmp_config.env_file.stat().st_mode) == 0o600
    assert len(saved.feeds) == 5
    assert all(f.configured for f in saved.feeds)
    for f in saved.feeds:
        assert f.masked_key is not None
        assert "1234567890" not in f.masked_key

    doc = run_doctor(tmp_config)
    assert doc.healthy is True
    chk_map = {c.name: c.detail for c in doc.checks}
    assert "NVD_API_KEY set" in chk_map["nvd_api_key"]
    assert "GITHUB_TOKEN set" in chk_map["github_token"]
    assert "VIRUSTOTAL_API_KEY set" in chk_map["virustotal_api_key"]
    assert "GREYNOISE_API_KEY set" in chk_map["greynoise_api_key"]
    assert "URLSCAN_API_KEY set" in chk_map["urlscan_api_key"]

    # CLI `intel env` preserves existing keys when updating a custom env file
    custom_env = tmp_path / "custom.env"
    custom_env.write_text('ANTHROPIC_API_KEY="sk-ant-api03-keepme9999"\n', encoding="utf-8")
    parser = build_parser()
    parsed = parser.parse_args(
        [
            "--home",
            str(tmp_config.home_dir),
            "--format",
            "json",
            "intel",
            "env",
            "--set-vt-key",
            "vt-custom-000000001111",
            "--env-file",
            str(custom_env),
        ]
    )
    out = io.StringIO()
    assert dispatch(parsed, stdout=out, stderr=io.StringIO()) == 0
    assert "ANTHROPIC_API_KEY" in custom_env.read_text(encoding="utf-8")
    assert "VIRUSTOTAL_API_KEY" in custom_env.read_text(encoding="utf-8")


def test_intel_lookup_vt_greynoise_urlscan_and_offline_cache(
    tmp_config: RuntimeConfig,
    audit_logger: AuditLogger,
) -> None:
    calls: list[str] = []

    def vt_handler(req: httpx.Request) -> httpx.Response:
        calls.append(f"vt:{req.url.path}")
        assert req.headers.get("x-apikey") == "fake-vt-key-00000000"
        return httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 2,
                            "suspicious": 1,
                            "harmless": 70,
                            "undetected": 15,
                        },
                        "reputation": -10,
                        "as_owner": "Example Cloud",
                        "categories": {"vendorA": "information technology"},
                        "last_analysis_date": 1730000000,
                    }
                }
            },
        )

    def gn_handler(req: httpx.Request) -> httpx.Response:
        calls.append(f"gn:{req.url.path}")
        assert req.headers.get("key") == "fake-gn-key-00000000"
        if req.url.path.endswith("/198.51.100.9"):
            return httpx.Response(404, json={"message": "IP not observed"})
        return httpx.Response(
            200,
            json={
                "ip": "93.184.216.34",
                "noise": False,
                "riot": True,
                "classification": "benign",
                "name": "Edgecast CDN",
                "last_seen": "2026-11-19",
            },
        )

    def us_handler(req: httpx.Request) -> httpx.Response:
        calls.append(f"us:{req.method}:{req.url.path}")
        assert req.method == "GET"  # Strictly passive search — never POST submit!
        return httpx.Response(
            200,
            json={
                "total": 42,
                "results": [
                    {
                        "task": {"time": "2026-11-18T12:00:00Z", "url": "https://example.com/"},
                        "page": {
                            "url": "https://example.com/",
                            "status": 200,
                            "server": "nginx",
                            "ip": "93.184.216.34",
                            "asnname": "EDGECAST",
                            "title": "Example Domain",
                        },
                        "result": "https://urlscan.io/api/v1/result/abc123/",
                    }
                ],
            },
        )

    svc = IntelService(
        tmp_config,
        vt_client=VirusTotalClient(
            tmp_config, api_key="fake-vt-key-00000000", transport=httpx.MockTransport(vt_handler)
        ),
        greynoise_client=GreyNoiseClient(
            tmp_config, api_key="fake-gn-key-00000000", transport=httpx.MockTransport(gn_handler)
        ),
        urlscan_client=URLScanClient(
            tmp_config, api_key="fake-us-key-00000000", transport=httpx.MockTransport(us_handler)
        ),
        audit_logger=audit_logger,
    )

    res = svc.lookup("https://example.com", pinned_ip="93.184.216.34")
    assert res.cached is False
    assert set(res.sources_queried) == {"vt", "greynoise", "urlscan"}
    assert res.virustotal is not None and res.virustotal.malicious == 2
    assert res.greynoise is not None and res.greynoise.riot is True
    assert res.urlscan is not None and res.urlscan.total_results == 42
    assert res.urlscan.observed_servers == ["nginx"]
    assert len(calls) == 3

    # Second call served 100% offline from SQLite cache (zero network calls)
    cached_res = svc.lookup("https://example.com", pinned_ip="93.184.216.34", offline=True)
    assert cached_res.cached is True
    assert len(calls) == 3

    # GreyNoise 404 handled cleanly without failing lookup
    res_404 = svc.lookup("198.51.100.9", sources=["greynoise"])
    assert res_404.greynoise is not None
    assert res_404.greynoise.classification == "unknown"


def test_github_advisories_and_cve_enrichment(
    tmp_config: RuntimeConfig,
    audit_logger: AuditLogger,
) -> None:
    nvd_payload = json.loads((FIXTURES / "nvd_cve_2021_23017.json").read_text(encoding="utf-8"))

    def gh_handler(req: httpx.Request) -> httpx.Response:
        assert req.headers.get("Authorization") == "Bearer ghp_fake_token_0000"
        return httpx.Response(
            200,
            json=[
                {
                    "ghsa_id": "GHSA-test-1234-5678",
                    "cve_id": "CVE-2021-23017",
                    "summary": "NGINX DNS resolver off-by-one heap write",
                    "severity": "high",
                    "cvss": {"score": 7.7},
                    "cwes": [{"cwe_id": "CWE-193"}],
                    "published_at": "2021-06-01T00:00:00Z",
                    "html_url": "https://github.com/advisories/GHSA-test-1234-5678",
                    "vulnerabilities": [{"first_patched_version": "1.20.1"}],
                }
            ],
        )

    gh_client = GitHubAdvisoryClient(
        tmp_config,
        token="ghp_fake_token_0000",
        transport=httpx.MockTransport(gh_handler),
    )
    intel_svc = IntelService(tmp_config, github_client=gh_client, audit_logger=audit_logger)
    adv_res = intel_svc.advisories(cve_id="CVE-2021-23017")
    assert len(adv_res.advisories) == 1
    assert adv_res.advisories[0].ghsa_id == "GHSA-test-1234-5678"
    assert adv_res.advisories[0].patched_versions == ["1.20.1"]

    cve_svc = CVEService(
        tmp_config,
        nvd_client=NVDClient(
            tmp_config,
            rate_limiter=RateLimiter(max_requests=50, window_seconds=30.0),
            transport=httpx.MockTransport(lambda _r: httpx.Response(200, json=nvd_payload)),
        ),
        github_client=gh_client,
        audit_logger=audit_logger,
    )
    cve_res = cve_svc.get("CVE-2021-23017", enrich=True)
    assert cve_res.records[0].ghsa_id == "GHSA-test-1234-5678"
    assert cve_res.records[0].patched_versions == ["1.20.1"]


def test_assess_with_intel_scoring_html_autoescape_and_mcp(
    tmp_config: RuntimeConfig,
    scope_manager: ScopeManager,
    audit_logger: AuditLogger,
    tmp_path: Path,
) -> None:
    # Scorer unit test for VT malicious + GreyNoise malicious/RIOT
    prof = ProfileResult(
        target="https://app.example.com",
        url="https://app.example.com/",
        pinned_ip="93.184.216.34",
        scope_id="s1",
        auth_ref="SOW-1",
        authorized_via="flag",
        dns=DNSRecords(a=["93.184.216.34"]),
        protocol=ProtocolInfo(status_code=200, http_version="HTTP/2"),
        tls=TLSResult(applicable=True, negotiated_version="TLSv1.3", verified=True),
        headers=analyze_headers([], is_https=True),
        raw_headers=[],
    )
    fp = FingerprintResult(
        target=prof.target, url=prof.url, mode="from_profile", scope_id="s1", auth_ref="SOW-1"
    )
    intel_bad = IntelLookupResult(
        indicator="app.example.com",
        indicator_type="domain",
        resolved_ip="93.184.216.34",
        sources_queried=["vt", "greynoise"],
        virustotal=VirusTotalIntel(
            indicator="app.example.com",
            indicator_type="domain",
            malicious=4,
            suspicious=1,
            harmless=60,
            as_owner="<script>alert(1)</script>",
            gui_url="https://www.virustotal.com/gui/domain/app.example.com",
        ),
        greynoise=GreyNoiseIntel(
            ip="93.184.216.34",
            noise=True,
            riot=False,
            classification="malicious",
        ),
    )
    _, findings, _ = evaluate_posture_with_suppressions(prof, fp, intel=intel_bad)
    fmap = {f.id: f for f in findings}
    assert fmap["INTEL-VT-MAL"].severity == "HIGH"
    assert fmap["INTEL-GN-MAL"].severity == "MEDIUM"

    # End-to-end `assess --intel --out-dir` + HTML autoescaping + MCP lookup
    scope_manager.add("app.example.com", owner="ACME", auth_ref="SOW-1", expires="2099-12-31")

    class StubDNS:
        def resolve(self, _h: str, rdtype: str, lifetime: float = 5.0) -> list[str]:
            _ = lifetime
            return ["93.184.216.34"] if rdtype == "A" else []

    class StubIntelService(IntelService):
        def lookup(self, raw_indicator: str, **_kwargs: object) -> IntelLookupResult:
            _ = raw_indicator
            return intel_bad

    prof_svc = ProfileService(
        tmp_config,
        scope_manager=scope_manager,
        audit_logger=audit_logger,
        dns_resolver=StubDNS(),
        tls_inspector=lambda **_kw: (
            TLSResult(applicable=True, negotiated_version="TLSv1.3", verified=True),
            "h2",
        ),
        http_transport=httpx.MockTransport(lambda _r: httpx.Response(200, content=b"ok")),
    )
    stub_intel = StubIntelService(tmp_config, audit_logger=audit_logger)
    assess_svc = AssessService(
        tmp_config,
        scope_manager=scope_manager,
        audit_logger=audit_logger,
        profile_service=prof_svc,
        intel_service=stub_intel,
    )
    out_dir = tmp_path / "out_intel"
    res = assess_svc.assess(
        "https://app.example.com",
        authorized=True,
        skip_cve=True,
        run_intel=True,
        out_dir=out_dir,
    )
    assert res.intel is not None
    assert (out_dir / "intel.json").is_file()
    html_text = (out_dir / "report.html").read_text(encoding="utf-8")
    assert "Passive Threat Intelligence" in html_text
    assert "<script>alert(1)</script>" not in html_text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_text

    # MCP `s1shell_intel_lookup` tool
    mcp = S1ShellMCPServer(tmp_config, intel_service=stub_intel)
    resp = mcp.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {
                "name": "s1shell_intel_lookup",
                "arguments": {"indicator": "app.example.com"},
            },
        }
    )
    assert resp is not None
    assert resp["result"]["isError"] is False
    parsed_mcp = json.loads(resp["result"]["content"][0]["text"])
    assert parsed_mcp["virustotal"]["malicious"] == 4
