"""Offline tests for KEV/EPSS priority, multi-CVE get, CPE ranges, and OSV.dev SBOM audits."""

from __future__ import annotations

import io
import json
from pathlib import Path

import httpx

from s1shell.audit import AuditLogger
from s1shell.cli import build_parser, dispatch
from s1shell.config import RuntimeConfig
from s1shell.cve.audit_deps import DependencyAuditService, OSVClient, parse_dependency_file
from s1shell.cve.enrichment import EPSSClient, KEVClient
from s1shell.cve.models import CPEAffectedRange, compute_cve_priority
from s1shell.cve.nvd import NVDClient, is_version_affected
from s1shell.cve.rate_limit import RateLimiter
from s1shell.cve.service import CVEService

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_ssvc_priority_and_cpe_version_bounds() -> None:
    assert compute_cve_priority(in_kev=True, epss_score=0.05, cvss_score=5.0) == "P0-IMMEDIATE"
    assert compute_cve_priority(in_kev=False, epss_score=0.72, cvss_score=7.5) == "P0-IMMEDIATE"
    assert compute_cve_priority(in_kev=False, epss_score=0.02, cvss_score=9.8) == "P1-URGENT"
    assert compute_cve_priority(in_kev=False, epss_score=0.02, cvss_score=7.5) == "P2-SCHEDULED"
    assert compute_cve_priority(in_kev=False, epss_score=0.01, cvss_score=5.3) == "P3-MONITOR"

    ranges = [
        CPEAffectedRange(
            criteria="cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
            vulnerable=True,
            version_start_including="1.18.0",
            version_end_excluding="1.20.1",
        )
    ]
    assert is_version_affected("1.18.0", ranges, cpe_vendor="f5", cpe_product="nginx") is True
    assert is_version_affected("1.20.1", ranges, cpe_vendor="f5", cpe_product="nginx") is False
    assert is_version_affected("1.17.9", ranges, cpe_vendor="f5", cpe_product="nginx") is False


def test_parse_lockfiles_and_cyclonedx_sbom(tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("# comment\nrequests==2.31.0\nJinja2[i18n]==3.1.2\n-r base.txt\n", "utf-8")
    fmt_r, pkgs_r = parse_dependency_file(req)
    assert fmt_r == "requirements.txt"
    assert [(p.ecosystem, p.name, p.version) for p in pkgs_r] == [
        ("PyPI", "requests", "2.31.0"),
        ("PyPI", "Jinja2", "3.1.2"),
    ]

    pkg_lock = tmp_path / "package-lock.json"
    pkg_lock.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "demo", "version": "1.0.0"},
                    "node_modules/lodash": {"version": "4.17.15"},
                },
            }
        ),
        "utf-8",
    )
    fmt_n, pkgs_n = parse_dependency_file(pkg_lock)
    assert fmt_n == "package-lock.json"
    assert pkgs_n[0].ecosystem == "npm" and pkgs_n[0].name == "lodash"

    gomod = tmp_path / "go.mod"
    gomod.write_text("module ex\nrequire (\n\tgolang.org/x/net v0.17.0\n)\n", "utf-8")
    fmt_g, pkgs_g = parse_dependency_file(gomod)
    assert fmt_g == "go.mod"
    assert pkgs_g[0].ecosystem == "Go" and pkgs_g[0].version == "0.17.0"

    cargo = tmp_path / "Cargo.lock"
    cargo.write_text('[[package]]\nname = "openssl"\nversion = "0.10.55"\n', "utf-8")
    fmt_c, pkgs_c = parse_dependency_file(cargo)
    assert fmt_c == "Cargo.lock"
    assert pkgs_c[0].ecosystem == "crates.io" and pkgs_c[0].name == "openssl"

    sbom = tmp_path / "sbom.cdx.json"
    sbom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {"name": "urllib3", "purl": "pkg:pypi/urllib3@1.26.5"},
                    {
                        "name": "log4j-core",
                        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                    },
                ],
            }
        ),
        "utf-8",
    )
    fmt_s, pkgs_s = parse_dependency_file(sbom)
    assert fmt_s == "cyclonedx"
    assert len(pkgs_s) == 2
    assert pkgs_s[1].ecosystem == "Maven"
    assert pkgs_s[1].name == "org.apache.logging.log4j:log4j-core"


def test_cve_audit_cli_osv_kev_epss_sarif_and_policy_gate(
    tmp_config: RuntimeConfig,
    audit_logger: AuditLogger,
    tmp_path: Path,
) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("urllib3==1.26.5\n", "utf-8")

    def osv_handler(request: httpx.Request) -> httpx.Response:
        _ = request
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "vulns": [
                            {
                                "id": "GHSA-xxxx-yyyy-zzzz",
                                "aliases": ["CVE-2023-45803"],
                                "summary": "urllib3 Cookie leak on redirect",
                                "database_specific": {"severity": "HIGH"},
                                "affected": [
                                    {
                                        "package": {"name": "urllib3"},
                                        "ranges": [{"events": [{"fixed": "1.26.18"}]}],
                                    }
                                ],
                                "references": [{"url": "https://osv.dev/GHSA-xxxx-yyyy-zzzz"}],
                            }
                        ]
                    }
                ]
            },
        )

    def kev_handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "vulnerabilities": [
                    {"cveID": "CVE-2023-45803", "dueDate": "2024-01-01", "dateAdded": "2023-12-01"}
                ]
            },
        )

    def epss_handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"data": [{"cve": "CVE-2023-45803", "epss": "0.61", "percentile": "0.97"}]},
        )

    dep_svc = DependencyAuditService(
        tmp_config,
        osv_client=OSVClient(tmp_config, transport=httpx.MockTransport(osv_handler)),
        kev_client=KEVClient(tmp_config, transport=httpx.MockTransport(kev_handler)),
        epss_client=EPSSClient(tmp_config, transport=httpx.MockTransport(epss_handler)),
        audit_logger=audit_logger,
    )

    parser = build_parser()
    sarif_out = io.StringIO()
    parsed = parser.parse_args(
        [
            "--home",
            str(tmp_config.home_dir),
            "--format",
            "sarif",
            "cve",
            "audit",
            str(req),
            "--enrich",
        ]
    )
    assert dispatch(parsed, dep_audit_service=dep_svc, stdout=sarif_out, stderr=io.StringIO()) == 0
    sarif_doc = json.loads(sarif_out.getvalue())
    assert sarif_doc["version"] == "2.1.0"
    assert sarif_doc["runs"][0]["results"][0]["ruleId"] == "CVE-2023-45803"

    # Second run works completely offline from SQLite cache AND triggers CI gate (--fail-on)
    parsed_gate = parser.parse_args(
        [
            "--home",
            str(tmp_config.home_dir),
            "--format",
            "json",
            "cve",
            "audit",
            str(req),
            "--offline",
            "--enrich",
            "--fail-on",
            "HIGH",
        ]
    )
    json_out = io.StringIO()
    try:
        dispatch(parsed_gate, dep_audit_service=dep_svc, stdout=json_out, stderr=io.StringIO())
        raise AssertionError("Expected PolicyGateError")
    except Exception as exc:
        assert getattr(exc, "exit_code", None) == 4
    data = json.loads(json_out.getvalue())
    assert data["cached"] is True
    assert data["vulnerabilities"][0]["in_kev"] is True
    assert data["vulnerabilities"][0]["priority"] == "P0-IMMEDIATE"
    assert data["vulnerabilities"][0]["fixed_versions"] == ["1.26.18"]


def test_cve_get_multi_id_with_enrichment(
    tmp_config: RuntimeConfig,
    audit_logger: AuditLogger,
) -> None:
    nvd_payload = json.loads((FIXTURES / "nvd_cve_2021_23017.json").read_text(encoding="utf-8"))

    def nvd_handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=nvd_payload)

    def kev_handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"vulnerabilities": [{"cveID": "CVE-2021-23017", "dueDate": "2022-01-01"}]},
        )

    def epss_handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"data": [{"cve": "CVE-2021-23017", "epss": "0.85", "percentile": "0.99"}]},
        )

    cve_svc = CVEService(
        tmp_config,
        nvd_client=NVDClient(
            tmp_config,
            rate_limiter=RateLimiter(max_requests=50, window_seconds=30.0),
            transport=httpx.MockTransport(nvd_handler),
        ),
        kev_client=KEVClient(tmp_config, transport=httpx.MockTransport(kev_handler)),
        epss_client=EPSSClient(tmp_config, transport=httpx.MockTransport(epss_handler)),
        audit_logger=audit_logger,
    )
    res = cve_svc.get_many(["CVE-2021-23017", "cve-2021-23017"], enrich=True)
    assert len(res.records) == 1
    assert res.records[0].in_kev is True
    assert res.records[0].priority == "P0-IMMEDIATE"
