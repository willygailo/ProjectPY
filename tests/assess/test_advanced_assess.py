"""Offline tests for presets, waivers, compliance, remediation playbooks, diff, SARIF, & batch."""

from __future__ import annotations

import io
import json
from pathlib import Path

import httpx
import pytest

from s1shell.assess.diff import diff_assessments
from s1shell.assess.remediate import generate_remediation_from_file, generate_remediation_plan
from s1shell.assess.scorer import evaluate_posture_with_suppressions
from s1shell.assess.service import AssessService
from s1shell.audit import AuditLogger
from s1shell.cli import build_parser, dispatch
from s1shell.config import RuntimeConfig
from s1shell.errors import PolicyGateError
from s1shell.fingerprint.models import FingerprintMatch, FingerprintResult
from s1shell.models import dumps_json
from s1shell.profile.header_check import analyze_headers
from s1shell.profile.html_check import analyze_html_body
from s1shell.profile.models import DNSRecords, ProfileResult, ProtocolInfo, TLSResult
from s1shell.profile.service import ProfileService
from s1shell.scope import ScopeManager


def _rich_profile() -> ProfileResult:
    raw_headers = [
        ("Server", "nginx/1.18.0"),
        ("X-Debug-Token", "deadbeef"),
        ("Cache-Control", "public"),
        ("Set-Cookie", "sid=abc; Domain=.example.com; Max-Age=9999999"),
    ]
    html = analyze_html_body(
        b'<html><body><a href="https://ext.example" target="_blank">x</a>'
        b'<form method="GET"><input type="password" name="p"></form></body></html>',
        headers=[("Content-Type", "text/html")],
        page_url="https://api.example.com/",
    )
    return ProfileResult(
        target="https://api.example.com",
        url="https://api.example.com/",
        pinned_ip="93.184.216.34",
        scope_id="s1",
        auth_ref="SOW-1",
        authorized_via="flag",
        dns=DNSRecords(
            a=["93.184.216.34"],
            mx=["10 mail.example.com"],
            spf="v=spf1 include:a include:b include:c include:d include:e "
            "include:f include:g include:h include:i include:j include:k ?all",
            spf_lookup_count=11,
            dmarc=None,
            dnssec_present=False,
            security_checked=True,
        ),
        protocol=ProtocolInfo(
            status_code=302,
            http_version="HTTP/2",
            alpn_protocol="h2",
            redirect_location="http://api.example.com/downgrade",
            methods_checked=True,
            allowed_methods=["GET", "OPTIONS", "TRACE"],
            risky_methods=["TRACE"],
        ),
        tls=TLSResult(
            applicable=True,
            negotiated_version="TLSv1.2",
            supported_versions=["TLSv1.2"],
            verified=True,
            days_remaining=60,
        ),
        headers=analyze_headers(raw_headers, is_https=True),
        raw_headers=raw_headers,
        html=html,
    )


def test_presets_waivers_new_checks_and_compliance_tags() -> None:
    prof = _rich_profile()
    fp = FingerprintResult(
        target=prof.target,
        url=prof.url,
        mode="from_profile",
        scope_id="s1",
        auth_ref="SOW-1",
        matches=[
            FingerprintMatch(
                vendor="F5 / NGINX",
                product="nginx",
                category="web_server",
                confidence="high",
                version="1.18.0",
                evidence=["header:server=nginx/1.18.0"],
            )
        ],
    )

    _, web_findings, _ = evaluate_posture_with_suppressions(prof, fp, preset="web")
    web_ids = {f.id for f in web_findings}
    assert {
        "TRANS-003",
        "METH-001",
        "HDR-CACHE",
        "DISC-DBG-X-DEBUG-TOKEN",
        "COOKIE-SCOPE-sid",
        "DNS-003-NEUTRAL",
        "DNS-003-LOOKUP",
        "DNS-006",
        "HTML-003",
        "HTML-004",
    }.issubset(web_ids)
    assert all(f.owasp and f.nist for f in web_findings)

    # API preset suppresses HTML & clickjacking noise transparently
    _, api_findings, api_suppressed = evaluate_posture_with_suppressions(
        prof,
        fp,
        preset="api",
        ignore_findings={"DNS-006"},
    )
    api_ids = {f.id for f in api_findings}
    sup_ids = {f.id for f in api_suppressed}
    assert "HTML-003" not in api_ids and "HTML-003" in sup_ids
    assert "HDR-XFO" not in api_ids and "HDR-XFO" in sup_ids
    assert "DNS-006" not in api_ids and "DNS-006" in sup_ids

    # Strict preset elevates TLS-009 / DNS-002 / DNS-005 from INFO -> LOW
    _, strict_findings, _ = evaluate_posture_with_suppressions(prof, fp, preset="strict")
    strict_map = {f.id: f.severity for f in strict_findings}
    assert strict_map["TLS-009"] == "LOW"
    assert strict_map["DNS-002"] == "LOW"
    assert strict_map["DNS-005"] == "LOW"


def test_deterministic_remediation_playbook_stacks_and_cli(tmp_path: Path) -> None:
    prof = _rich_profile()
    fp = FingerprintResult(
        target=prof.target,
        url=prof.url,
        mode="from_profile",
        scope_id="s1",
        auth_ref="SOW-1",
        matches=[
            FingerprintMatch(
                vendor="F5 / NGINX",
                product="nginx",
                category="web_server",
                confidence="high",
                version="1.18.0",
                evidence=["header:server=nginx/1.18.0"],
            )
        ],
    )
    _, findings, _ = evaluate_posture_with_suppressions(prof, fp)
    plan = generate_remediation_plan(
        target_url=prof.url,
        findings=findings,
        fingerprint_matches=[{"product": "nginx"}],
        stack="auto",
    )
    assert plan.selected_stack == "nginx"
    combined_cfg = "\n".join(s.config for s in plan.snippets)
    assert "server_tokens off;" in combined_cfg
    assert "Strict-Transport-Security" in combined_cfg
    assert "_dmarc.api.example.com" in combined_cfg

    for stack in ("apache", "caddy", "express", "generic"):
        alt = generate_remediation_plan(
            target_url=prof.url,
            findings=findings,
            fingerprint_matches=[],
            stack=stack,
        )
        assert alt.selected_stack == stack
        assert len(alt.snippets) >= 1

    # CLI `s1shell remediate assess.json`
    assess_file = tmp_path / "assess.json"
    assess_file.write_text(
        json.dumps(
            {
                "artifact_type": "assess_report",
                "url": prof.url,
                "fingerprint": {"matches": [{"product": "nginx"}]},
                "findings": [{"id": "HDR-HSTS"}, {"id": "METH-001"}],
            }
        ),
        encoding="utf-8",
    )
    loaded = generate_remediation_from_file(assess_file)
    assert loaded.selected_stack == "nginx"

    parser = build_parser()
    out = io.StringIO()
    parsed = parser.parse_args(["remediate", str(assess_file), "--format", "md"])
    assert dispatch(parsed, stdout=out, stderr=io.StringIO()) == 0
    assert "NGINX Security Headers" in out.getvalue()


def test_batch_assessment_html_dashboard_ci_gate_and_diff(
    tmp_config: RuntimeConfig,
    scope_manager: ScopeManager,
    audit_logger: AuditLogger,
    tmp_path: Path,
) -> None:
    scope_manager.add("ok.example.com", owner="ACME", auth_ref="SOW-1", expires="2099-12-31")

    class StubDNS:
        def resolve(self, _h: str, rdtype: str, lifetime: float = 5.0) -> list[str]:
            _ = lifetime
            return ["93.184.216.34"] if rdtype == "A" else []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "OPTIONS":
            return httpx.Response(200, headers={"Allow": "GET, HEAD, TRACE"})
        return httpx.Response(200, headers={"Server": "nginx/1.24.0"}, content=b"ok")

    def fake_tls(**_kw: object) -> tuple[TLSResult, str | None]:
        return (
            TLSResult(
                applicable=True,
                negotiated_version="TLSv1.3",
                supported_versions=["TLSv1.3"],
                verified=True,
                days_remaining=90,
            ),
            "h2",
        )

    prof_svc = ProfileService(
        tmp_config,
        scope_manager=scope_manager,
        audit_logger=audit_logger,
        dns_resolver=StubDNS(),
        tls_inspector=fake_tls,
        http_transport=httpx.MockTransport(handler),
    )
    assess_svc = AssessService(
        tmp_config,
        scope_manager=scope_manager,
        audit_logger=audit_logger,
        profile_service=prof_svc,
    )

    targets_file = tmp_path / "targets.txt"
    targets_file.write_text("https://ok.example.com\nhttps://oos.example.com\n", encoding="utf-8")
    out_dir = tmp_path / "batch_out"

    parser = build_parser()
    parsed = parser.parse_args(
        [
            "--home",
            str(tmp_config.home_dir),
            "--format",
            "html",
            "assess",
            "--targets-file",
            str(targets_file),
            "--authorized",
            "--delay",
            "0",
            "--skip-cve",
            "--no-remediate",
            "--check-methods",
            "--fail-on",
            "HIGH",
            "--out-dir",
            str(out_dir),
        ]
    )
    html_out = io.StringIO()
    with pytest.raises(PolicyGateError):
        dispatch(
            parsed,
            scope_manager=scope_manager,
            assess_service=assess_svc,
            stdout=html_out,
            stderr=io.StringIO(),
        )
    assert "Batch Assessment Report" in html_out.getvalue()
    assert (out_dir / "batch_report.html").is_file()
    assert (out_dir / "batch_summary.json").is_file()
    first_assess_path = out_dir / "01_https_ok.example.com" / "assess.json"
    first_assess = json.loads(first_assess_path.read_text(encoding="utf-8"))
    assert first_assess["remediation_snippets"] == []

    # Posture drift diff & regression detection
    base_json = tmp_path / "base.json"
    curr_json = tmp_path / "curr.json"
    base_json.write_text(
        dumps_json(
            {
                "artifact_type": "assess_report",
                "url": "https://ok.example.com/",
                "posture": {"score": 92, "grade": "A", "risk_level": "LOW"},
                "findings": [],
                "profile": {"tls": {"days_remaining": 80}},
            }
        ),
        encoding="utf-8",
    )
    curr_json.write_text(
        dumps_json(
            {
                "artifact_type": "assess_report",
                "url": "https://ok.example.com/",
                "posture": {"score": 65, "grade": "D", "risk_level": "HIGH"},
                "findings": [
                    {
                        "id": "METH-001",
                        "severity": "HIGH",
                        "category": "methods",
                        "title": "Risky methods",
                    }
                ],
                "profile": {"tls": {"days_remaining": 70}},
            }
        ),
        encoding="utf-8",
    )
    diff_res = diff_assessments(base_json, curr_json)
    assert diff_res.regressed is True
    assert diff_res.score_delta == -27
    assert diff_res.cert_days_delta == -10
    assert diff_res.new_findings[0]["id"] == "METH-001"
