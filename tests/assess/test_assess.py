"""Offline unit and CLI tests for the all-in-one `s1shell assess` pipeline."""

from __future__ import annotations

import io
import json
from pathlib import Path

import httpx
import pytest

from s1shell.ai.service import AIService
from s1shell.assess.scorer import evaluate_posture
from s1shell.assess.service import AssessService
from s1shell.audit import AuditLogger
from s1shell.cli import build_parser, dispatch, main
from s1shell.config import RuntimeConfig
from s1shell.cve.models import CVERecord, CVESearchResult, CVSSMetric
from s1shell.cve.nvd import NVDClient
from s1shell.cve.rate_limit import RateLimiter
from s1shell.cve.service import CVEService
from s1shell.fingerprint.models import FingerprintMatch, FingerprintResult
from s1shell.profile.header_check import analyze_headers
from s1shell.profile.models import DNSRecords, ProfileResult, ProtocolInfo, TLSResult
from s1shell.profile.service import ProfileService
from s1shell.scope import ScopeManager

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _make_profile(
    *,
    url: str = "https://app.example.com/",
    status_code: int = 200,
    redirect_location: str | None = None,
    tls: TLSResult | None = None,
    raw_headers: list[tuple[str, str]] | None = None,
) -> ProfileResult:
    headers_list = raw_headers or []
    is_https = url.startswith("https://")
    return ProfileResult(
        target=url,
        url=url,
        pinned_ip="93.184.216.34",
        scope_id="s1",
        auth_ref="SOW-1",
        authorized_via="flag",
        dns=DNSRecords(a=["93.184.216.34"]),
        protocol=ProtocolInfo(
            status_code=status_code,
            http_version="HTTP/2",
            alpn_protocol="h2",
            redirect_location=redirect_location,
        ),
        tls=tls,
        headers=analyze_headers(headers_list, is_https=is_https),
        raw_headers=headers_list,
    )


def test_evaluate_posture_covers_tls_headers_cors_cookies_and_cves() -> None:
    raw_headers = [
        ("Server", "nginx/1.18.0"),
        ("Content-Security-Policy", "default-src 'self' 'unsafe-inline'"),
        ("Access-Control-Allow-Origin", "*"),
        ("Access-Control-Allow-Credentials", "true"),
        ("Set-Cookie", "sid=abc123"),
    ]
    prof = _make_profile(
        tls=TLSResult(
            applicable=True,
            negotiated_version="TLSv1.3",
            supported_versions=["TLSv1.1", "TLSv1.2", "TLSv1.3"],
            verified=False,
            verification_error="self-signed",
            days_remaining=10,
            not_after="2026-12-01T00:00:00Z",
        ),
        raw_headers=raw_headers,
    )
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
    cve = CVESearchResult(
        query={"keyword": "nginx 1.18.0"},
        cached=True,
        records=[
            CVERecord(
                cve_id="CVE-2021-23017",
                description="nginx resolver vuln",
                published="2021-06-01T00:00:00Z",
                last_modified="2021-06-02T00:00:00Z",
                cvss=CVSSMetric(version="3.1", base_score=7.7, severity="HIGH"),
            )
        ],
    )

    posture, findings = evaluate_posture(prof, fp, cve)
    ids = {f.id for f in findings}
    assert "TLS-001" in ids
    assert "TLS-003" in ids
    assert "TLS-004" in ids
    assert "HDR-HSTS" in ids
    assert "HDR-CSP-UNSAFE" in ids
    assert "CORS-001" in ids
    assert "COOKIE-SEC-sid" in ids
    assert "COOKIE-HTTPONLY-sid" in ids
    assert "COOKIE-SAMESITE-sid" in ids
    assert "DISC-VER-SERVER" in ids
    assert "CVE-VER" in ids
    assert posture.risk_level == "HIGH"
    assert posture.score < 55
    assert posture.grade == "F"

    # Expired TLS cert -> CRITICAL, plain HTTP without redirect -> HIGH, unversioned CVE -> INFO
    bad_http = _make_profile(
        url="http://app.example.com/",
        tls=TLSResult(
            applicable=True,
            verified=True,
            days_remaining=-2,
            not_after="2026-01-01T00:00:00Z",
        ),
        raw_headers=[
            ("Server", "nginx"),
            ("Access-Control-Allow-Origin", "*"),
        ],
    )
    unver_fp = FingerprintResult(
        target=bad_http.target,
        url=bad_http.url,
        mode="from_profile",
        scope_id="s1",
        auth_ref="SOW-1",
        matches=[
            FingerprintMatch(
                vendor="F5 / NGINX",
                product="nginx",
                category="web_server",
                confidence="high",
                version=None,
                evidence=["header:server=nginx"],
            )
        ],
    )
    posture2, findings2 = evaluate_posture(bad_http, unver_fp, cve)
    ids2 = {f.id for f in findings2}
    assert "TRANS-002" in ids2
    assert "TLS-002" in ids2
    assert "CORS-002" in ids2
    assert "DISC-BANNER-SERVER" in ids2
    assert "CVE-UNVER" in ids2
    assert posture2.risk_level == "CRITICAL"


def test_assess_service_and_cli_bundle_output_offline(
    tmp_config: RuntimeConfig,
    scope_manager: ScopeManager,
    audit_logger: AuditLogger,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    scope_manager.add("example.com", owner="ACME", auth_ref="SOW-1", expires="2099-12-31")
    nvd_payload = json.loads((FIXTURES / "nvd_cve_2021_23017.json").read_text(encoding="utf-8"))

    class StubDNSResolver:
        def resolve(self, _host: str, rdtype: str, *, lifetime: float = 5.0) -> list[str]:
            _ = lifetime
            return ["93.184.216.34"] if rdtype == "A" else []

    def target_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "Server": "nginx/1.18.0",
                "Strict-Transport-Security": "max-age=31536000",
            },
            content=b"ok",
        )

    def fake_tls(**_kwargs: object) -> tuple[TLSResult, str | None]:
        return (
            TLSResult(
                applicable=True,
                negotiated_version="TLSv1.3",
                cipher_suite="TLS_AES_256_GCM_SHA384",
                supported_versions=["TLSv1.1", "TLSv1.2", "TLSv1.3"],
                verified=True,
                subject="CN=example.com",
                issuer="CN=Test CA",
                sans=["DNS:example.com"],
                days_remaining=80,
            ),
            "h2",
        )

    def nvd_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=nvd_payload)

    def ai_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "content": [{"type": "text", "text": "Disable TLS 1.1 and add CSP."}],
                "usage": {"input_tokens": 50, "output_tokens": 12},
            },
        )

    tmp_config.env_file.write_text(
        'ANTHROPIC_API_KEY="sk-ant-api03-testkey0000"\n', encoding="utf-8"
    )

    prof_svc = ProfileService(
        tmp_config,
        scope_manager=scope_manager,
        audit_logger=audit_logger,
        dns_resolver=StubDNSResolver(),
        tls_inspector=fake_tls,
        http_transport=httpx.MockTransport(target_handler),
    )
    cve_svc = CVEService(
        tmp_config,
        nvd_client=NVDClient(
            tmp_config,
            rate_limiter=RateLimiter(max_requests=50, window_seconds=30.0),
            transport=httpx.MockTransport(nvd_handler),
        ),
        audit_logger=audit_logger,
    )
    ai_svc = AIService(
        tmp_config,
        audit_logger=audit_logger,
        transport=httpx.MockTransport(ai_handler),
    )
    assess_svc = AssessService(
        tmp_config,
        scope_manager=scope_manager,
        audit_logger=audit_logger,
        profile_service=prof_svc,
        cve_service=cve_svc,
        ai_service=ai_svc,
    )

    out_dir = tmp_path / "bundle"
    parser = build_parser()

    for fmt in ("table", "json", "md", "html"):
        cli_args = [
            "--home",
            str(tmp_config.home_dir),
            "--no-color",
            "--format",
            fmt,
            "assess",
            "https://example.com",
            "--authorized",
            "--operator",
            "Jane Doe",
        ]
        if fmt == "table":
            cli_args.extend(["--ai", "--out-dir", str(out_dir)])
        parsed = parser.parse_args(cli_args)
        out = io.StringIO()
        code = dispatch(
            parsed,
            scope_manager=scope_manager,
            assess_service=assess_svc,
            stdout=out,
            stderr=io.StringIO(),
        )
        assert code == 0
        text = out.getvalue()
        if fmt == "json":
            data = json.loads(text)
            assert data["artifact_type"] == "assess_report"
            assert data["posture"]["grade"] in {"A", "B", "C", "D", "F"}
            assert len(data["cve"]["records"]) >= 1
        elif fmt == "html":
            assert "<html" in text.lower()
            assert "Jane Doe" in text
        elif fmt == "md":
            assert "# S1shell Assessment:" in text
            assert "TLS-004" in text
        else:
            assert "Assessment Posture Summary" in text
            assert "Disable TLS 1.1 and add CSP." in text

    for expected in (
        "profile.json",
        "fingerprint.json",
        "cves.json",
        "report.md",
        "report.html",
        "assess.json",
    ):
        assert (out_dir / expected).is_file()


def test_assess_enforces_scope_and_auth_gates(tmp_path: Path) -> None:
    home = tmp_path / ".s1shell"

    # Empty scope -> exit 2
    code_oos = main(
        ["--home", str(home), "assess", "https://example.com", "--authorized"],
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )
    assert code_oos == 2

    # Add scope, omit --authorized in non-TTY -> exit 3
    main(
        [
            "--home",
            str(home),
            "scope",
            "add",
            "127.0.0.1",
            "--owner",
            "Lab",
            "--ref",
            "LAB-1",
            "--expires",
            "2099-12-31",
        ],
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )
    import s1shell.guard as guard_mod

    orig_stdin = guard_mod.sys.stdin
    try:
        guard_mod.sys.stdin = io.StringIO("")
        code_unauth = main(
            ["--home", str(home), "assess", "https://127.0.0.1"],
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )
        assert code_unauth == 3
    finally:
        guard_mod.sys.stdin = orig_stdin
