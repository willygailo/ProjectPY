"""Tests for FingerprintService offline profile mode and guarded live mode."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from s1shell.audit import AuditLogger
from s1shell.config import RuntimeConfig
from s1shell.errors import OutOfScopeError, UnauthorizedError
from s1shell.fingerprint.service import FingerprintService
from s1shell.profile.models import TLSResult
from s1shell.scope import ScopeManager

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_fingerprint_from_profile_works_offline(tmp_config: RuntimeConfig) -> None:
    svc = FingerprintService(tmp_config)
    res = svc.from_profile(FIXTURES / "sample_profile.json")
    assert res.mode == "from_profile"
    assert res.target == "https://app.example.com"
    assert res.matches[0].product == "Cloudflare CDN/WAF"


def test_fingerprint_live_respects_scope_and_auth_gates(
    tmp_config: RuntimeConfig,
    scope_manager: ScopeManager,
    audit_logger: AuditLogger,
) -> None:
    calls = [0]

    def handler(_request: httpx.Request) -> httpx.Response:
        calls[0] += 1
        return httpx.Response(200, headers={"Server": "nginx/1.24.0"})

    def fake_tls(**_kwargs: object) -> tuple[TLSResult, str | None]:
        return TLSResult(applicable=True, verified=True, issuer="CN=Test CA"), "h2"

    svc = FingerprintService(
        tmp_config,
        scope_manager=scope_manager,
        audit_logger=audit_logger,
        tls_inspector=fake_tls,
        http_transport=httpx.MockTransport(handler),
    )

    with pytest.raises(OutOfScopeError):
        svc.inspect_target("https://outofscope.example", authorized=True)

    scope_manager.add("example.com", owner="ACME", auth_ref="SOW-1", expires="2099-12-31")
    with pytest.raises(UnauthorizedError):
        svc.inspect_target("https://example.com", authorized=False)
    assert calls[0] == 0

    res = svc.inspect_target("https://example.com", authorized=True)
    assert res.mode == "live"
    assert [m.product for m in res.matches] == ["nginx"]
    assert calls[0] == 1
