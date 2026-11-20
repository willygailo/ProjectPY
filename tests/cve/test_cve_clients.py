"""Tests for mocked NVD 2.0 and CVE.org clients plus rate limiter."""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from s1shell.config import RuntimeConfig
from s1shell.cve.cveorg import CVEOrgClient
from s1shell.cve.nvd import NVDClient, parse_nvd_payload
from s1shell.cve.rate_limit import RateLimiter

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_rate_limiter_enforces_window_with_fake_clock() -> None:
    now = [0.0]
    sleeps: list[float] = []

    def fake_sleep(dt: float) -> None:
        sleeps.append(dt)
        now[0] += dt

    limiter = RateLimiter(
        max_requests=2,
        window_seconds=30.0,
        clock=lambda: now[0],
        sleeper=fake_sleep,
    )
    limiter.acquire()
    limiter.acquire()
    assert sleeps == []

    limiter.acquire()
    assert sleeps == [30.0]


def test_nvd_client_passes_api_key_and_retries_429(tmp_config: RuntimeConfig) -> None:
    payload = json.loads((FIXTURES / "nvd_cve_2021_23017.json").read_text(encoding="utf-8"))
    seen_headers: list[dict[str, str]] = []
    calls = [0]

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.append(dict(request.headers))
        calls[0] += 1
        if calls[0] == 1:
            return httpx.Response(429, headers={"Retry-After": "1"})
        return httpx.Response(200, json=payload)

    sleeps: list[float] = []
    client = NVDClient(
        tmp_config,
        api_key="test-nvd-key",
        rate_limiter=RateLimiter(max_requests=50, window_seconds=30.0),
        transport=httpx.MockTransport(handler),
        sleeper=sleeps.append,
    )
    res = client.fetch({"keywordSearch": "nginx 1.18"})
    assert len(parse_nvd_payload(res)) == 2
    assert calls[0] == 2
    assert sleeps == [1.0]
    assert seen_headers[0]["apikey"] == "test-nvd-key"
    assert "S1shell/" in seen_headers[0]["user-agent"]


def test_cveorg_client_parses_cna_record(tmp_config: RuntimeConfig) -> None:
    payload = json.loads((FIXTURES / "cveorg_2021_23017.json").read_text(encoding="utf-8"))

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("CVE-2021-23017"):
            return httpx.Response(200, json=payload)
        return httpx.Response(404)

    client = CVEOrgClient(tmp_config, transport=httpx.MockTransport(handler))
    rec = client.fetch_cve("CVE-2021-23017")
    assert rec is not None
    assert "Off-by-one" in rec.description
    assert client.fetch_cve("CVE-2099-99999") is None
