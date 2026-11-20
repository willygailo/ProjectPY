"""Tests for CVEService search, get, filtering, caching, and offline mode."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from s1shell.audit import AuditLogger
from s1shell.config import RuntimeConfig
from s1shell.cve.cache import CVECache
from s1shell.cve.cveorg import CVEOrgClient
from s1shell.cve.models import CVESearchFilter
from s1shell.cve.nvd import NVDClient
from s1shell.cve.rate_limit import RateLimiter
from s1shell.cve.service import CVEService
from s1shell.errors import NetworkError, ValidationError

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _build_service(tmp_config: RuntimeConfig, nvd_calls: list[int]) -> CVEService:
    nvd_payload = json.loads((FIXTURES / "nvd_cve_2021_23017.json").read_text(encoding="utf-8"))
    cveorg_payload = json.loads((FIXTURES / "cveorg_2021_23017.json").read_text(encoding="utf-8"))

    def nvd_handler(_request: httpx.Request) -> httpx.Response:
        nvd_calls[0] += 1
        return httpx.Response(200, json=nvd_payload)

    def cveorg_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=cveorg_payload)

    return CVEService(
        tmp_config,
        cache=CVECache(tmp_config.cache_db),
        nvd_client=NVDClient(
            tmp_config,
            rate_limiter=RateLimiter(max_requests=50, window_seconds=30.0),
            transport=httpx.MockTransport(nvd_handler),
        ),
        cveorg_client=CVEOrgClient(tmp_config, transport=httpx.MockTransport(cveorg_handler)),
        audit_logger=AuditLogger(tmp_config.audit_log),
    )


def test_cve_search_filters_and_caches(tmp_config: RuntimeConfig) -> None:
    calls = [0]
    svc = _build_service(tmp_config, calls)

    res1 = svc.search(CVESearchFilter(keyword="nginx 1.18", min_cvss=7.0))
    assert res1.cached is False
    assert calls[0] == 1
    assert [r.cve_id for r in res1.records] == ["CVE-2021-23017"]

    # Second identical query hits SQLite cache without calling NVD
    res2 = svc.search(CVESearchFilter(keyword="nginx 1.18", min_cvss=7.0))
    assert res2.cached is True
    assert calls[0] == 1

    # Offline works when cached; raises on uncached
    res3 = svc.search(CVESearchFilter(keyword="nginx 1.18", min_cvss=7.0), offline=True)
    assert res3.cached is True
    with pytest.raises(NetworkError):
        svc.search(CVESearchFilter(cpe="cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"), offline=True)


def test_cve_get_enriches_with_cveorg_and_validates_id(tmp_config: RuntimeConfig) -> None:
    calls = [0]
    svc = _build_service(tmp_config, calls)

    res = svc.get("cve-2021-23017")
    assert len(res.records) == 1
    assert res.records[0].source == "nvd+cve.org"
    assert "Authoritative CVE.org description" in res.records[0].description

    with pytest.raises(ValidationError):
        svc.get("not-a-cve")


def test_cve_search_uses_full_page_with_client_filter_and_from_fingerprint(
    tmp_config: RuntimeConfig, tmp_path: Path
) -> None:
    nvd_payload = json.loads((FIXTURES / "nvd_cve_2021_23017.json").read_text(encoding="utf-8"))
    seen_urls: list[str] = []

    def nvd_handler(request: httpx.Request) -> httpx.Response:
        seen_urls.append(str(request.url))
        return httpx.Response(200, json=nvd_payload)

    def cveorg_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    svc = CVEService(
        tmp_config,
        cache=CVECache(tmp_config.cache_db),
        nvd_client=NVDClient(
            tmp_config,
            rate_limiter=RateLimiter(max_requests=50, window_seconds=30.0),
            transport=httpx.MockTransport(nvd_handler),
        ),
        cveorg_client=CVEOrgClient(tmp_config, transport=httpx.MockTransport(cveorg_handler)),
        audit_logger=AuditLogger(tmp_config.audit_log),
    )

    filtered = svc.search(CVESearchFilter(keyword="nginx", min_cvss=7.0, limit=1))
    assert len(filtered.records) == 1
    assert "resultsPerPage=200" in seen_urls[0]

    fp_path = tmp_path / "fp.json"
    fp_path.write_text(
        json.dumps(
            {
                "artifact_type": "fingerprint_report",
                "matches": [{"product": "nginx", "version": "1.18.0"}],
            }
        ),
        encoding="utf-8",
    )
    correl = svc.search_from_fingerprint(
        fp_path,
        filters=CVESearchFilter(min_cvss=7.0, limit=5),
    )
    assert [r.cve_id for r in correl.records] == ["CVE-2021-23017"]
    assert "keywordSearch=nginx+1.18.0" in seen_urls[1]
