"""Tests for SQLite CVE TTL cache."""

from __future__ import annotations

from pathlib import Path

from s1shell.cve.cache import CVECache


def test_cve_cache_hit_miss_ttl_and_clear(tmp_path: Path) -> None:
    now = [1000.0]
    cache = CVECache(tmp_path / "cache.db", clock=lambda: now[0])

    assert cache.get("k1", ttl_seconds=60) is None
    cache.set("k1", {"vulnerabilities": [1, 2]})
    assert cache.get("k1", ttl_seconds=60) == {"vulnerabilities": [1, 2]}

    now[0] = 1061.0
    assert cache.get("k1", ttl_seconds=60) is None

    cache.set("k2", {"ok": True})
    assert cache.clear() == 2
    assert cache.get("k2", ttl_seconds=60) is None
