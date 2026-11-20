"""Public CISA KEV and FIRST EPSS vulnerability enrichment clients (zero target contact)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from typing import Any

import httpx

from s1shell.config import RuntimeConfig
from s1shell.cve.cache import CVECache
from s1shell.cve.models import CVERecord, compute_cve_priority
from s1shell.errors import NetworkError
from s1shell.http import build_intel_client

_KEV_CACHE_KEY = "cisa_kev_catalog_v1"


def _epss_cache_key(cve_ids: list[str]) -> str:
    joined = ",".join(sorted(cve_ids))
    return "first_epss_" + hashlib.sha256(joined.encode("utf-8")).hexdigest()


class KEVClient:
    """Fetches and caches CISA's Known Exploited Vulnerabilities (KEV) JSON feed."""

    def __init__(
        self,
        cfg: RuntimeConfig,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._cfg = cfg
        self._transport = transport

    def fetch_catalog(self) -> dict[str, dict[str, str]]:
        """Download CISA KEV catalog and map `{CVE-ID: {due_date, date_added}}`."""
        try:
            with build_intel_client(self._cfg, transport=self._transport) as client:
                resp = client.get(self._cfg.cisa_kev_url)
        except httpx.HTTPError as exc:
            raise NetworkError(f"CISA KEV request failed: {exc}") from exc

        if resp.status_code != 200:
            raise NetworkError(f"CISA KEV returned HTTP {resp.status_code}")
        try:
            payload = resp.json()
        except ValueError as exc:
            raise NetworkError(f"CISA KEV returned invalid JSON: {exc}") from exc

        catalog: dict[str, dict[str, str]] = {}
        for item in payload.get("vulnerabilities", []):
            if not isinstance(item, dict):
                continue
            cid = str(item.get("cveID", "")).strip().upper()
            if cid:
                catalog[cid] = {
                    "due_date": str(item.get("dueDate", "")),
                    "date_added": str(item.get("dateAdded", "")),
                }
        return catalog


class EPSSClient:
    """Fetches Exploit Prediction Scoring System (EPSS) probabilities from FIRST.org."""

    def __init__(
        self,
        cfg: RuntimeConfig,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._cfg = cfg
        self._transport = transport

    def fetch_scores(self, cve_ids: list[str]) -> dict[str, tuple[float, float]]:
        """Return `{CVE-ID: (epss_score, percentile)}` for up to 100 CVE IDs."""
        clean_ids = sorted({cid.strip().upper() for cid in cve_ids if cid.strip()})
        if not clean_ids:
            return {}
        results: dict[str, tuple[float, float]] = {}
        # Batch in chunks of 50 to respect URL length limits
        with build_intel_client(self._cfg, transport=self._transport) as client:
            for idx in range(0, len(clean_ids), 50):
                batch = clean_ids[idx : idx + 50]
                try:
                    resp = client.get(self._cfg.epss_api_url, params={"cve": ",".join(batch)})
                except httpx.HTTPError as exc:
                    raise NetworkError(f"FIRST EPSS request failed: {exc}") from exc
                if resp.status_code != 200:
                    raise NetworkError(f"FIRST EPSS returned HTTP {resp.status_code}")
                try:
                    data = resp.json()
                except ValueError as exc:
                    raise NetworkError(f"FIRST EPSS returned invalid JSON: {exc}") from exc
                for entry in data.get("data", []):
                    if not isinstance(entry, dict):
                        continue
                    cid = str(entry.get("cve", "")).strip().upper()
                    if not cid:
                        continue
                    try:
                        score = float(entry["epss"])
                        pct = float(entry["percentile"])
                    except (KeyError, TypeError, ValueError):
                        continue
                    results[cid] = (score, pct)
        return results


def enrich_records(
    records: list[CVERecord],
    *,
    cache: CVECache,
    ttl_seconds: int,
    kev_client: KEVClient | None = None,
    epss_client: EPSSClient | None = None,
    offline: bool = False,
    refresh: bool = False,
) -> list[CVERecord]:
    """Attach CISA KEV and FIRST EPSS risk metadata to CVE records with graceful degradation."""
    if not records:
        return records

    kev_map: dict[str, dict[str, str]] = {}
    if kev_client is not None:
        cached_kev: Any = None if refresh else cache.get(_KEV_CACHE_KEY, ttl_seconds=ttl_seconds)
        if isinstance(cached_kev, dict):
            kev_map = cached_kev
        elif not offline:
            try:
                kev_map = kev_client.fetch_catalog()
                cache.set(_KEV_CACHE_KEY, kev_map)
            except NetworkError:
                kev_map = {}

    epss_map: dict[str, tuple[float, float]] = {}
    if epss_client is not None:
        cve_ids = sorted({r.cve_id.upper() for r in records})
        e_key = _epss_cache_key(cve_ids)
        cached_epss: Any = None if refresh else cache.get(e_key, ttl_seconds=ttl_seconds)
        if isinstance(cached_epss, dict):
            for cid, pair in cached_epss.items():
                if isinstance(pair, list) and len(pair) == 2:
                    epss_map[str(cid)] = (float(pair[0]), float(pair[1]))
        elif not offline:
            try:
                epss_map = epss_client.fetch_scores(cve_ids)
                cache.set(
                    e_key,
                    json.loads(json.dumps({k: [v[0], v[1]] for k, v in epss_map.items()})),
                )
            except NetworkError:
                epss_map = {}

    enriched: list[CVERecord] = []
    for rec in records:
        cid = rec.cve_id.upper()
        kev_entry = kev_map.get(cid)
        epss_pair = epss_map.get(cid)
        in_kev = kev_entry is not None
        epss_val = epss_pair[0] if epss_pair else rec.epss_score
        enriched.append(
            replace(
                rec,
                in_kev=in_kev,
                kev_due_date=(kev_entry.get("due_date") or None) if kev_entry else None,
                epss_score=epss_val,
                epss_percentile=epss_pair[1] if epss_pair else rec.epss_percentile,
                priority=compute_cve_priority(
                    in_kev=in_kev,
                    epss_score=epss_val,
                    cvss_score=rec.cvss.base_score if rec.cvss else None,
                ),
            )
        )
    return enriched
