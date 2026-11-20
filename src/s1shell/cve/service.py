"""CVE research orchestrator: cache -> NVD/CVE.org -> KEV/EPSS enrichment -> audit logging."""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import replace
from pathlib import Path

from s1shell.audit import AuditEvent, AuditLogger
from s1shell.config import RuntimeConfig
from s1shell.cve.cache import CVECache
from s1shell.cve.cveorg import CVEOrgClient
from s1shell.cve.enrichment import EPSSClient, KEVClient, enrich_records
from s1shell.cve.models import CVERecord, CVESearchFilter, CVESearchResult
from s1shell.cve.nvd import NVDClient, is_version_affected, parse_nvd_payload
from s1shell.errors import ExitCode, NetworkError, ValidationError

_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def validate_cve_id(cve_id: str) -> str:
    """Validate and normalize a CVE identifier."""
    norm = cve_id.strip().upper()
    if not _CVE_ID_RE.match(norm):
        raise ValidationError(f"Invalid CVE ID format: '{cve_id}'. Expected CVE-YYYY-NNNN.")
    return norm


def _build_cache_key(kind: str, params: dict[str, str]) -> str:
    serialized = json.dumps({"kind": kind, "params": params}, sort_keys=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _sort_key(rec: CVERecord) -> tuple[int, float, float, str]:
    """Rank CVEs by CISA KEV status, EPSS probability, CVSS base score, and publish date."""
    return (
        1 if rec.in_kev else 0,
        rec.epss_score if rec.epss_score is not None else -1.0,
        rec.cvss.base_score if rec.cvss else -1.0,
        rec.published,
    )


def _filter_and_sort(records: list[CVERecord], filters: CVESearchFilter) -> list[CVERecord]:
    filtered: list[CVERecord] = []
    target_sev = filters.severity.upper() if filters.severity else None
    after = filters.published_after
    before = filters.published_before

    for rec in records:
        score = rec.cvss.base_score if rec.cvss else None
        sev = rec.cvss.severity.upper() if rec.cvss else None

        if filters.min_cvss is not None and (score is None or score < filters.min_cvss):
            continue
        if target_sev is not None and sev != target_sev:
            continue
        if filters.kev_only and not rec.in_kev:
            continue

        pub_date = rec.published[:10] if len(rec.published) >= 10 else ""
        if after and (not pub_date or pub_date < after):
            continue
        if before and (not pub_date or pub_date > before):
            continue
        filtered.append(rec)

    filtered.sort(key=_sort_key, reverse=True)
    return filtered[: filters.limit]


def _validate_date_arg(value: str | None, label: str) -> None:
    if value is not None and not _DATE_RE.match(value):
        raise ValidationError(f"Invalid {label} date '{value}'. Expected YYYY-MM-DD.")


class CVEService:
    """Coordinates cached NVD/CVE.org/KEV/EPSS lookups, filtering, and intel audit logging."""

    def __init__(
        self,
        cfg: RuntimeConfig,
        *,
        cache: CVECache | None = None,
        nvd_client: NVDClient | None = None,
        cveorg_client: CVEOrgClient | None = None,
        kev_client: KEVClient | None = None,
        epss_client: EPSSClient | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self.cfg = cfg
        self.cache = cache if cache is not None else CVECache(cfg.cache_db)
        self.nvd_client = nvd_client if nvd_client is not None else NVDClient(cfg)
        self.cveorg_client = cveorg_client if cveorg_client is not None else CVEOrgClient(cfg)
        self.kev_client = kev_client if kev_client is not None else KEVClient(cfg)
        self.epss_client = epss_client if epss_client is not None else EPSSClient(cfg)
        self.audit_logger = audit_logger if audit_logger is not None else AuditLogger(cfg.audit_log)

    def search(
        self,
        filters: CVESearchFilter,
        *,
        refresh: bool = False,
        offline: bool = False,
        enrich: bool = False,
    ) -> CVESearchResult:
        """Search NVD by keyword or CPE with caching and client-side triage filters."""
        if not filters.keyword and not filters.cpe:
            raise ValidationError("Provide either --keyword or --cpe for `cve search`.")
        if filters.limit <= 0:
            raise ValidationError("--limit must be a positive integer.")
        _validate_date_arg(filters.published_after, "published-after")
        _validate_date_arg(filters.published_before, "published-before")

        has_client_filter = (
            filters.min_cvss is not None or filters.severity is not None or filters.kev_only
        )
        fetch_page_size = 200 if has_client_filter else min(max(filters.limit, 1), 200)
        params: dict[str, str] = {"resultsPerPage": str(fetch_page_size)}
        if filters.keyword:
            params["keywordSearch"] = filters.keyword.strip()
        if filters.cpe:
            params["cpeName"] = filters.cpe.strip()
        if filters.published_after:
            params["pubStartDate"] = f"{filters.published_after}T00:00:00.000"
        if filters.published_before:
            params["pubEndDate"] = f"{filters.published_before}T23:59:59.999"

        cache_key = _build_cache_key("nvd_search", params)
        cached = False
        payload = (
            None
            if refresh
            else self.cache.get(cache_key, ttl_seconds=self.cfg.cve_cache_ttl_seconds)
        )

        if payload is not None:
            cached = True
        else:
            if offline:
                raise NetworkError("Cache miss in --offline mode for CVE search.")
            started = time.monotonic()
            try:
                payload = self.nvd_client.fetch(params)
                self.cache.set(cache_key, payload)
                self._log_intel(
                    "cve search",
                    filters.keyword or filters.cpe or "",
                    "success",
                    0,
                    started,
                )
            except Exception as exc:
                self._log_intel(
                    "cve search",
                    filters.keyword or filters.cpe or "",
                    "error",
                    int(ExitCode.ERROR),
                    started,
                    error=str(exc),
                )
                raise

        parsed = parse_nvd_payload(payload)
        if enrich or filters.kev_only:
            parsed = enrich_records(
                parsed,
                cache=self.cache,
                ttl_seconds=self.cfg.cve_cache_ttl_seconds,
                kev_client=self.kev_client,
                epss_client=self.epss_client,
                offline=offline,
                refresh=refresh,
            )

        records = _filter_and_sort(parsed, filters)
        query_meta: dict[str, object] = {
            "keyword": filters.keyword,
            "cpe": filters.cpe,
            "min_cvss": filters.min_cvss,
            "severity": filters.severity,
            "published_after": filters.published_after,
            "published_before": filters.published_before,
            "kev_only": filters.kev_only,
            "enriched": enrich or filters.kev_only,
        }
        return CVESearchResult(query=query_meta, cached=cached, records=records)

    def search_from_fingerprint(
        self,
        fingerprint_path: Path,
        *,
        filters: CVESearchFilter,
        refresh: bool = False,
        offline: bool = False,
        enrich: bool = False,
    ) -> CVESearchResult:
        """Correlate passively identified technologies from a fingerprint JSON with NVD."""
        if filters.limit <= 0:
            raise ValidationError("--limit must be a positive integer.")
        _validate_date_arg(filters.published_after, "published-after")
        _validate_date_arg(filters.published_before, "published-before")

        try:
            data = json.loads(fingerprint_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ValidationError(
                f"Failed to read fingerprint artifact '{fingerprint_path}': {exc}"
            ) from exc

        if not isinstance(data, dict) or data.get("artifact_type") != "fingerprint_report":
            raise ValidationError(
                f"File '{fingerprint_path}' is not a valid s1shell fingerprint_report artifact."
            )

        queries: list[tuple[str | None, str | None, str | None]] = []
        seen_keys: set[str] = set()
        keywords: list[str] = []
        cpes: list[str] = []

        for match in data.get("matches", []):
            if not isinstance(match, dict):
                continue
            product = str(match.get("product", "")).strip()
            version = str(match.get("version") or "").strip() or None
            cpe_str = str(match.get("cpe") or "").strip() or None
            if not product and not cpe_str:
                continue
            if cpe_str:
                dedup_key = f"cpe:{cpe_str.lower()}"
                if dedup_key not in seen_keys:
                    seen_keys.add(dedup_key)
                    cpes.append(cpe_str)
                    queries.append((None, cpe_str, version))
            else:
                kw = f"{product} {version or ''}".strip()
                dedup_key = f"kw:{kw.lower()}"
                if dedup_key not in seen_keys:
                    seen_keys.add(dedup_key)
                    keywords.append(kw)
                    queries.append((kw, None, version))

        if not queries:
            return CVESearchResult(
                query={"from_fingerprint": str(fingerprint_path), "keywords": [], "cpes": []},
                cached=True,
                records=[],
            )

        combined_by_id: dict[str, CVERecord] = {}
        all_cached = True
        for kw_q, cpe_str, version in queries:
            sub_res = self.search(
                CVESearchFilter(
                    keyword=kw_q,
                    cpe=cpe_str,
                    min_cvss=filters.min_cvss,
                    severity=filters.severity,
                    published_after=filters.published_after,
                    published_before=filters.published_before,
                    limit=max(filters.limit, 25),
                    kev_only=filters.kev_only,
                ),
                refresh=refresh,
                offline=offline,
                enrich=enrich,
            )
            all_cached = all_cached and sub_res.cached
            cpe_vendor: str | None = None
            cpe_product: str | None = None
            if cpe_str:
                parts = cpe_str.split(":")
                if len(parts) >= 5:
                    cpe_vendor = parts[3]
                    cpe_product = parts[4]
            for rec in sub_res.records:
                if version and rec.cpe_ranges:
                    affected = is_version_affected(
                        version,
                        rec.cpe_ranges,
                        cpe_vendor=cpe_vendor,
                        cpe_product=cpe_product,
                    )
                    if affected is False:
                        continue
                    rec = replace(rec, version_verified=affected)
                combined_by_id.setdefault(rec.cve_id, rec)

        merged = _filter_and_sort(list(combined_by_id.values()), filters)
        return CVESearchResult(
            query={
                "from_fingerprint": str(fingerprint_path),
                "keywords": keywords,
                "cpes": cpes,
                "min_cvss": filters.min_cvss,
                "severity": filters.severity,
                "kev_only": filters.kev_only,
                "enriched": enrich or filters.kev_only,
            },
            cached=all_cached,
            records=merged,
        )

    def get(
        self,
        cve_id: str,
        *,
        refresh: bool = False,
        offline: bool = False,
        enrich: bool = False,
    ) -> CVESearchResult:
        """Fetch a specific CVE by ID from NVD and enrich with CVE.org (+ optional KEV/EPSS)."""
        norm_id = validate_cve_id(cve_id)
        params = {"cveId": norm_id}
        cache_key = _build_cache_key("cve_get", params)

        cached = False
        cached_bundle = (
            None
            if refresh
            else self.cache.get(cache_key, ttl_seconds=self.cfg.cve_cache_ttl_seconds)
        )

        if cached_bundle is not None:
            cached = True
            nvd_payload = cached_bundle["nvd"]
            cveorg_data = cached_bundle.get("cveorg")
        else:
            if offline:
                raise NetworkError(f"Cache miss in --offline mode for {norm_id}.")
            started = time.monotonic()
            try:
                nvd_payload = self.nvd_client.fetch(params)
                cveorg_rec = None
                try:
                    cveorg_rec = self.cveorg_client.fetch_cve(norm_id)
                except NetworkError:
                    cveorg_rec = None
                cveorg_data = (
                    {
                        "description": cveorg_rec.description,
                        "references": cveorg_rec.references,
                    }
                    if cveorg_rec is not None
                    else None
                )
                self.cache.set(cache_key, {"nvd": nvd_payload, "cveorg": cveorg_data})
                self._log_intel("cve get", norm_id, "success", 0, started)
            except Exception as exc:
                self._log_intel(
                    "cve get",
                    norm_id,
                    "error",
                    int(ExitCode.ERROR),
                    started,
                    error=str(exc),
                )
                raise

        records = [r for r in parse_nvd_payload(nvd_payload) if r.cve_id == norm_id]
        if records and cveorg_data:
            rec = records[0]
            merged_refs = list(dict.fromkeys([*rec.references, *cveorg_data.get("references", [])]))
            desc = cveorg_data.get("description") or rec.description
            records = [
                replace(
                    rec,
                    description=desc,
                    references=merged_refs,
                    source="nvd+cve.org",
                )
            ]
        if records and enrich:
            records = enrich_records(
                records,
                cache=self.cache,
                ttl_seconds=self.cfg.cve_cache_ttl_seconds,
                kev_client=self.kev_client,
                epss_client=self.epss_client,
                offline=offline,
                refresh=refresh,
            )
        return CVESearchResult(query={"cve_id": norm_id}, cached=cached, records=records)

    def get_many(
        self,
        cve_ids: list[str],
        *,
        refresh: bool = False,
        offline: bool = False,
        enrich: bool = False,
    ) -> CVESearchResult:
        """Fetch and prioritize one or more specific CVE IDs in a single consolidated result."""
        norm_ids = list(dict.fromkeys(validate_cve_id(cid) for cid in cve_ids))
        if not norm_ids:
            raise ValidationError("Provide at least one CVE ID.")
        if len(norm_ids) == 1:
            return self.get(norm_ids[0], refresh=refresh, offline=offline, enrich=enrich)

        combined: dict[str, CVERecord] = {}
        all_cached = True
        for cid in norm_ids:
            sub = self.get(cid, refresh=refresh, offline=offline, enrich=enrich)
            all_cached = all_cached and sub.cached
            for rec in sub.records:
                combined[rec.cve_id] = rec
        ordered = sorted(combined.values(), key=_sort_key, reverse=True)
        return CVESearchResult(
            query={"cve_ids": norm_ids, "enriched": enrich},
            cached=all_cached,
            records=ordered,
        )

    def clear_cache(self) -> int:
        """Remove all cached CVE entries."""
        return self.cache.clear()

    def _log_intel(
        self,
        command: str,
        target: str,
        outcome: str,
        exit_code: int,
        started: float,
        *,
        error: str | None = None,
    ) -> None:
        self.audit_logger.log(
            AuditEvent.create(
                category="intel",
                command=command,
                target=target,
                authorized_via="n/a",
                outcome=outcome,
                exit_code=exit_code,
                duration_ms=int((time.monotonic() - started) * 1000),
                error=error,
            )
        )
