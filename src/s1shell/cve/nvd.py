"""NVD REST API 2.0 client and CPE version-range matcher."""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from typing import Any

import httpx

from s1shell.config import RuntimeConfig
from s1shell.cve.models import CPEAffectedRange, CVERecord, CVSSMetric
from s1shell.cve.rate_limit import RateLimiter
from s1shell.errors import NetworkError
from s1shell.http import build_intel_client

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_VER_TOKEN_RE = re.compile(r"\d+|[a-zA-Z]+")


def _version_key(version: str) -> tuple[tuple[int, int | str], ...]:
    """Convert dotted version strings (e.g. '1.18.0', '2.4.49p1') into comparable tuples."""
    tokens: list[tuple[int, int | str]] = []
    for tok in _VER_TOKEN_RE.findall(version.strip()):
        if tok.isdigit():
            tokens.append((0, int(tok)))
        else:
            tokens.append((1, tok.lower()))
    return tuple(tokens)


def compare_versions(left: str, right: str) -> int:
    """Compare two version strings; returns -1, 0, or 1."""
    lk = list(_version_key(left))
    rk = list(_version_key(right))
    max_len = max(len(lk), len(rk))
    while len(lk) < max_len:
        lk.append((0, 0))
    while len(rk) < max_len:
        rk.append((0, 0))
    for a, b in zip(lk, rk, strict=True):
        if a == b:
            continue
        if a[0] != b[0]:
            return -1 if a[0] < b[0] else 1
        if a[0] == 1:
            return -1 if str(a[1]) < str(b[1]) else 1
        return -1 if int(a[1]) < int(b[1]) else 1
    return 0


def _parse_cpe_parts(criteria: str) -> tuple[str, str, str]:
    """Extract `(vendor, product, version)` from a CPE 2.3 string."""
    parts = criteria.split(":")
    if len(parts) < 6 or parts[0] != "cpe":
        return "", "", ""
    return parts[3].lower(), parts[4].lower(), parts[5].lower()


def is_version_affected(
    version: str,
    cpe_ranges: list[CPEAffectedRange],
    *,
    cpe_vendor: str | None = None,
    cpe_product: str | None = None,
) -> bool | None:
    """Verify whether `version` falls within any vulnerable NVD CPE range.

    Returns `True` if explicitly matched, `False` if matching product ranges exist and none
    cover `version`, or `None` if no comparable CPE ranges were present.
    """
    if not version or not cpe_ranges:
        return None

    target_vendor = cpe_vendor.lower() if cpe_vendor else None
    target_product = cpe_product.lower() if cpe_product else None
    saw_relevant = False

    for rng in cpe_ranges:
        if not rng.vulnerable:
            continue
        v, p, ver_field = _parse_cpe_parts(rng.criteria)
        if target_vendor and v and v != target_vendor:
            continue
        if target_product and p and p != target_product:
            continue
        saw_relevant = True

        # Exact version in CPE field (when no range bounds override)
        has_bounds = any(
            (
                rng.version_start_including,
                rng.version_start_excluding,
                rng.version_end_including,
                rng.version_end_excluding,
            )
        )
        if not has_bounds:
            if ver_field in {"*", "-", ""}:
                return True
            if compare_versions(version, ver_field) == 0:
                return True
            continue

        in_range = True
        if rng.version_start_including and compare_versions(version, rng.version_start_including) < 0:
            in_range = False
        if rng.version_start_excluding and compare_versions(version, rng.version_start_excluding) <= 0:
            in_range = False
        if rng.version_end_including and compare_versions(version, rng.version_end_including) > 0:
            in_range = False
        if rng.version_end_excluding and compare_versions(version, rng.version_end_excluding) >= 0:
            in_range = False
        if in_range:
            return True

    return False if saw_relevant else None


def _extract_cvss(metrics: dict[str, Any]) -> CVSSMetric | None:
    """Pick the highest-priority CVSS metric from NVD metrics block."""
    order = [
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ]
    for key, default_ver in order:
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries:
            continue
        primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        cvss_data = primary.get("cvssData", {})
        if "baseScore" not in cvss_data:
            continue
        score = float(cvss_data["baseScore"])
        severity = str(
            cvss_data.get("baseSeverity")
            or primary.get("baseSeverity")
            or _score_to_severity(score)
        ).upper()
        return CVSSMetric(
            version=str(cvss_data.get("version") or default_ver),
            base_score=score,
            severity=severity,
            vector=cvss_data.get("vectorString"),
        )
    return None


def _score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def _extract_cpes_and_ranges(
    configurations: list[dict[str, Any]],
) -> tuple[list[str], list[CPEAffectedRange]]:
    cpes: list[str] = []
    seen: set[str] = set()
    ranges: list[CPEAffectedRange] = []
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                crit = str(match.get("criteria", "")).strip()
                if not crit:
                    continue
                if crit not in seen:
                    seen.add(crit)
                    cpes.append(crit)
                ranges.append(
                    CPEAffectedRange(
                        criteria=crit,
                        vulnerable=bool(match.get("vulnerable", True)),
                        version_start_including=(
                            str(match["versionStartIncluding"]).strip()
                            if match.get("versionStartIncluding")
                            else None
                        ),
                        version_start_excluding=(
                            str(match["versionStartExcluding"]).strip()
                            if match.get("versionStartExcluding")
                            else None
                        ),
                        version_end_including=(
                            str(match["versionEndIncluding"]).strip()
                            if match.get("versionEndIncluding")
                            else None
                        ),
                        version_end_excluding=(
                            str(match["versionEndExcluding"]).strip()
                            if match.get("versionEndExcluding")
                            else None
                        ),
                    )
                )
    return cpes, ranges


def parse_nvd_payload(payload: dict[str, Any]) -> list[CVERecord]:
    """Convert raw NVD 2.0 JSON response into normalized CVERecord objects."""
    records: list[CVERecord] = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = str(cve.get("id", "")).strip()
        if not cve_id:
            continue

        descriptions = cve.get("descriptions", [])
        en_desc = next(
            (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
            descriptions[0].get("value", "") if descriptions else "",
        )
        refs = [
            str(r.get("url"))
            for r in cve.get("references", [])
            if isinstance(r, dict) and r.get("url")
        ]
        cpes, cpe_ranges = _extract_cpes_and_ranges(cve.get("configurations", []))
        records.append(
            CVERecord(
                cve_id=cve_id,
                description=str(en_desc).strip(),
                published=str(cve.get("published", "")),
                last_modified=str(cve.get("lastModified", "")),
                cvss=_extract_cvss(cve.get("metrics", {})),
                cpes=cpes,
                references=refs,
                source="nvd",
                cpe_ranges=cpe_ranges,
            )
        )
    return records


class NVDClient:
    """Thin resilient client for the NVD REST API 2.0."""

    def __init__(
        self,
        cfg: RuntimeConfig,
        *,
        api_key: str | None = None,
        rate_limiter: RateLimiter | None = None,
        transport: httpx.BaseTransport | None = None,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        self.cfg = cfg
        if api_key is not None:
            resolved_key: str | None = api_key
        else:
            resolved_key, _ = cfg.get_nvd_api_key()
        self.api_key = resolved_key.strip() if resolved_key and resolved_key.strip() else None
        self.rate_limiter = (
            rate_limiter
            if rate_limiter is not None
            else RateLimiter.for_nvd(has_api_key=self.api_key is not None)
        )
        self.transport = transport
        self._sleeper = sleeper if sleeper is not None else time.sleep

    def fetch(self, params: dict[str, str]) -> dict[str, Any]:
        """Execute a rate-limited NVD 2.0 GET request with bounded backoff on 429/503."""
        headers: dict[str, str] = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        max_attempts = 3
        with build_intel_client(self.cfg, transport=self.transport) as client:
            for attempt in range(max_attempts):
                self.rate_limiter.acquire()
                try:
                    resp = client.get(NVD_API_URL, params=params, headers=headers)
                except httpx.HTTPError as exc:
                    raise NetworkError(f"NVD API request failed: {exc}") from exc

                if resp.status_code in {429, 503} and attempt < max_attempts - 1:
                    retry_after = resp.headers.get("Retry-After")
                    delay = (
                        min(float(retry_after), 30.0)
                        if retry_after and retry_after.isdigit()
                        else float(2**attempt)
                    )
                    self._sleeper(delay)
                    continue

                if resp.status_code != 200:
                    raise NetworkError(
                        f"NVD API returned HTTP {resp.status_code}: {resp.text[:200]}"
                    )
                try:
                    data: dict[str, Any] = resp.json()
                except ValueError as exc:
                    raise NetworkError(f"Invalid JSON received from NVD API: {exc}") from exc
                return data

        raise NetworkError("NVD API retries exhausted.")
