"""HTTP clients for VirusTotal v3, GreyNoise Community, urlscan.io Search, and GitHub GHSA."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

from s1shell.config import RuntimeConfig
from s1shell.errors import NetworkError
from s1shell.http import build_intel_client
from s1shell.intel.models import (
    GitHubAdvisory,
    GreyNoiseIntel,
    URLScanEntry,
    URLScanSummary,
    VirusTotalIntel,
)


def _epoch_to_iso(ts: object) -> str | None:
    if isinstance(ts, (int, float)) and ts > 0:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat().replace("+00:00", "Z")
    return None


def parse_virustotal_payload(
    payload: dict[str, Any],
    *,
    indicator: str,
    indicator_type: str,
) -> VirusTotalIntel:
    """Parse VirusTotal v3 `/domains/{d}` or `/ip_addresses/{ip}` response JSON."""
    data = payload.get("data", {}) if isinstance(payload, dict) else {}
    attrs = data.get("attributes", {}) if isinstance(data, dict) else {}
    stats = attrs.get("last_analysis_stats", {}) if isinstance(attrs, dict) else {}
    raw_cats = attrs.get("categories", {}) if isinstance(attrs, dict) else {}
    cats: list[str] = []
    if isinstance(raw_cats, dict):
        for val in raw_cats.values():
            cleaned = str(val).strip()
            if cleaned and cleaned not in cats and len(cats) < 8:
                cats.append(cleaned)
    gui_section = "ip-address" if indicator_type == "ip" else "domain"
    return VirusTotalIntel(
        indicator=indicator,
        indicator_type=indicator_type,
        malicious=int(stats.get("malicious", 0) or 0),
        suspicious=int(stats.get("suspicious", 0) or 0),
        harmless=int(stats.get("harmless", 0) or 0),
        undetected=int(stats.get("undetected", 0) or 0),
        reputation=int(attrs.get("reputation", 0) or 0),
        as_owner=str(attrs["as_owner"]).strip() if attrs.get("as_owner") else None,
        country=str(attrs["country"]).strip() if attrs.get("country") else None,
        categories=cats,
        last_analysis_utc=_epoch_to_iso(attrs.get("last_analysis_date")),
        gui_url=f"https://www.virustotal.com/gui/{gui_section}/{indicator}",
    )


def parse_greynoise_payload(payload: dict[str, Any], *, ip: str) -> GreyNoiseIntel:
    """Parse GreyNoise v3 Community JSON response."""
    return GreyNoiseIntel(
        ip=str(payload.get("ip") or ip),
        noise=bool(payload.get("noise", False)),
        riot=bool(payload.get("riot", False)),
        classification=str(payload.get("classification") or "unknown").strip().lower(),
        name=str(payload["name"]).strip() if payload.get("name") else None,
        last_seen=str(payload["last_seen"]).strip() if payload.get("last_seen") else None,
        message=str(payload["message"]).strip() if payload.get("message") else None,
        link=str(payload["link"]).strip() if payload.get("link") else None,
    )


def parse_urlscan_payload(payload: dict[str, Any], *, query: str) -> URLScanSummary:
    """Parse urlscan.io passive `/api/v1/search/` JSON response."""
    total = int(payload.get("total", 0) or 0)
    results = payload.get("results", []) if isinstance(payload, dict) else []
    entries: list[URLScanEntry] = []
    ips: list[str] = []
    servers: list[str] = []
    asns: list[str] = []

    for item in results[:10]:
        if not isinstance(item, dict):
            continue
        task = item.get("task", {}) if isinstance(item.get("task"), dict) else {}
        page = item.get("page", {}) if isinstance(item.get("page"), dict) else {}
        ip_val = str(page.get("ip") or "").strip() or None
        srv_val = str(page.get("server") or "").strip() or None
        asn_val = str(page.get("asnname") or page.get("asn") or "").strip() or None
        status_raw = page.get("status")
        status_int = int(status_raw) if isinstance(status_raw, int) else None
        if ip_val and ip_val not in ips:
            ips.append(ip_val)
        if srv_val and srv_val not in servers:
            servers.append(srv_val)
        if asn_val and asn_val not in asns:
            asns.append(asn_val)
        entries.append(
            URLScanEntry(
                indexed_at=str(task.get("time") or item.get("indexedAt") or ""),
                page_url=str(page.get("url") or task.get("url") or ""),
                status=status_int,
                server=srv_val,
                ip=ip_val,
                asn=asn_val,
                title=str(page.get("title") or "").strip()[:120] or None,
                result_url=str(item.get("result") or "").strip() or None,
            )
        )

    return URLScanSummary(
        query=query,
        total_results=total,
        recent_scans=entries,
        observed_ips=ips,
        observed_servers=servers,
        observed_asns=asns,
    )


def parse_github_advisories_payload(payload: Any) -> list[GitHubAdvisory]:
    """Parse GitHub REST `/advisories` JSON list into normalized GitHubAdvisory objects."""
    if not isinstance(payload, list):
        return []
    out: list[GitHubAdvisory] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        ghsa_id = str(item.get("ghsa_id") or "").strip()
        if not ghsa_id:
            continue
        cve_id = str(item.get("cve_id") or "").strip().upper() or None
        cvss_blk = item.get("cvss")
        cvss_score: float | None = None
        if isinstance(cvss_blk, dict) and cvss_blk.get("score") is not None:
            try:
                cvss_score = float(cvss_blk["score"])
            except (TypeError, ValueError):
                cvss_score = None
        sev = str(item.get("severity") or "medium").strip().upper()
        if sev == "MODERATE":
            sev = "MEDIUM"
        cwes: list[str] = []
        for cwe_obj in item.get("cwes", []) or []:
            if isinstance(cwe_obj, dict) and cwe_obj.get("cwe_id"):
                cid = str(cwe_obj["cwe_id"]).strip()
                if cid and cid not in cwes:
                    cwes.append(cid)
        patched: list[str] = []
        for vuln in item.get("vulnerabilities", []) or []:
            if not isinstance(vuln, dict):
                continue
            pv = str(vuln.get("first_patched_version") or "").strip()
            if pv and pv not in patched:
                patched.append(pv)
        out.append(
            GitHubAdvisory(
                ghsa_id=ghsa_id,
                cve_id=cve_id,
                summary=str(item.get("summary") or "").strip()[:240],
                severity=sev,
                cvss_score=cvss_score,
                cwes=cwes,
                published_at=str(item.get("published_at") or ""),
                html_url=str(item.get("html_url") or f"https://github.com/advisories/{ghsa_id}"),
                patched_versions=patched,
            )
        )
    return out


class VirusTotalClient:
    """Read-only VirusTotal v3 passive domain/IP lookup client."""

    def __init__(
        self,
        cfg: RuntimeConfig,
        *,
        api_key: str | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._cfg = cfg
        resolved = api_key if api_key is not None else cfg.get_virustotal_api_key()[0]
        self._api_key = resolved.strip() if resolved and resolved.strip() else None
        self._transport = transport

    @property
    def configured(self) -> bool:
        return self._api_key is not None

    def fetch(self, indicator: str, *, indicator_type: str) -> dict[str, Any]:
        """Fetch raw VirusTotal v3 JSON for a domain or IP address."""
        if not self._api_key:
            raise NetworkError("VIRUSTOTAL_API_KEY is not configured.")
        endpoint = "ip_addresses" if indicator_type == "ip" else "domains"
        url = f"{self._cfg.virustotal_api_url.rstrip('/')}/{endpoint}/{indicator}"
        headers = {"x-apikey": self._api_key}
        try:
            with build_intel_client(self._cfg, transport=self._transport) as client:
                resp = client.get(url, headers=headers)
        except httpx.HTTPError as exc:
            raise NetworkError(f"VirusTotal API request failed: {exc}") from exc
        if resp.status_code != 200:
            raise NetworkError(f"VirusTotal API returned HTTP {resp.status_code}")
        try:
            data: dict[str, Any] = resp.json()
        except ValueError as exc:
            raise NetworkError(f"VirusTotal API returned invalid JSON: {exc}") from exc
        return data


class GreyNoiseClient:
    """Read-only GreyNoise Community API client for passive IP noise/RIOT classification."""

    def __init__(
        self,
        cfg: RuntimeConfig,
        *,
        api_key: str | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._cfg = cfg
        resolved = api_key if api_key is not None else cfg.get_greynoise_api_key()[0]
        self._api_key = resolved.strip() if resolved and resolved.strip() else None
        self._transport = transport

    @property
    def configured(self) -> bool:
        return self._api_key is not None

    def fetch_ip(self, ip: str) -> dict[str, Any]:
        """Fetch GreyNoise Community JSON for an IPv4 address (404 returns unobserved stub)."""
        if not self._api_key:
            raise NetworkError("GREYNOISE_API_KEY is not configured.")
        url = f"{self._cfg.greynoise_api_url.rstrip('/')}/{ip}"
        headers = {"key": self._api_key}
        try:
            with build_intel_client(self._cfg, transport=self._transport) as client:
                resp = client.get(url, headers=headers)
        except httpx.HTTPError as exc:
            raise NetworkError(f"GreyNoise API request failed: {exc}") from exc
        if resp.status_code == 404:
            return {
                "ip": ip,
                "noise": False,
                "riot": False,
                "classification": "unknown",
                "message": "IP not observed scanning the internet or in RIOT.",
            }
        if resp.status_code != 200:
            raise NetworkError(f"GreyNoise API returned HTTP {resp.status_code}")
        try:
            data: dict[str, Any] = resp.json()
        except ValueError as exc:
            raise NetworkError(f"GreyNoise API returned invalid JSON: {exc}") from exc
        return data


class URLScanClient:
    """Strictly passive urlscan.io historical Search API client (never submits active scans)."""

    def __init__(
        self,
        cfg: RuntimeConfig,
        *,
        api_key: str | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._cfg = cfg
        resolved = api_key if api_key is not None else cfg.get_urlscan_api_key()[0]
        self._api_key = resolved.strip() if resolved and resolved.strip() else None
        self._transport = transport

    @property
    def configured(self) -> bool:
        return self._api_key is not None

    def search(self, query: str, *, size: int = 10) -> dict[str, Any]:
        """Query urlscan.io's existing public search index passively (`GET /api/v1/search/`)."""
        headers: dict[str, str] = {}
        if self._api_key:
            headers["API-Key"] = self._api_key
        params = {"q": query, "size": str(min(max(size, 1), 25))}
        try:
            with build_intel_client(self._cfg, transport=self._transport) as client:
                resp = client.get(self._cfg.urlscan_api_url, params=params, headers=headers)
        except httpx.HTTPError as exc:
            raise NetworkError(f"urlscan.io Search API request failed: {exc}") from exc
        if resp.status_code != 200:
            raise NetworkError(f"urlscan.io Search API returned HTTP {resp.status_code}")
        try:
            data: dict[str, Any] = resp.json()
        except ValueError as exc:
            raise NetworkError(f"urlscan.io Search API returned invalid JSON: {exc}") from exc
        return data


class GitHubAdvisoryClient:
    """Read-only client for the public GitHub Security Advisories REST API."""

    def __init__(
        self,
        cfg: RuntimeConfig,
        *,
        token: str | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._cfg = cfg
        resolved = token if token is not None else cfg.get_github_token()[0]
        self._token = resolved.strip() if resolved and resolved.strip() else None
        self._transport = transport

    @property
    def configured(self) -> bool:
        return self._token is not None

    def fetch_advisories(
        self,
        *,
        cve_id: str | None = None,
        ecosystem: str | None = None,
        package: str | None = None,
        per_page: int = 15,
    ) -> list[dict[str, Any]]:
        """Query `GET /advisories` by CVE ID or ecosystem+package."""
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        params: dict[str, str] = {"per_page": str(min(max(per_page, 1), 50))}
        if cve_id:
            params["cve_id"] = cve_id.strip().upper()
        if ecosystem:
            params["ecosystem"] = ecosystem.strip().lower()
        if package:
            params["affects"] = package.strip()
        try:
            with build_intel_client(self._cfg, transport=self._transport) as client:
                resp = client.get(self._cfg.github_advisories_url, params=params, headers=headers)
        except httpx.HTTPError as exc:
            raise NetworkError(f"GitHub Advisories API request failed: {exc}") from exc
        if resp.status_code != 200:
            raise NetworkError(f"GitHub Advisories API returned HTTP {resp.status_code}")
        try:
            data = resp.json()
        except ValueError as exc:
            raise NetworkError(f"GitHub Advisories API returned invalid JSON: {exc}") from exc
        if not isinstance(data, list):
            raise NetworkError("GitHub Advisories API returned unexpected payload.")
        return [item for item in data if isinstance(item, dict)]
