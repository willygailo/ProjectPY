"""CVE.org CVE Services JSON API client for authoritative CNA record details."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from s1shell.config import RuntimeConfig
from s1shell.errors import NetworkError
from s1shell.http import build_intel_client

CVE_ORG_API_BASE = "https://cveawg.mitre.org/api/cve"


@dataclass(frozen=True)
class CVEOrgRecord:
    """Authoritative CNA description and reference URLs from CVE.org."""

    cve_id: str
    description: str
    references: list[str]
    state: str


def parse_cveorg_payload(payload: dict[str, Any]) -> CVEOrgRecord | None:
    """Parse CVE JSON 5.x record returned by CVE Services API."""
    meta = payload.get("cveMetadata", {})
    cve_id = str(meta.get("cveId", "")).strip()
    if not cve_id:
        return None
    state = str(meta.get("state", "PUBLISHED"))
    cna = payload.get("containers", {}).get("cna", {})
    descs = cna.get("descriptions", [])
    en_desc = next(
        (d.get("value", "") for d in descs if str(d.get("lang", "")).startswith("en")),
        descs[0].get("value", "") if descs else "",
    )
    refs = [
        str(r.get("url")) for r in cna.get("references", []) if isinstance(r, dict) and r.get("url")
    ]
    return CVEOrgRecord(
        cve_id=cve_id,
        description=str(en_desc).strip(),
        references=refs,
        state=state,
    )


class CVEOrgClient:
    """Client for fetching individual CVE JSON records from CVE.org."""

    def __init__(
        self,
        cfg: RuntimeConfig,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.cfg = cfg
        self.transport = transport

    def fetch_cve(self, cve_id: str) -> CVEOrgRecord | None:
        """Fetch and parse a single CVE record; returns None on 404."""
        url = f"{CVE_ORG_API_BASE}/{cve_id.upper()}"
        with build_intel_client(self.cfg, transport=self.transport) as client:
            try:
                resp = client.get(url)
            except httpx.HTTPError as exc:
                raise NetworkError(f"CVE.org request failed: {exc}") from exc

        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            raise NetworkError(f"CVE.org API returned HTTP {resp.status_code}")
        try:
            data = resp.json()
        except ValueError as exc:
            raise NetworkError(f"Invalid JSON from CVE.org API: {exc}") from exc
        return parse_cveorg_payload(data)
