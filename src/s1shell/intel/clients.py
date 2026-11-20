"""HTTP clients for VirusTotal v3, GreyNoise Community, urlscan.io Search, and GitHub GHSA."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

import httpx

from s1shell.config import RuntimeConfig
from s1shell.errors import NetworkError
from s1shell.http import build_intel_client
from s1shell.intel.models import (
    CTCertEntry,
    CTLookupResult,
    GitHubAdvisory,
    GreyNoiseIntel,
    RDAPLookupResult,
    URLScanEntry,
    URLScanSummary,
    VirusTotalIntel,
)

_RETRYABLE_STATUS_CODES = {429, 502, 503, 504}


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    cleaned = value.strip()
    try:
        delay = float(cleaned)
    except ValueError:
        return None
    return min(max(delay, 0.0), 30.0)


def _get_with_retry(
    cfg: RuntimeConfig,
    url: str,
    *,
    service_name: str,
    params: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    transport: httpx.BaseTransport | None = None,
    follow_redirects: bool = False,
    sleeper: Callable[[float], None] | None = None,
    max_attempts: int = 3,
) -> httpx.Response:
    """Execute a read-only intel GET with bounded backoff on HTTP 429/502/503/504."""
    sleep_fn = sleeper if sleeper is not None else time.sleep
    with build_intel_client(
        cfg,
        transport=transport,
        follow_redirects=follow_redirects,
    ) as client:
        for attempt in range(max_attempts):
            try:
                resp = client.get(url, params=params, headers=headers)
            except httpx.HTTPError as exc:
                raise NetworkError(f"{service_name} request failed: {exc}") from exc

            if resp.status_code in _RETRYABLE_STATUS_CODES and attempt < max_attempts - 1:
                retry_delay = _parse_retry_after(resp.headers.get("Retry-After"))
                delay = retry_delay if retry_delay is not None else float(2**attempt)
                sleep_fn(delay)
                continue
            return resp
    raise NetworkError(f"{service_name} retries exhausted.")


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
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        self._cfg = cfg
        resolved = api_key if api_key is not None else cfg.get_virustotal_api_key()[0]
        self._api_key = resolved.strip() if resolved and resolved.strip() else None
        self._transport = transport
        self._sleeper = sleeper

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
        resp = _get_with_retry(
            self._cfg,
            url,
            service_name="VirusTotal API",
            headers=headers,
            transport=self._transport,
            sleeper=self._sleeper,
        )
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
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        self._cfg = cfg
        resolved = api_key if api_key is not None else cfg.get_greynoise_api_key()[0]
        self._api_key = resolved.strip() if resolved and resolved.strip() else None
        self._transport = transport
        self._sleeper = sleeper

    @property
    def configured(self) -> bool:
        return self._api_key is not None

    def fetch_ip(self, ip: str) -> dict[str, Any]:
        """Fetch GreyNoise Community JSON for an IPv4 address (404 returns unobserved stub)."""
        if not self._api_key:
            raise NetworkError("GREYNOISE_API_KEY is not configured.")
        url = f"{self._cfg.greynoise_api_url.rstrip('/')}/{ip}"
        headers = {"key": self._api_key}
        resp = _get_with_retry(
            self._cfg,
            url,
            service_name="GreyNoise API",
            headers=headers,
            transport=self._transport,
            sleeper=self._sleeper,
        )
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
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        self._cfg = cfg
        resolved = api_key if api_key is not None else cfg.get_urlscan_api_key()[0]
        self._api_key = resolved.strip() if resolved and resolved.strip() else None
        self._transport = transport
        self._sleeper = sleeper

    @property
    def configured(self) -> bool:
        return self._api_key is not None

    def search(self, query: str, *, size: int = 10) -> dict[str, Any]:
        """Query urlscan.io's existing public search index passively (`GET /api/v1/search/`)."""
        headers: dict[str, str] = {}
        if self._api_key:
            headers["API-Key"] = self._api_key
        params = {"q": query, "size": str(min(max(size, 1), 25))}
        resp = _get_with_retry(
            self._cfg,
            self._cfg.urlscan_api_url,
            service_name="urlscan.io Search API",
            params=params,
            headers=headers,
            transport=self._transport,
            sleeper=self._sleeper,
        )
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
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        self._cfg = cfg
        resolved = token if token is not None else cfg.get_github_token()[0]
        self._token = resolved.strip() if resolved and resolved.strip() else None
        self._transport = transport
        self._sleeper = sleeper

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
        resp = _get_with_retry(
            self._cfg,
            self._cfg.github_advisories_url,
            service_name="GitHub Advisories API",
            params=params,
            headers=headers,
            transport=self._transport,
            sleeper=self._sleeper,
        )
        if resp.status_code != 200:
            raise NetworkError(f"GitHub Advisories API returned HTTP {resp.status_code}")
        try:
            data = resp.json()
        except ValueError as exc:
            raise NetworkError(f"GitHub Advisories API returned invalid JSON: {exc}") from exc
        if not isinstance(data, list):
            raise NetworkError("GitHub Advisories API returned unexpected payload.")
        return [item for item in data if isinstance(item, dict)]


def _parse_iso_dt(raw: str | None) -> datetime | None:
    if not raw or not raw.strip():
        return None
    cleaned = raw.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _extract_rdap_vcard_field(entity: dict[str, Any], field_name: str) -> str | None:
    vals = _extract_rdap_vcard_fields(entity, field_name)
    return vals[0] if vals else None


def _extract_rdap_vcard_fields(entity: dict[str, Any], field_name: str) -> list[str]:
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return []
    out: list[str] = []
    for row in vcard[1]:
        if isinstance(row, list) and len(row) >= 4 and str(row[0]).lower() == field_name:
            val = row[3]
            if isinstance(val, str) and val.strip():
                cleaned = val.strip()
                if cleaned.lower().startswith("tel:"):
                    cleaned = cleaned[4:].strip()
                elif cleaned.lower().startswith("mailto:"):
                    cleaned = cleaned[7:].strip()
                if cleaned and cleaned not in out:
                    out.append(cleaned)
    return out


def parse_crtsh_payload(
    payload: Any,
    *,
    domain: str,
    cached: bool = False,
    now: datetime | None = None,
) -> CTLookupResult:
    """Parse crt.sh JSON certificate list into deduplicated passive SAN & issuer intelligence."""
    ref_now = now if now is not None else datetime.now(timezone.utc)
    dom_low = domain.strip().lower().rstrip(".")
    if not isinstance(payload, list):
        return CTLookupResult(domain=dom_low, cached=cached)

    subdomains: set[str] = set()
    wildcards: set[str] = set()
    issuers: list[str] = []
    seen_issuers: set[str] = set()
    recent: list[CTCertEntry] = []
    seen_ids: set[int] = set()
    active_count = 0
    expired_count = 0

    for item in payload:
        if not isinstance(item, dict):
            continue
        raw_id = item.get("id")
        cert_id = int(raw_id) if isinstance(raw_id, int) else None
        if cert_id is not None and cert_id in seen_ids:
            continue
        if cert_id is not None:
            seen_ids.add(cert_id)

        cn = str(item.get("common_name") or "").strip().lower()
        name_val = str(item.get("name_value") or "")
        issuer_name = str(item.get("issuer_name") or "").strip()
        not_before = str(item.get("not_before") or "").strip() or None
        not_after = str(item.get("not_after") or "").strip() or None

        na_dt = _parse_iso_dt(not_after)
        is_expired = bool(na_dt is not None and na_dt < ref_now)
        if is_expired:
            expired_count += 1
        else:
            active_count += 1

        if issuer_name and issuer_name not in seen_issuers and len(issuers) < 20:
            seen_issuers.add(issuer_name)
            issuers.append(issuer_name[:160])

        raw_names = [line.strip().lower() for line in name_val.splitlines() if line.strip()]
        if cn and cn not in raw_names:
            raw_names.insert(0, cn)

        clean_sans: list[str] = []
        for candidate in raw_names:
            if not candidate or " " in candidate or "@" in candidate:
                continue
            cleaned = candidate.rstrip(".")
            if cleaned.startswith("*."):
                base = cleaned[2:]
                if base == dom_low or base.endswith("." + dom_low):
                    wildcards.add(cleaned)
                    clean_sans.append(cleaned)
            elif cleaned == dom_low or cleaned.endswith("." + dom_low):
                subdomains.add(cleaned)
                clean_sans.append(cleaned)

        if len(recent) < 25:
            recent.append(
                CTCertEntry(
                    cert_id=cert_id,
                    common_name=cn,
                    san_names=clean_sans[:15],
                    issuer_name=issuer_name[:160],
                    not_before=not_before,
                    not_after=not_after,
                    expired=is_expired,
                )
            )

    return CTLookupResult(
        domain=dom_low,
        cached=cached,
        total_certificates=len(seen_ids) if seen_ids else active_count + expired_count,
        unique_subdomains=sorted(subdomains)[:250],
        wildcard_sans=sorted(wildcards)[:50],
        issuers=issuers,
        active_certificates=active_count,
        expired_certificates=expired_count,
        recent_certificates=recent,
    )


def parse_rdap_payload(
    payload: dict[str, Any],
    *,
    indicator: str,
    indicator_type: str,
    source_url: str | None = None,
    cached: bool = False,
    now: datetime | None = None,
) -> RDAPLookupResult:
    """Parse RFC 7483 RDAP domain or IP network JSON payload."""
    ref_now = now if now is not None else datetime.now(timezone.utc)
    handle = str(payload.get("handle") or "").strip() or None
    name = str(payload.get("name") or payload.get("ldhName") or "").strip() or None
    country = str(payload.get("country") or "").strip().upper() or None
    statuses = [str(s).strip() for s in payload.get("status", []) if str(s).strip()]

    transfer_locked: bool | None = None
    if indicator_type == "domain" and statuses:
        low_statuses = {s.lower().replace(" ", "") for s in statuses}
        transfer_locked = any(
            s in low_statuses for s in {"clienttransferprohibited", "servertransferprohibited"}
        )

    dnssec_signed: bool | None = None
    sec_dns = payload.get("secureDNS")
    if isinstance(sec_dns, dict) and "delegationSigned" in sec_dns:
        dnssec_signed = bool(sec_dns.get("delegationSigned"))

    created_at: str | None = None
    updated_at: str | None = None
    expires_at: str | None = None
    for ev in payload.get("events", []) or []:
        if not isinstance(ev, dict):
            continue
        action = str(ev.get("eventAction") or "").strip().lower()
        date_val = str(ev.get("eventDate") or "").strip()
        if not date_val:
            continue
        if action == "registration" and created_at is None:
            created_at = date_val
        elif action in {"last changed", "last update of rdap database"} and updated_at is None:
            updated_at = date_val
        elif action == "expiration" and expires_at is None:
            expires_at = date_val

    created_dt = _parse_iso_dt(created_at)
    expires_dt = _parse_iso_dt(expires_at)
    age_days = max(0, (ref_now - created_dt).days) if created_dt is not None else None
    days_until_expiry = (expires_dt - ref_now).days if expires_dt is not None else None

    nameservers: list[str] = []
    for ns in payload.get("nameservers", []) or []:
        if isinstance(ns, dict) and ns.get("ldhName"):
            ns_val = str(ns["ldhName"]).strip().lower().rstrip(".")
            if ns_val and ns_val not in nameservers:
                nameservers.append(ns_val)

    registrar: str | None = None
    organization: str | None = None
    abuse_contact: str | None = None
    emails: list[str] = []
    phone_numbers: list[str] = []
    entity_summaries: list[str] = []

    def _walk_entities(entities: Any) -> None:
        nonlocal registrar, organization, abuse_contact
        if not isinstance(entities, list):
            return
        for ent in entities:
            if not isinstance(ent, dict):
                continue
            roles = {str(r).strip().lower() for r in ent.get("roles", []) if str(r).strip()}
            ent_handle = str(ent.get("handle") or "").strip()
            fn = _extract_rdap_vcard_field(ent, "fn")
            ent_emails = _extract_rdap_vcard_fields(ent, "email")
            ent_tels = _extract_rdap_vcard_fields(ent, "tel")
            email = ent_emails[0] if ent_emails else None
            for em in ent_emails:
                if em not in emails:
                    emails.append(em)
            for tel in ent_tels:
                if tel not in phone_numbers:
                    phone_numbers.append(tel)
            label_name = fn or ent_handle
            if label_name:
                role_tag = "/".join(sorted(roles)) if roles else "entity"
                summary_item = (
                    f"{label_name} ({role_tag})"
                    if fn and not ent_handle
                    else (
                        f"{fn} [{ent_handle}] ({role_tag})"
                        if fn and ent_handle and fn != ent_handle
                        else f"{label_name} ({role_tag})"
                    )
                )
                if summary_item not in entity_summaries:
                    entity_summaries.append(summary_item)
            if "registrar" in roles and registrar is None and fn:
                registrar = fn
            if ("registrant" in roles or "administrative" in roles) and organization is None and fn:
                organization = fn
            if abuse_contact is None and email and ("abuse" in roles or "abuse" in email.lower()):
                abuse_contact = email
            _walk_entities(ent.get("entities"))

    _walk_entities(payload.get("entities"))
    if abuse_contact and abuse_contact not in emails:
        emails.insert(0, abuse_contact)

    cidr: str | None = None
    cidr_list = payload.get("cidr0_cidrs")
    if isinstance(cidr_list, list) and cidr_list:
        first = cidr_list[0]
        if isinstance(first, dict):
            prefix = first.get("v4prefix") or first.get("v6prefix")
            length = first.get("length")
            if prefix and length is not None:
                cidr = f"{prefix}/{length}"
    start_addr = str(payload.get("startAddress") or "").strip() or None
    end_addr = str(payload.get("endAddress") or "").strip() or None

    return RDAPLookupResult(
        indicator=indicator,
        indicator_type=indicator_type,
        cached=cached,
        handle=handle,
        name=name,
        registrar=registrar,
        organization=organization,
        country=country,
        statuses=statuses,
        transfer_locked=transfer_locked,
        dnssec_signed=dnssec_signed,
        created_at=created_at,
        updated_at=updated_at,
        expires_at=expires_at,
        domain_age_days=age_days,
        days_until_expiry=days_until_expiry,
        nameservers=nameservers,
        cidr=cidr,
        start_address=start_addr,
        end_address=end_addr,
        abuse_contact=abuse_contact,
        emails=emails[:20],
        phone_numbers=phone_numbers[:20],
        entities=entity_summaries[:20],
        source_url=source_url,
    )


class CrtShClient:
    """Strictly passive Certificate Transparency log client via crt.sh (zero target contact)."""

    def __init__(
        self,
        cfg: RuntimeConfig,
        *,
        transport: httpx.BaseTransport | None = None,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        self._cfg = cfg
        self._transport = transport
        self._sleeper = sleeper

    def fetch_domain(self, domain: str) -> list[dict[str, Any]]:
        """Query `https://crt.sh/?q=%.<domain>&output=json` passively."""
        cleaned = domain.strip().lower().rstrip(".")
        params = {"q": f"%.{cleaned}", "output": "json"}
        resp = _get_with_retry(
            self._cfg,
            self._cfg.crtsh_api_url,
            service_name="crt.sh CT log",
            params=params,
            transport=self._transport,
            sleeper=self._sleeper,
        )
        if resp.status_code == 404:
            return []
        if resp.status_code != 200:
            raise NetworkError(f"crt.sh CT log returned HTTP {resp.status_code}")
        text = resp.text.strip()
        if not text:
            return []
        try:
            data = resp.json()
        except ValueError as exc:
            raise NetworkError(f"crt.sh returned invalid JSON: {exc}") from exc
        if not isinstance(data, list):
            return []
        return [item for item in data if isinstance(item, dict)]


class RDAPClient:
    """Read-only RFC 7480–7484 RDAP registration lookup client (domain or IP, zero API key)."""

    def __init__(
        self,
        cfg: RuntimeConfig,
        *,
        transport: httpx.BaseTransport | None = None,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        self._cfg = cfg
        self._transport = transport
        self._sleeper = sleeper

    def fetch(self, indicator: str, *, indicator_type: str) -> tuple[dict[str, Any], str]:
        """Fetch RDAP JSON for a domain or IP via RFC 7484 bootstrap (`follow_redirects=True`)."""
        endpoint = "ip" if indicator_type == "ip" else "domain"
        url = f"{self._cfg.rdap_base_url.rstrip('/')}/{endpoint}/{indicator.strip()}"
        resp = _get_with_retry(
            self._cfg,
            url,
            service_name="RDAP",
            headers={"Accept": "application/rdap+json, application/json"},
            transport=self._transport,
            follow_redirects=True,
            sleeper=self._sleeper,
        )
        if resp.status_code != 200:
            raise NetworkError(f"RDAP server returned HTTP {resp.status_code}")
        try:
            data: dict[str, Any] = resp.json()
        except ValueError as exc:
            raise NetworkError(f"RDAP server returned invalid JSON: {exc}") from exc
        return data, str(resp.url)
