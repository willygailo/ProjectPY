"""Passive threat intelligence orchestrator, GHSA lookup, and `0600` `.env` manager."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import time
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

from s1shell.audit import AuditEvent, AuditLogger
from s1shell.config import (
    RuntimeConfig,
    chmod_private_file,
    ensure_private_dir,
    load_dotenv_file,
    mask_api_key,
)
from s1shell.cve.cache import CVECache
from s1shell.errors import ExitCode, NetworkError, ValidationError
from s1shell.intel.clients import (
    CrtShClient,
    GitHubAdvisoryClient,
    GreyNoiseClient,
    RDAPClient,
    URLScanClient,
    VirusTotalClient,
    parse_crtsh_payload,
    parse_github_advisories_payload,
    parse_greynoise_payload,
    parse_rdap_payload,
    parse_urlscan_payload,
    parse_virustotal_payload,
)
from s1shell.intel.models import (
    CTLookupResult,
    GitHubAdvisoryResult,
    GreyNoiseIntel,
    IntelEnvStatus,
    IntelFeedKeyStatus,
    IntelLookupResult,
    RDAPLookupResult,
    URLScanSummary,
    VirusTotalIntel,
)
from s1shell.scope import parse_target

DEFAULT_INTEL_LOOKUP_SOURCES = ("vt", "greynoise", "urlscan")
SUPPORTED_INTEL_SOURCES = ("vt", "greynoise", "urlscan", "rdap")


def _cache_key(prefix: str, payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return f"intel_{prefix}_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _format_dotenv(values: dict[str, str]) -> str:
    lines: list[str] = []
    for key, val in values.items():
        escaped = val.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'{key}="{escaped}"')
    return "\n".join(lines) + ("\n" if lines else "")


def _is_ipv4(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False


class IntelService:
    """Coordinates cached VirusTotal, GreyNoise, urlscan.io, and GitHub GHSA lookups."""

    def __init__(
        self,
        cfg: RuntimeConfig,
        *,
        cache: CVECache | None = None,
        vt_client: VirusTotalClient | None = None,
        greynoise_client: GreyNoiseClient | None = None,
        urlscan_client: URLScanClient | None = None,
        github_client: GitHubAdvisoryClient | None = None,
        crtsh_client: CrtShClient | None = None,
        rdap_client: RDAPClient | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self.cfg = cfg
        self._cache: CVECache | None = cache
        self.vt_client = vt_client if vt_client is not None else VirusTotalClient(cfg)
        self.greynoise_client = (
            greynoise_client if greynoise_client is not None else GreyNoiseClient(cfg)
        )
        self.urlscan_client = urlscan_client if urlscan_client is not None else URLScanClient(cfg)
        self.github_client = (
            github_client if github_client is not None else GitHubAdvisoryClient(cfg)
        )
        self.crtsh_client = crtsh_client if crtsh_client is not None else CrtShClient(cfg)
        self.rdap_client = rdap_client if rdap_client is not None else RDAPClient(cfg)
        self.audit_logger = audit_logger if audit_logger is not None else AuditLogger(cfg.audit_log)

    @property
    def cache(self) -> CVECache:
        """Lazily initialize the SQLite cache so `intel env` never creates unused DB files."""
        if self._cache is None:
            self._cache = CVECache(self.cfg.cache_db)
        return self._cache

    def env_status(self) -> IntelEnvStatus:
        """Return masked configuration status of all five passive intelligence feeds."""
        feed_defs = [
            ("nvd", "NVD_API_KEY", self.cfg.get_nvd_api_key(), "NVD 2.0 CVE lookup (50 req/30s)"),
            (
                "github",
                "GITHUB_TOKEN",
                self.cfg.get_github_token(),
                "GitHub Security Advisories (GHSA)",
            ),
            (
                "virustotal",
                "VIRUSTOTAL_API_KEY",
                self.cfg.get_virustotal_api_key(),
                "VirusTotal v3 passive domain/IP reputation",
            ),
            (
                "greynoise",
                "GREYNOISE_API_KEY",
                self.cfg.get_greynoise_api_key(),
                "GreyNoise IP scanner & RIOT context",
            ),
            (
                "urlscan",
                "URLSCAN_API_KEY",
                self.cfg.get_urlscan_api_key(),
                "urlscan.io passive historical search",
            ),
        ]
        feeds: list[IntelFeedKeyStatus] = []
        for name, env_var, (val, src), purpose in feed_defs:
            feeds.append(
                IntelFeedKeyStatus(
                    feed=name,
                    env_var=env_var,
                    configured=bool(val),
                    masked_key=mask_api_key(val) if val else None,
                    source=src,
                    purpose=purpose,
                )
            )
        default_env = (
            self.cfg.project_env_file
            if self.cfg.project_env_file is not None and self.cfg.project_env_file.is_file()
            else self.cfg.env_file
        )
        return IntelEnvStatus(env_file=str(default_env), feeds=feeds)

    def save_env(
        self,
        *,
        nvd_key: str | None = None,
        github_token: str | None = None,
        vt_key: str | None = None,
        greynoise_key: str | None = None,
        urlscan_key: str | None = None,
        env_file: Path | None = None,
    ) -> IntelEnvStatus:
        """Persist one or more threat-intel API keys to a `0600` `.env` file."""
        updates: dict[str, str] = {}
        mapping = [
            ("NVD_API_KEY", nvd_key, "--set-nvd-key"),
            ("GITHUB_TOKEN", github_token, "--set-github-key"),
            ("VIRUSTOTAL_API_KEY", vt_key, "--set-vt-key"),
            ("GREYNOISE_API_KEY", greynoise_key, "--set-greynoise-key"),
            ("URLSCAN_API_KEY", urlscan_key, "--set-urlscan-key"),
        ]
        for env_name, raw_val, flag in mapping:
            if raw_val is not None:
                cleaned = raw_val.strip()
                if not cleaned:
                    raise ValidationError(f"{flag} cannot be empty.")
                updates[env_name] = cleaned

        if not updates:
            raise ValidationError("Provide at least one --set-*-key flag to update `.env`.")

        target_path = env_file.expanduser().resolve() if env_file is not None else self.cfg.env_file
        existing = load_dotenv_file(target_path)
        existing.update(updates)

        if target_path.parent == self.cfg.home_dir:
            ensure_private_dir(target_path.parent)
        else:
            target_path.parent.mkdir(parents=True, exist_ok=True)

        target_path.write_text(_format_dotenv(existing), encoding="utf-8")
        chmod_private_file(target_path)

        if env_file is not None:
            feeds: list[IntelFeedKeyStatus] = []
            specs = [
                ("nvd", "NVD_API_KEY", "NVD 2.0 CVE lookup (50 req/30s)"),
                ("github", "GITHUB_TOKEN", "GitHub Security Advisories (GHSA)"),
                ("virustotal", "VIRUSTOTAL_API_KEY", "VirusTotal v3 passive domain/IP reputation"),
                ("greynoise", "GREYNOISE_API_KEY", "GreyNoise IP scanner & RIOT context"),
                ("urlscan", "URLSCAN_API_KEY", "urlscan.io passive historical search"),
            ]
            for feed_name, env_var, purpose in specs:
                val = existing.get(env_var, "").strip() or None
                feeds.append(
                    IntelFeedKeyStatus(
                        feed=feed_name,
                        env_var=env_var,
                        configured=bool(val),
                        masked_key=mask_api_key(val) if val else None,
                        source=str(target_path) if val else "unset",
                        purpose=purpose,
                    )
                )
            return IntelEnvStatus(env_file=str(target_path), feeds=feeds)
        return self.env_status()

    def lookup(
        self,
        raw_indicator: str,
        *,
        pinned_ip: str | None = None,
        sources: Sequence[str] | None = None,
        offline: bool = False,
        refresh: bool = False,
    ) -> IntelLookupResult:
        """Query passive threat-intel feeds for a domain, URL, or IP (zero target contact)."""
        parsed = parse_target(raw_indicator)
        indicator = parsed.host
        ind_type = "ip" if parsed.is_ip else "domain"
        effective_ip = indicator if parsed.is_ip else (pinned_ip.strip() if pinned_ip else None)

        requested = (
            [s.strip().lower() for s in sources if s.strip()]
            if sources
            else list(DEFAULT_INTEL_LOOKUP_SOURCES)
        )
        for src in requested:
            if src not in SUPPORTED_INTEL_SOURCES:
                raise ValidationError(
                    f"Unsupported intel source '{src}'. "
                    f"Choose from {', '.join(SUPPORTED_INTEL_SOURCES)}."
                )

        vt_res: VirusTotalIntel | None = None
        gn_res: GreyNoiseIntel | None = None
        us_res: URLScanSummary | None = None
        rdap_res: RDAPLookupResult | None = None
        warnings: list[str] = []
        queried: list[str] = []
        all_cached = True

        # 1. VirusTotal v3 (domain or IP)
        if "vt" in requested:
            vt_key = _cache_key("vt", {"type": ind_type, "indicator": indicator})
            vt_payload: Any = (
                None
                if refresh
                else self.cache.get(vt_key, ttl_seconds=self.cfg.cve_cache_ttl_seconds)
            )
            if isinstance(vt_payload, dict):
                vt_res = parse_virustotal_payload(
                    vt_payload, indicator=indicator, indicator_type=ind_type
                )
                queried.append("vt")
            elif offline:
                warnings.append("vt: cache miss in --offline mode")
            elif not self.vt_client.configured:
                warnings.append("vt: VIRUSTOTAL_API_KEY not configured (skipped)")
            else:
                all_cached = False
                started = time.monotonic()
                try:
                    vt_payload = self.vt_client.fetch(indicator, indicator_type=ind_type)
                    self.cache.set(vt_key, vt_payload)
                    vt_res = parse_virustotal_payload(
                        vt_payload, indicator=indicator, indicator_type=ind_type
                    )
                    queried.append("vt")
                    self._log_intel("intel vt", indicator, "success", 0, started)
                except NetworkError as exc:
                    warnings.append(f"vt: {exc}")
                    self._log_intel(
                        "intel vt", indicator, "error", int(ExitCode.ERROR), started, error=str(exc)
                    )

        # 2. GreyNoise Community (IPv4 only — direct IP or validated pinned_ip)
        if "greynoise" in requested:
            if not effective_ip or not _is_ipv4(effective_ip):
                if ind_type == "ip":
                    warnings.append("greynoise: IPv6 addresses are not supported by Community API")
                else:
                    warnings.append("greynoise: skipped (requires IPv4 or pinned IP from assess)")
            else:
                gn_key = _cache_key("gn", {"ip": effective_ip})
                gn_payload: Any = (
                    None
                    if refresh
                    else self.cache.get(gn_key, ttl_seconds=self.cfg.cve_cache_ttl_seconds)
                )
                if isinstance(gn_payload, dict):
                    gn_res = parse_greynoise_payload(gn_payload, ip=effective_ip)
                    queried.append("greynoise")
                elif offline:
                    warnings.append("greynoise: cache miss in --offline mode")
                elif not self.greynoise_client.configured:
                    warnings.append("greynoise: GREYNOISE_API_KEY not configured (skipped)")
                else:
                    all_cached = False
                    started = time.monotonic()
                    try:
                        gn_payload = self.greynoise_client.fetch_ip(effective_ip)
                        self.cache.set(gn_key, gn_payload)
                        gn_res = parse_greynoise_payload(gn_payload, ip=effective_ip)
                        queried.append("greynoise")
                        self._log_intel("intel greynoise", effective_ip, "success", 0, started)
                    except NetworkError as exc:
                        warnings.append(f"greynoise: {exc}")
                        self._log_intel(
                            "intel greynoise",
                            effective_ip,
                            "error",
                            int(ExitCode.ERROR),
                            started,
                            error=str(exc),
                        )

        # 3. urlscan.io passive search index (`domain:` or `ip:`)
        if "urlscan" in requested:
            us_query = f"ip:{indicator}" if ind_type == "ip" else f"domain:{indicator}"
            us_key = _cache_key("urlscan", {"q": us_query})
            us_payload: Any = (
                None
                if refresh
                else self.cache.get(us_key, ttl_seconds=self.cfg.cve_cache_ttl_seconds)
            )
            if isinstance(us_payload, dict):
                us_res = parse_urlscan_payload(us_payload, query=us_query)
                queried.append("urlscan")
            elif offline:
                warnings.append("urlscan: cache miss in --offline mode")
            else:
                all_cached = False
                started = time.monotonic()
                try:
                    us_payload = self.urlscan_client.search(us_query)
                    self.cache.set(us_key, us_payload)
                    us_res = parse_urlscan_payload(us_payload, query=us_query)
                    queried.append("urlscan")
                    self._log_intel("intel urlscan", us_query, "success", 0, started)
                except NetworkError as exc:
                    warnings.append(f"urlscan: {exc}")
                    self._log_intel(
                        "intel urlscan",
                        us_query,
                        "error",
                        int(ExitCode.ERROR),
                        started,
                        error=str(exc),
                    )

        # 4. RFC 7480–7484 RDAP registration lookup (zero API key)
        if "rdap" in requested:
            try:
                rdap_res = self.rdap_lookup(indicator, offline=offline, refresh=refresh)
                queried.append("rdap")
                all_cached = all_cached and rdap_res.cached
            except NetworkError as exc:
                warnings.append(f"rdap: {exc}")

        return IntelLookupResult(
            indicator=indicator,
            indicator_type=ind_type,
            resolved_ip=effective_ip,
            sources_queried=queried,
            cached=all_cached and bool(queried),
            virustotal=vt_res,
            greynoise=gn_res,
            urlscan=us_res,
            rdap=rdap_res,
            warnings=warnings,
        )

    def ct_lookup(
        self,
        raw_domain: str,
        *,
        offline: bool = False,
        refresh: bool = False,
        export_candidates: Path | None = None,
    ) -> CTLookupResult:
        """Query passive Certificate Transparency logs via crt.sh (zero target contact)."""
        parsed = parse_target(raw_domain)
        if parsed.is_ip:
            raise ValidationError("`intel ct` requires a domain name, not an IP address.")
        domain = parsed.host.lower().rstrip(".")
        cache_k = _cache_key("ct", {"domain": domain})
        cached = False
        raw: Any = (
            None if refresh else self.cache.get(cache_k, ttl_seconds=self.cfg.cve_cache_ttl_seconds)
        )
        if isinstance(raw, list):
            cached = True
        else:
            if offline:
                raise NetworkError(f"Cache miss in --offline mode for CT log lookup '{domain}'.")
            started = time.monotonic()
            try:
                raw = self.crtsh_client.fetch_domain(domain)
                self.cache.set(cache_k, raw)
                self._log_intel("intel ct", domain, "success", 0, started)
            except Exception as exc:
                self._log_intel(
                    "intel ct",
                    domain,
                    "error",
                    int(ExitCode.ERROR),
                    started,
                    error=str(exc),
                )
                raise

        res = parse_crtsh_payload(raw, domain=domain, cached=cached)
        if export_candidates is not None:
            out_path = export_candidates.expanduser().resolve()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            lines = [
                f"# Passive Certificate Transparency candidates for {domain}",
                "# Review and authorize before importing with `s1shell scope import`.",
                *res.unique_subdomains,
            ]
            out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            res = replace(res, exported_candidates_file=str(out_path))
        return res

    def rdap_lookup(
        self,
        raw_indicator: str,
        *,
        offline: bool = False,
        refresh: bool = False,
    ) -> RDAPLookupResult:
        """Query RFC 7480–7484 RDAP registration data for a domain or IP (zero target contact)."""
        parsed = parse_target(raw_indicator)
        indicator = parsed.host.lower().rstrip(".")
        ind_type = "ip" if parsed.is_ip else "domain"
        cache_k = _cache_key("rdap", {"type": ind_type, "indicator": indicator})
        cached = False
        cached_blob: Any = (
            None if refresh else self.cache.get(cache_k, ttl_seconds=self.cfg.cve_cache_ttl_seconds)
        )
        if isinstance(cached_blob, dict) and isinstance(cached_blob.get("payload"), dict):
            cached = True
            payload = cached_blob["payload"]
            source_url = str(cached_blob.get("source_url") or "") or None
        else:
            if offline:
                raise NetworkError(f"Cache miss in --offline mode for RDAP lookup '{indicator}'.")
            started = time.monotonic()
            try:
                payload, source_url = self.rdap_client.fetch(indicator, indicator_type=ind_type)
                self.cache.set(cache_k, {"payload": payload, "source_url": source_url})
                self._log_intel("intel rdap", indicator, "success", 0, started)
            except Exception as exc:
                self._log_intel(
                    "intel rdap",
                    indicator,
                    "error",
                    int(ExitCode.ERROR),
                    started,
                    error=str(exc),
                )
                raise
        return parse_rdap_payload(
            payload,
            indicator=indicator,
            indicator_type=ind_type,
            source_url=source_url,
            cached=cached,
        )

    def advisories(
        self,
        *,
        cve_id: str | None = None,
        ecosystem: str | None = None,
        package: str | None = None,
        limit: int = 15,
        offline: bool = False,
        refresh: bool = False,
    ) -> GitHubAdvisoryResult:
        """Query GitHub Security Advisories (GHSA) by CVE ID or ecosystem+package."""
        if not cve_id and not package:
            raise ValidationError("Provide --cve CVE-ID or --package PKG for `intel advisory`.")
        if limit <= 0:
            raise ValidationError("--limit must be a positive integer.")

        norm_cve = cve_id.strip().upper() if cve_id else None
        norm_eco = ecosystem.strip().lower() if ecosystem else None
        norm_pkg = package.strip() if package else None

        q_dict: dict[str, object] = {
            "cve_id": norm_cve,
            "ecosystem": norm_eco,
            "package": norm_pkg,
            "limit": limit,
        }
        cache_k = _cache_key("ghsa", q_dict)
        cached = False
        raw: Any = (
            None if refresh else self.cache.get(cache_k, ttl_seconds=self.cfg.cve_cache_ttl_seconds)
        )
        if isinstance(raw, list):
            cached = True
        else:
            if offline:
                raise NetworkError("Cache miss in --offline mode for GitHub Advisories lookup.")
            started = time.monotonic()
            target_label = norm_cve or f"{norm_eco or 'any'}:{norm_pkg}"
            try:
                raw = self.github_client.fetch_advisories(
                    cve_id=norm_cve,
                    ecosystem=norm_eco,
                    package=norm_pkg,
                    per_page=limit,
                )
                self.cache.set(cache_k, raw)
                self._log_intel("intel advisory", target_label, "success", 0, started)
            except Exception as exc:
                self._log_intel(
                    "intel advisory",
                    target_label,
                    "error",
                    int(ExitCode.ERROR),
                    started,
                    error=str(exc),
                )
                raise

        parsed = parse_github_advisories_payload(raw)[:limit]
        return GitHubAdvisoryResult(query=q_dict, cached=cached, advisories=parsed)

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
