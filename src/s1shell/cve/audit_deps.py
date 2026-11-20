"""Zero-target-contact lockfile & CycloneDX SBOM vulnerability auditor via OSV.dev + KEV/EPSS."""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import replace
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import httpx

from s1shell.audit import AuditEvent, AuditLogger
from s1shell.config import RuntimeConfig
from s1shell.cve.cache import CVECache
from s1shell.cve.enrichment import EPSSClient, KEVClient
from s1shell.cve.models import (
    DependencyAuditResult,
    DependencyPackage,
    DependencyVuln,
    compute_cve_priority,
)
from s1shell.errors import ExitCode, NetworkError, ValidationError
from s1shell.http import build_intel_client

_REQ_PIN_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?\s*===?\s*([A-Za-z0-9._+-]+)"
)
_GOMOD_REQ_RE = re.compile(r"^\s*(?:require\s+)?([^\s/]+(?:/[^\s]+)+)\s+v([0-9][^\s]*)\s*$")
_PURL_ECOSYSTEM_MAP = {
    "pypi": "PyPI",
    "npm": "npm",
    "golang": "Go",
    "cargo": "crates.io",
    "maven": "Maven",
    "nuget": "NuGet",
    "composer": "Packagist",
    "gem": "RubyGems",
}
_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _parse_purl(purl: str) -> DependencyPackage | None:
    """Parse a standard `pkg:<type>/<name>@<version>` Package URL."""
    cleaned = purl.strip()
    if not cleaned.startswith("pkg:") or "@" not in cleaned:
        return None
    body = cleaned[4:].split("?", 1)[0].split("#", 1)[0]
    if "/" not in body:
        return None
    pkg_type, rest = body.split("/", 1)
    eco = _PURL_ECOSYSTEM_MAP.get(pkg_type.lower())
    if not eco or "@" not in rest:
        return None
    name_raw, ver_raw = rest.rsplit("@", 1)
    name = unquote(name_raw).strip()
    ver = unquote(ver_raw).strip()
    if eco == "Maven" and "/" in name:
        name = name.replace("/", ":")
    if not name or not ver:
        return None
    return DependencyPackage(ecosystem=eco, name=name, version=ver)


def parse_dependency_file(path: Path) -> tuple[str, list[DependencyPackage]]:
    """Parse a lockfile or CycloneDX JSON SBOM into pinned `(format, packages)`."""
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValidationError(f"Failed to read dependency file '{path}': {exc}") from exc

    fname = path.name.lower()
    packages: list[DependencyPackage] = []
    seen: set[tuple[str, str, str]] = set()

    def _add(eco: str, name: str, ver: str) -> None:
        key = (eco, name.strip(), ver.strip())
        if key[1] and key[2] and key not in seen:
            seen.add(key)
            packages.append(DependencyPackage(ecosystem=eco, name=key[1], version=key[2]))

    # 1. JSON formats: package-lock.json or CycloneDX SBOM
    stripped = raw_text.lstrip()
    if fname.endswith(".json") or stripped.startswith("{"):
        try:
            data = json.loads(raw_text)
        except ValueError as exc:
            raise ValidationError(f"Invalid JSON in '{path}': {exc}") from exc
        if not isinstance(data, dict):
            raise ValidationError(f"Expected JSON object in '{path}'.")

        if data.get("bomFormat") == "CycloneDX" or isinstance(data.get("components"), list):
            for comp in data.get("components", []):
                if not isinstance(comp, dict):
                    continue
                purl = str(comp.get("purl") or "").strip()
                if purl:
                    parsed = _parse_purl(purl)
                    if parsed is not None:
                        _add(parsed.ecosystem, parsed.name, parsed.version)
            return "cyclonedx", packages

        # npm package-lock.json (v2/v3 `packages` or v1 `dependencies`)
        if isinstance(data.get("packages"), dict):
            for pkg_path, meta in data["packages"].items():
                if not isinstance(meta, dict) or not pkg_path:
                    continue
                ver = str(meta.get("version") or "").strip()
                if not ver:
                    continue
                name = str(meta.get("name") or "").strip()
                if not name and "node_modules/" in pkg_path:
                    name = pkg_path.rsplit("node_modules/", 1)[-1]
                if name:
                    _add("npm", name, ver)
            return "package-lock.json", packages

        if isinstance(data.get("dependencies"), dict):

            def _walk_npm_deps(deps: dict[str, Any]) -> None:
                for dep_name, meta in deps.items():
                    if not isinstance(meta, dict):
                        continue
                    ver = str(meta.get("version") or "").strip()
                    if ver:
                        _add("npm", str(dep_name), ver)
                    nested = meta.get("dependencies")
                    if isinstance(nested, dict):
                        _walk_npm_deps(nested)

            _walk_npm_deps(data["dependencies"])
            return "package-lock.json", packages

        raise ValidationError(
            f"Unrecognized JSON dependency format in '{path}'. "
            "Supported JSON formats: package-lock.json and CycloneDX SBOM."
        )

    # 2. Go `go.mod`
    if fname == "go.mod" or fname.endswith(".mod"):
        in_require = False
        for raw_line in raw_text.splitlines():
            line = raw_line.split("//", 1)[0].strip()
            if not line:
                continue
            if line.startswith("require ("):
                in_require = True
                continue
            if in_require and line == ")":
                in_require = False
                continue
            m = _GOMOD_REQ_RE.match(line)
            if m and (in_require or line.startswith("require ")):
                _add("Go", m.group(1), m.group(2))
        return "go.mod", packages

    # 3. Rust `Cargo.lock`
    if fname == "cargo.lock":
        cur_name: str | None = None
        cur_ver: str | None = None
        for raw_line in raw_text.splitlines():
            line = raw_line.strip()
            if line == "[[package]]":
                if cur_name and cur_ver:
                    _add("crates.io", cur_name, cur_ver)
                cur_name = None
                cur_ver = None
                continue
            if line.startswith("name = "):
                cur_name = line.split("=", 1)[1].strip().strip('"')
            elif line.startswith("version = "):
                cur_ver = line.split("=", 1)[1].strip().strip('"')
        if cur_name and cur_ver:
            _add("crates.io", cur_name, cur_ver)
        return "Cargo.lock", packages

    # 4. Default: Python `requirements.txt`
    for raw_line in raw_text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http://", "https://")):
            continue
        m = _REQ_PIN_RE.match(line)
        if m:
            _add("PyPI", m.group(1), m.group(2))
    return "requirements.txt", packages


def _extract_osv_severity(vuln: dict[str, Any]) -> tuple[str, float | None]:
    db_spec = vuln.get("database_specific")
    if isinstance(db_spec, dict) and db_spec.get("severity"):
        raw = str(db_spec["severity"]).strip().upper()
        if raw == "MODERATE":
            raw = "MEDIUM"
        if raw in _SEV_RANK:
            return raw, None

    for sev_item in vuln.get("severity", []):
        if not isinstance(sev_item, dict):
            continue
        score_raw = str(sev_item.get("score") or "").strip()
        try:
            num = float(score_raw)
        except ValueError:
            continue
        if num >= 9.0:
            return "CRITICAL", num
        if num >= 7.0:
            return "HIGH", num
        if num >= 4.0:
            return "MEDIUM", num
        return "LOW", num

    return "MEDIUM", None


def _extract_fixed_versions(vuln: dict[str, Any], pkg_name: str) -> list[str]:
    fixed: list[str] = []
    for aff in vuln.get("affected", []):
        if not isinstance(aff, dict):
            continue
        pkg = aff.get("package", {})
        if (
            isinstance(pkg, dict)
            and pkg.get("name")
            and str(pkg["name"]).lower() != pkg_name.lower()
        ):
            continue
        for rng in aff.get("ranges", []):
            if not isinstance(rng, dict):
                continue
            for ev in rng.get("events", []):
                if isinstance(ev, dict) and ev.get("fixed"):
                    fver = str(ev["fixed"]).strip()
                    if fver and fver not in fixed:
                        fixed.append(fver)
    return fixed


class OSVClient:
    """Client for public OSV.dev batch vulnerability queries (zero target contact)."""

    def __init__(
        self,
        cfg: RuntimeConfig,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._cfg = cfg
        self._transport = transport

    def query_batch(self, packages: list[DependencyPackage]) -> list[list[dict[str, Any]]]:
        """Query OSV.dev `/v1/querybatch` for pinned packages, returning aligned vuln lists."""
        if not packages:
            return []
        out: list[list[dict[str, Any]]] = []
        with build_intel_client(self._cfg, transport=self._transport) as client:
            for start in range(0, len(packages), 100):
                chunk = packages[start : start + 100]
                body = {
                    "queries": [
                        {
                            "package": {"name": p.name, "ecosystem": p.ecosystem},
                            "version": p.version,
                        }
                        for p in chunk
                    ]
                }
                try:
                    resp = client.post(self._cfg.osv_api_url, json=body)
                except httpx.HTTPError as exc:
                    raise NetworkError(f"OSV.dev API request failed: {exc}") from exc
                if resp.status_code != 200:
                    raise NetworkError(f"OSV.dev API returned HTTP {resp.status_code}")
                try:
                    payload = resp.json()
                except ValueError as exc:
                    raise NetworkError(f"OSV.dev API returned invalid JSON: {exc}") from exc
                results = payload.get("results", []) if isinstance(payload, dict) else []
                for idx in range(len(chunk)):
                    raw_item = results[idx] if idx < len(results) else {}
                    item = raw_item if isinstance(raw_item, dict) else {}
                    vulns = item.get("vulns", [])
                    clean_vulns = (
                        [v for v in vulns if isinstance(v, dict)] if isinstance(vulns, list) else []
                    )
                    out.append(clean_vulns)
        return out


class DependencyAuditService:
    """Audits lockfiles & CycloneDX SBOMs against OSV.dev with SQLite cache + KEV/EPSS."""

    def __init__(
        self,
        cfg: RuntimeConfig,
        *,
        cache: CVECache | None = None,
        osv_client: OSVClient | None = None,
        kev_client: KEVClient | None = None,
        epss_client: EPSSClient | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self.cfg = cfg
        self.cache = cache if cache is not None else CVECache(cfg.cache_db)
        self.osv_client = osv_client if osv_client is not None else OSVClient(cfg)
        self.kev_client = kev_client if kev_client is not None else KEVClient(cfg)
        self.epss_client = epss_client if epss_client is not None else EPSSClient(cfg)
        self.audit_logger = audit_logger if audit_logger is not None else AuditLogger(cfg.audit_log)

    def audit_file(
        self,
        path: Path,
        *,
        offline: bool = False,
        refresh: bool = False,
        enrich: bool = False,
        kev_only: bool = False,
    ) -> DependencyAuditResult:
        """Parse `path` and correlate pinned packages with OSV.dev (+ optional KEV/EPSS)."""
        fmt, packages = parse_dependency_file(path)
        if not packages:
            return DependencyAuditResult(
                source_file=str(path),
                format_detected=fmt,
                packages_scanned=0,
                vulnerable_packages=0,
                cached=True,
                vulnerabilities=[],
            )

        sig_payload = json.dumps(
            [(p.ecosystem, p.name, p.version) for p in packages], separators=(",", ":")
        )
        cache_key = "osv_batch_" + hashlib.sha256(sig_payload.encode("utf-8")).hexdigest()

        cached = False
        raw_results: Any = (
            None
            if refresh
            else self.cache.get(cache_key, ttl_seconds=self.cfg.cve_cache_ttl_seconds)
        )
        if isinstance(raw_results, list) and len(raw_results) == len(packages):
            cached = True
        else:
            if offline:
                raise NetworkError(
                    f"Cache miss in --offline mode for dependency audit of '{path}'."
                )
            started = time.monotonic()
            try:
                raw_results = self.osv_client.query_batch(packages)
                self.cache.set(cache_key, raw_results)
                self._log_intel("cve audit", str(path.name), "success", 0, started)
            except Exception as exc:
                self._log_intel(
                    "cve audit",
                    str(path.name),
                    "error",
                    int(ExitCode.ERROR),
                    started,
                    error=str(exc),
                )
                raise

        vulns: list[DependencyVuln] = []
        for pkg, pkg_vulns in zip(packages, raw_results, strict=True):
            if not isinstance(pkg_vulns, list):
                continue
            for v in pkg_vulns:
                if not isinstance(v, dict):
                    continue
                vid = str(v.get("id", "")).strip()
                if not vid:
                    continue
                aliases = [str(a).strip() for a in v.get("aliases", []) if str(a).strip()]
                cve_id = (
                    vid
                    if vid.upper().startswith("CVE-")
                    else next((a.upper() for a in aliases if a.upper().startswith("CVE-")), None)
                )
                sev, cvss_score = _extract_osv_severity(v)
                summary = str(v.get("summary") or v.get("details") or "").strip()[:240]
                refs = [
                    str(r.get("url")).strip()
                    for r in v.get("references", [])
                    if isinstance(r, dict) and r.get("url")
                ][:5]
                fixed = _extract_fixed_versions(v, pkg.name)
                fallback_summary = f"Vulnerability {vid} affecting {pkg.name} {pkg.version}"
                vulns.append(
                    DependencyVuln(
                        package=pkg.name,
                        version=pkg.version,
                        ecosystem=pkg.ecosystem,
                        vuln_id=vid,
                        aliases=aliases,
                        cve_id=cve_id,
                        severity=sev,
                        cvss_score=cvss_score,
                        summary=summary or fallback_summary,
                        fixed_versions=fixed,
                        priority=compute_cve_priority(cvss_score=cvss_score),
                        references=refs,
                    )
                )

        if (enrich or kev_only) and vulns:
            vulns = self._enrich_vulns(vulns, offline=offline, refresh=refresh)

        if kev_only:
            vulns = [v for v in vulns if v.in_kev]

        vulns.sort(
            key=lambda item: (
                0 if item.in_kev else 1,
                _SEV_RANK.get(item.severity, 9),
                -(item.epss_score if item.epss_score is not None else -1.0),
                item.package.lower(),
                item.vuln_id,
            )
        )
        vuln_pkg_count = len({(v.ecosystem, v.package, v.version) for v in vulns})
        return DependencyAuditResult(
            source_file=str(path),
            format_detected=fmt,
            packages_scanned=len(packages),
            vulnerable_packages=vuln_pkg_count,
            cached=cached,
            vulnerabilities=vulns,
        )

    def _enrich_vulns(
        self,
        vulns: list[DependencyVuln],
        *,
        offline: bool,
        refresh: bool,
    ) -> list[DependencyVuln]:
        cve_ids = sorted({v.cve_id for v in vulns if v.cve_id})
        if not cve_ids:
            return vulns

        kev_map: dict[str, dict[str, str]] = {}
        cached_kev: Any = (
            None
            if refresh
            else self.cache.get("cisa_kev_catalog_v1", ttl_seconds=self.cfg.cve_cache_ttl_seconds)
        )
        if isinstance(cached_kev, dict):
            kev_map = cached_kev
        elif not offline:
            try:
                kev_map = self.kev_client.fetch_catalog()
                self.cache.set("cisa_kev_catalog_v1", kev_map)
            except NetworkError:
                kev_map = {}

        epss_map: dict[str, tuple[float, float]] = {}
        e_key = "first_epss_" + hashlib.sha256(",".join(cve_ids).encode("utf-8")).hexdigest()
        cached_epss: Any = (
            None if refresh else self.cache.get(e_key, ttl_seconds=self.cfg.cve_cache_ttl_seconds)
        )
        if isinstance(cached_epss, dict):
            for cid, pair in cached_epss.items():
                if isinstance(pair, list) and len(pair) == 2:
                    epss_map[str(cid)] = (float(pair[0]), float(pair[1]))
        elif not offline:
            try:
                epss_map = self.epss_client.fetch_scores(cve_ids)
                self.cache.set(
                    e_key,
                    json.loads(json.dumps({k: [v[0], v[1]] for k, v in epss_map.items()})),
                )
            except NetworkError:
                epss_map = {}

        enriched: list[DependencyVuln] = []
        for item in vulns:
            cid = item.cve_id
            kev_entry = kev_map.get(cid) if cid else None
            epss_pair = epss_map.get(cid) if cid else None
            in_kev = kev_entry is not None
            epss_val = epss_pair[0] if epss_pair else None
            enriched.append(
                replace(
                    item,
                    in_kev=in_kev,
                    kev_due_date=(kev_entry.get("due_date") or None) if kev_entry else None,
                    epss_score=epss_val,
                    priority=compute_cve_priority(
                        in_kev=in_kev,
                        epss_score=epss_val,
                        cvss_score=item.cvss_score,
                    ),
                )
            )
        return enriched

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
