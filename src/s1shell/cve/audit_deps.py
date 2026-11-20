"""Zero-target-contact lockfile & CycloneDX SBOM vulnerability auditor via OSV.dev + KEV/EPSS."""

from __future__ import annotations

import hashlib
import json
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import replace
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import httpx
import yaml

from s1shell.audit import AuditEvent, AuditLogger
from s1shell.config import RuntimeConfig
from s1shell.cve.cache import CVECache
from s1shell.cve.cvss import calculate_cvss3_base_score, score_to_severity
from s1shell.cve.enrichment import EPSSClient, KEVClient
from s1shell.cve.models import (
    DependencyAuditResult,
    DependencyPackage,
    DependencyVuln,
    compute_cve_priority,
)
from s1shell.cve.nvd import compare_versions
from s1shell.errors import ExitCode, NetworkError, ValidationError
from s1shell.http import build_intel_client

_REQ_PIN_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?\s*===?\s*([A-Za-z0-9._+-]+)"
)
_GOMOD_REQ_RE = re.compile(r"^\s*(?:require\s+)?([^\s/]+(?:/[^\s]+)+)\s+v([0-9][^\s]*)\s*$")
_GEMFILE_SPEC_RE = re.compile(r"^\s{4}([A-Za-z0-9._-]+)\s+\(([0-9][^)\s]*)\)")
_YARN_HEADER_RE = re.compile(r'^"?(@?[^@\s",:][^@\s",]*?)@')
_YARN_VERSION_RE = re.compile(r'^\s+version(?:\s*[:=]\s*|\s+)"?([^"\s]+)"?')
_PNPM_PKG_KEY_RE = re.compile(r"^/?(@?[^@/\s]+(?:/[^@/\s]+)?)[@/]([0-9][^(:\s]+)")
_SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "target",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
}
_DISCOVERABLE_FILENAMES = {
    "requirements.txt",
    "package-lock.json",
    "go.mod",
    "cargo.lock",
    "uv.lock",
    "poetry.lock",
    "pipfile.lock",
    "yarn.lock",
    "pnpm-lock.yaml",
    "composer.lock",
    "gemfile.lock",
    "pom.xml",
}
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


def discover_dependency_files(root: Path, *, recursive: bool = True) -> list[Path]:
    """Discover supported lockfiles and CycloneDX/SPDX SBOMs under a directory."""
    resolved = root.expanduser().resolve()
    if resolved.is_file():
        return [resolved]
    if not resolved.is_dir():
        raise ValidationError(f"Dependency path does not exist: '{root}'.")

    found: list[Path] = []
    iterator = resolved.rglob("*") if recursive else resolved.iterdir()
    for p in iterator:
        if not p.is_file():
            continue
        rel_parts = p.relative_to(resolved).parts
        if any(part in _SKIP_DIRS for part in rel_parts[:-1]):
            continue
        low = p.name.lower()
        if (
            low in _DISCOVERABLE_FILENAMES
            or low.endswith((".cdx.json", ".spdx.json"))
            or (low.startswith("requirements") and low.endswith(".txt"))
        ):
            found.append(p)
    return sorted(found)


def _parse_toml_lock_packages(raw_text: str, *, ecosystem: str) -> list[tuple[str, str, str]]:
    """Parse `[[package]]` blocks from `Cargo.lock`, `uv.lock`, or `poetry.lock`."""
    out: list[tuple[str, str, str]] = []
    cur_name: str | None = None
    cur_ver: str | None = None
    in_pkg = False
    for raw_line in raw_text.splitlines():
        line = raw_line.strip()
        if line == "[[package]]":
            if cur_name and cur_ver:
                out.append((ecosystem, cur_name, cur_ver))
            cur_name = None
            cur_ver = None
            in_pkg = True
            continue
        if line.startswith("[") and line != "[[package]]":
            if cur_name and cur_ver:
                out.append((ecosystem, cur_name, cur_ver))
                cur_name = None
                cur_ver = None
            in_pkg = False
            continue
        if not in_pkg:
            continue
        if line.startswith("name = "):
            cur_name = line.split("=", 1)[1].strip().strip('"').strip("'")
        elif line.startswith("version = "):
            cur_ver = line.split("=", 1)[1].strip().strip('"').strip("'")
    if cur_name and cur_ver:
        out.append((ecosystem, cur_name, cur_ver))
    return out


def build_upgrade_commands(vulns: list[DependencyVuln]) -> list[str]:
    """Generate deterministic safe upgrade commands picking the highest required fixed version."""
    upgrades: dict[tuple[str, str], str] = {}
    for v in vulns:
        if not v.fixed_versions:
            continue
        key = (v.ecosystem, v.package)
        for cand in v.fixed_versions:
            cleaned = cand.strip()
            if not cleaned:
                continue
            existing = upgrades.get(key)
            if existing is None or compare_versions(cleaned, existing) > 0:
                upgrades[key] = cleaned

    by_eco: dict[str, list[tuple[str, str]]] = {}
    for (eco, pkg), ver in sorted(upgrades.items()):
        by_eco.setdefault(eco, []).append((pkg, ver))

    cmds: list[str] = []
    for eco, items in by_eco.items():
        if eco == "PyPI":
            specs = " ".join(f'"{p}>={v}"' for p, v in items[:10])
            cmds.append(f"pip install --upgrade {specs}")
        elif eco == "npm":
            specs = " ".join(f"{p}@{v}" for p, v in items[:10])
            cmds.append(f"npm install {specs}")
        elif eco == "Go":
            specs = " ".join(f"{p}@v{v.lstrip('v')}" for p, v in items[:10])
            cmds.append(f"go get {specs} && go mod tidy")
        elif eco == "crates.io":
            specs = " ".join(f"-p {p}" for p, _ in items[:10])
            cmds.append(f"cargo update {specs}")
        elif eco == "Packagist":
            specs = " ".join(f"{p}:^{v}" for p, v in items[:10])
            cmds.append(f"composer require {specs}")
        elif eco == "RubyGems":
            specs = " ".join(p for p, _ in items[:10])
            cmds.append(f"bundle update {specs}")
    return cmds


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
            packages.append(
                DependencyPackage(
                    ecosystem=eco,
                    name=key[1],
                    version=key[2],
                    source_file=str(path),
                )
            )

    # 1. JSON formats: CycloneDX SBOM, SPDX 2.3 SBOM, package-lock.json, Pipfile.lock, composer.lock
    stripped = raw_text.lstrip()
    if (
        fname.endswith(".json")
        or fname in {"pipfile.lock", "composer.lock"}
        or stripped.startswith("{")
    ):
        try:
            data = json.loads(raw_text)
        except ValueError as exc:
            raise ValidationError(f"Invalid JSON in '{path}': {exc}") from exc
        if not isinstance(data, dict):
            raise ValidationError(f"Expected JSON object in '{path}'.")

        # 1a. CycloneDX JSON SBOM
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

        # 1b. SPDX 2.x JSON SBOM
        if data.get("spdxVersion") or (
            isinstance(data.get("packages"), list) and data.get("SPDXID")
        ):
            for pkg in data.get("packages", []):
                if not isinstance(pkg, dict):
                    continue
                for ref in pkg.get("externalRefs", []) or []:
                    if not isinstance(ref, dict):
                        continue
                    if str(ref.get("referenceType") or "").lower() == "purl":
                        purl_str = str(ref.get("referenceLocator") or "").strip()
                        parsed = _parse_purl(purl_str)
                        if parsed is not None:
                            _add(parsed.ecosystem, parsed.name, parsed.version)
            return "spdx", packages

        # 1c. PHP composer.lock
        if fname == "composer.lock" or (
            isinstance(data.get("packages"), list) and "content-hash" in data
        ):
            for section in ("packages", "packages-dev"):
                for item in data.get(section, []) or []:
                    if not isinstance(item, dict):
                        continue
                    cname = str(item.get("name") or "").strip()
                    cver = str(item.get("version") or "").strip().lstrip("v")
                    if cname and cver:
                        _add("Packagist", cname, cver)
            return "composer.lock", packages

        # 1d. Python Pipfile.lock
        if fname == "pipfile.lock" or (
            isinstance(data.get("_meta"), dict) and isinstance(data.get("default"), dict)
        ):
            for section in ("default", "develop"):
                sec_map = data.get(section)
                if not isinstance(sec_map, dict):
                    continue
                for pname, meta in sec_map.items():
                    if not isinstance(meta, dict):
                        continue
                    pver = str(meta.get("version") or "").strip().lstrip("=")
                    if pname and pver:
                        _add("PyPI", str(pname), pver)
            return "Pipfile.lock", packages

        # 1e. npm package-lock.json (v2/v3 `packages` or v1 `dependencies`)
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
            f"Unrecognized JSON dependency format in '{path}'. Supported JSON formats: "
            "package-lock.json, CycloneDX, SPDX, Pipfile.lock, composer.lock."
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

    # 3. Rust `Cargo.lock` / Python `uv.lock` / `poetry.lock`
    if fname in {"cargo.lock", "uv.lock", "poetry.lock"}:
        eco = "crates.io" if fname == "cargo.lock" else "PyPI"
        fmt_label = {
            "cargo.lock": "Cargo.lock",
            "uv.lock": "uv.lock",
            "poetry.lock": "poetry.lock",
        }[fname]
        for p_eco, p_name, p_ver in _parse_toml_lock_packages(raw_text, ecosystem=eco):
            _add(p_eco, p_name, p_ver)
        return fmt_label, packages

    # 4. Yarn `yarn.lock` (v1 classic & Berry YAML-ish)
    if fname == "yarn.lock":
        cur_yarn_name: str | None = None
        for raw_line in raw_text.splitlines():
            if not raw_line.strip() or raw_line.lstrip().startswith("#"):
                continue
            if not raw_line[0].isspace() and raw_line.rstrip().endswith(":"):
                hm = _YARN_HEADER_RE.match(raw_line.strip())
                cur_yarn_name = hm.group(1).strip() if hm else None
                continue
            if cur_yarn_name:
                vm = _YARN_VERSION_RE.match(raw_line)
                if vm:
                    _add("npm", cur_yarn_name, vm.group(1))
                    cur_yarn_name = None
        return "yarn.lock", packages

    # 5. pnpm `pnpm-lock.yaml`
    if fname == "pnpm-lock.yaml":
        try:
            doc = yaml.safe_load(raw_text) or {}
        except yaml.YAMLError as exc:
            raise ValidationError(f"Invalid YAML in '{path}': {exc}") from exc
        if isinstance(doc, dict):
            for section in ("packages", "snapshots"):
                sec = doc.get(section)
                if not isinstance(sec, dict):
                    continue
                for raw_key in sec:
                    km = _PNPM_PKG_KEY_RE.match(str(raw_key).strip())
                    if km:
                        _add("npm", km.group(1), km.group(2))
        return "pnpm-lock.yaml", packages

    # 6. Ruby `Gemfile.lock`
    if fname == "gemfile.lock":
        in_specs = False
        for raw_line in raw_text.splitlines():
            if raw_line.strip() == "specs:":
                in_specs = True
                continue
            if in_specs and raw_line and not raw_line[0].isspace():
                in_specs = False
            if in_specs:
                gm = _GEMFILE_SPEC_RE.match(raw_line)
                if gm:
                    _add("RubyGems", gm.group(1), gm.group(2))
        return "Gemfile.lock", packages

    # 7. Maven `pom.xml`
    if fname == "pom.xml" or fname.endswith(".xml"):
        try:
            root_el = ET.fromstring(raw_text)  # noqa: S314
        except ET.ParseError as exc:
            raise ValidationError(f"Invalid XML in '{path}': {exc}") from exc
        for dep in root_el.iter():
            if not dep.tag.endswith("dependency"):
                continue
            gid = ""
            aid = ""
            ver = ""
            for child in dep:
                tag = child.tag.rsplit("}", 1)[-1]
                text = (child.text or "").strip()
                if tag == "groupId":
                    gid = text
                elif tag == "artifactId":
                    aid = text
                elif tag == "version":
                    ver = text
            if gid and aid and ver and not ver.startswith("${"):
                _add("Maven", f"{gid}:{aid}", ver)
        return "pom.xml", packages

    # 8. Default: Python `requirements.txt`
    for raw_line in raw_text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http://", "https://")):
            continue
        m = _REQ_PIN_RE.match(line)
        if m:
            _add("PyPI", m.group(1), m.group(2))
    return "requirements.txt", packages


def _extract_osv_severity(vuln: dict[str, Any]) -> tuple[str, float | None]:
    best_score: float | None = None
    best_sev: str | None = None

    for sev_item in vuln.get("severity", []):
        if not isinstance(sev_item, dict):
            continue
        score_raw = str(sev_item.get("score") or "").strip()
        if not score_raw:
            continue
        parsed_vec = calculate_cvss3_base_score(score_raw)
        if parsed_vec is not None:
            num, sev = parsed_vec
            if best_score is None or num > best_score:
                best_score = num
                best_sev = sev
            continue
        try:
            num = float(score_raw)
        except ValueError:
            continue
        sev = score_to_severity(num)
        if best_score is None or num > best_score:
            best_score = num
            best_sev = sev

    db_spec = vuln.get("database_specific")
    db_sev: str | None = None
    if isinstance(db_spec, dict) and db_spec.get("severity"):
        raw = str(db_spec["severity"]).strip().upper()
        if raw == "MODERATE":
            raw = "MEDIUM"
        if raw in _SEV_RANK:
            db_sev = raw

    if best_sev is not None and best_score is not None:
        return best_sev, best_score
    if db_sev is not None:
        return db_sev, best_score
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

    def audit_path(
        self,
        path: Path,
        *,
        recursive: bool = False,
        offline: bool = False,
        refresh: bool = False,
        enrich: bool = False,
        kev_only: bool = False,
    ) -> DependencyAuditResult:
        """Audit either a single lockfile/SBOM or a directory of lockfiles/SBOMs."""
        resolved = path.expanduser().resolve()
        if resolved.is_file():
            return self.audit_file(
                resolved,
                offline=offline,
                refresh=refresh,
                enrich=enrich,
                kev_only=kev_only,
            )
        files = discover_dependency_files(resolved, recursive=recursive)
        if not files:
            raise ValidationError(f"No supported lockfiles or SBOMs found under '{path}'.")

        all_packages: list[DependencyPackage] = []
        formats: list[str] = []
        for fpath in files:
            try:
                fmt, pkgs = parse_dependency_file(fpath)
            except ValidationError:
                continue
            if fmt not in formats:
                formats.append(fmt)
            all_packages.extend(pkgs)

        return self._audit_packages(
            source_label=str(path),
            fmt_label="multi(" + ",".join(formats) + ")"
            if len(formats) > 1
            else (formats[0] if formats else "empty"),
            packages=all_packages,
            source_files=[str(f) for f in files],
            offline=offline,
            refresh=refresh,
            enrich=enrich,
            kev_only=kev_only,
        )

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
        return self._audit_packages(
            source_label=str(path),
            fmt_label=fmt,
            packages=packages,
            source_files=[str(path)],
            offline=offline,
            refresh=refresh,
            enrich=enrich,
            kev_only=kev_only,
        )

    def _audit_packages(
        self,
        *,
        source_label: str,
        fmt_label: str,
        packages: list[DependencyPackage],
        source_files: list[str],
        offline: bool,
        refresh: bool,
        enrich: bool,
        kev_only: bool,
    ) -> DependencyAuditResult:
        if not packages:
            return DependencyAuditResult(
                source_file=source_label,
                format_detected=fmt_label,
                packages_scanned=0,
                vulnerable_packages=0,
                cached=True,
                vulnerabilities=[],
                source_files=source_files,
                upgrade_commands=[],
                unpatched_count=0,
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
                    f"Cache miss in --offline mode for dependency audit of '{source_label}'."
                )
            started = time.monotonic()
            try:
                raw_results = self.osv_client.query_batch(packages)
                self.cache.set(cache_key, raw_results)
                self._log_intel("cve audit", Path(source_label).name, "success", 0, started)
            except Exception as exc:
                self._log_intel(
                    "cve audit",
                    Path(source_label).name,
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
                        source_file=pkg.source_file,
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
        unpatched = sum(1 for v in vulns if not v.fixed_versions)
        return DependencyAuditResult(
            source_file=source_label,
            format_detected=fmt_label,
            packages_scanned=len(packages),
            vulnerable_packages=vuln_pkg_count,
            cached=cached,
            vulnerabilities=vulns,
            source_files=source_files,
            upgrade_commands=build_upgrade_commands(vulns),
            unpatched_count=unpatched,
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
