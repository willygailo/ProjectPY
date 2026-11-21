"""Offline CycloneDX 1.5 JSON SBOM generator from lockfiles, manifests, and Dockerfiles."""

from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import quote

from s1shell import __version__
from s1shell.cve.audit_deps import discover_dependency_files, parse_dependency_file
from s1shell.cve.models import DependencyPackage
from s1shell.errors import ValidationError
from s1shell.models import utc_now_iso
from s1shell.scan.models import SBOMGenerateResult

_ECO_TO_PURL_TYPE: dict[str, str] = {
    "PyPI": "pypi",
    "npm": "npm",
    "Go": "golang",
    "crates.io": "cargo",
    "Maven": "maven",
    "NuGet": "nuget",
    "Packagist": "composer",
    "RubyGems": "gem",
    "OCI": "oci",
}

_PEP508_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?\s*(?:===?|>=|~=|<=|>|<)\s*([0-9][A-Za-z0-9._+-]*)"
)
_PYPROJECT_DEP_STR_RE = re.compile(r'["\']([^"\']+)["\']')
_SKIP_DIRS = frozenset(
    {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", "target"}
)


def _make_purl(ecosystem: str, name: str, version: str) -> str:
    ptype = _ECO_TO_PURL_TYPE.get(ecosystem, ecosystem.lower())
    clean_name = name.strip()
    if ptype == "maven" and ":" in clean_name:
        group, artifact = clean_name.split(":", 1)
        g_enc = quote(group, safe="")
        a_enc = quote(artifact, safe="")
        return f"pkg:maven/{g_enc}/{a_enc}@{quote(version, safe='')}"
    if ptype == "npm" and clean_name.startswith("@") and "/" in clean_name:
        scope, pkg = clean_name.split("/", 1)
        return f"pkg:npm/{quote(scope, safe='')}/{quote(pkg, safe='')}@{quote(version, safe='')}"
    return f"pkg:{ptype}/{quote(clean_name, safe='/')}@{quote(version, safe='')}"


def _parse_pyproject_toml(path: Path) -> list[DependencyPackage]:
    text = path.read_text(encoding="utf-8", errors="replace")
    pkgs: list[DependencyPackage] = []
    in_deps = False
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if re.match(r"^dependencies\s*=\s*\[", line):
            in_deps = True
            for val in _PYPROJECT_DEP_STR_RE.findall(line):
                m = _PEP508_RE.match(val)
                if m:
                    pkgs.append(DependencyPackage("PyPI", m.group(1), m.group(2), str(path)))
            if "]" in line:
                in_deps = False
            continue
        if in_deps:
            for val in _PYPROJECT_DEP_STR_RE.findall(line):
                m = _PEP508_RE.match(val)
                if m:
                    pkgs.append(DependencyPackage("PyPI", m.group(1), m.group(2), str(path)))
            if "]" in line:
                in_deps = False
    return pkgs


def _parse_package_json(path: Path) -> list[DependencyPackage]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    pkgs: list[DependencyPackage] = []
    for section in ("dependencies", "devDependencies"):
        sec = data.get(section)
        if not isinstance(sec, dict):
            continue
        for name, raw_ver in sec.items():
            cleaned = str(raw_ver or "").strip().lstrip("^~>=< ")
            if cleaned and cleaned[0].isdigit():
                pkgs.append(DependencyPackage("npm", str(name), cleaned, str(path)))
    return pkgs


def _parse_dockerfile_images(path: Path) -> list[DependencyPackage]:
    pkgs: list[DependencyPackage] = []
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line.upper().startswith("FROM "):
            continue
        tokens = line.split()
        if len(tokens) < 2:
            continue
        img = tokens[1]
        if img.lower() == "scratch" or img.startswith("$"):
            continue
        if "@sha256:" in img:
            name, ver = img.split("@", 1)
        elif ":" in img:
            name, ver = img.rsplit(":", 1)
        else:
            name, ver = img, "latest"
        pkgs.append(DependencyPackage("OCI", name, ver, str(path)))
    return pkgs


def generate_cyclonedx_sbom(
    path: Path,
    *,
    recursive: bool = True,
    include_manifests: bool = True,
) -> SBOMGenerateResult:
    """Generate a CycloneDX 1.5 JSON SBOM from local lockfiles, manifests, and Dockerfiles."""
    resolved = path.expanduser().resolve()
    if not resolved.exists():
        raise ValidationError(f"SBOM target path does not exist: '{path}'.")

    files_scanned: list[str] = []
    packages: list[DependencyPackage] = []
    seen: set[tuple[str, str, str]] = set()

    def _add_pkg(pkg: DependencyPackage) -> None:
        key = (pkg.ecosystem, pkg.name.lower(), pkg.version)
        if key not in seen:
            seen.add(key)
            packages.append(pkg)

    dep_files = discover_dependency_files(resolved, recursive=recursive)
    for df in dep_files:
        try:
            _, parsed = parse_dependency_file(df)
        except ValidationError:
            continue
        rel_lbl = str(df.relative_to(resolved)) if resolved.is_dir() else df.name
        files_scanned.append(rel_lbl)
        for pkg in parsed:
            _add_pkg(pkg)

    if include_manifests and resolved.is_dir():
        iterator = resolved.rglob("*") if recursive else resolved.iterdir()
        for item in sorted(iterator):
            if not item.is_file():
                continue
            rel = item.relative_to(resolved)
            if any(part in _SKIP_DIRS for part in rel.parts[:-1]):
                continue
            low = item.name.lower()
            if low == "pyproject.toml":
                parsed = _parse_pyproject_toml(item)
                if parsed:
                    files_scanned.append(rel.as_posix())
                    for pkg in parsed:
                        _add_pkg(pkg)
            elif low == "package.json":
                # Only supplement if no package-lock.json in same directory
                if not (item.parent / "package-lock.json").exists():
                    parsed = _parse_package_json(item)
                    if parsed:
                        files_scanned.append(rel.as_posix())
                        for pkg in parsed:
                            _add_pkg(pkg)
            elif (
                low == "dockerfile" or low.startswith("dockerfile.") or low.endswith(".dockerfile")
            ):
                parsed = _parse_dockerfile_images(item)
                if parsed:
                    files_scanned.append(rel.as_posix())
                    for pkg in parsed:
                        _add_pkg(pkg)
    elif resolved.is_file() and not dep_files:
        low = resolved.name.lower()
        if low == "pyproject.toml":
            files_scanned.append(resolved.name)
            for pkg in _parse_pyproject_toml(resolved):
                _add_pkg(pkg)
        elif low == "package.json":
            files_scanned.append(resolved.name)
            for pkg in _parse_package_json(resolved):
                _add_pkg(pkg)
        elif low == "dockerfile" or low.endswith(".dockerfile"):
            files_scanned.append(resolved.name)
            for pkg in _parse_dockerfile_images(resolved):
                _add_pkg(pkg)

    serial = f"urn:uuid:{uuid.uuid4()}"
    ecosystems: dict[str, int] = {}
    components: list[dict[str, Any]] = []
    for pkg in sorted(packages, key=lambda p: (p.ecosystem, p.name.lower(), p.version)):
        ecosystems[pkg.ecosystem] = ecosystems.get(pkg.ecosystem, 0) + 1
        purl = _make_purl(pkg.ecosystem, pkg.name, pkg.version)
        comp_type = "container" if pkg.ecosystem == "OCI" else "library"
        comp: dict[str, Any] = {
            "type": comp_type,
            "bom-ref": purl,
            "name": pkg.name,
            "version": pkg.version,
            "purl": purl,
            "properties": [
                {"name": "s1shell:ecosystem", "value": pkg.ecosystem},
            ],
        }
        if pkg.source_file:
            src_lbl = (
                Path(pkg.source_file).relative_to(resolved).as_posix()
                if resolved.is_dir() and Path(pkg.source_file).is_relative_to(resolved)
                else Path(pkg.source_file).name
            )
            comp["properties"].append({"name": "s1shell:source_file", "value": src_lbl})
        components.append(comp)

    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": utc_now_iso(),
            "tools": [
                {
                    "vendor": "S1shell",
                    "name": "s1shell",
                    "version": __version__,
                }
            ],
            "component": {
                "type": "application",
                "name": resolved.name,
            },
        },
        "components": components,
    }

    return SBOMGenerateResult(
        target_path=str(path),
        bom_format="CycloneDX",
        spec_version="1.5",
        serial_number=serial,
        files_scanned=sorted(set(files_scanned)),
        component_count=len(components),
        ecosystems=ecosystems,
        bom=bom,
    )
