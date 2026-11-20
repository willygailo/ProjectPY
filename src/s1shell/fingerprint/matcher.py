"""Declarative passive signature loader and matching engine."""

from __future__ import annotations

import re
from collections.abc import Sequence
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from s1shell.fingerprint.models import FingerprintMatch
from s1shell.profile.models import HTMLPassiveAnalysis

_COMPILED_CACHE: dict[str, re.Pattern[str]] = {}


def _compile(pattern: str) -> re.Pattern[str]:
    compiled = _COMPILED_CACHE.get(pattern)
    if compiled is None:
        compiled = re.compile(pattern)
        _COMPILED_CACHE[pattern] = compiled
    return compiled


def load_signatures(
    path: Path | None = None,
    *,
    extra_dir: Path | None = None,
) -> list[dict[str, Any]]:
    """Load passive technology signatures from package data, custom YAML, and `signatures.d`."""
    if path is not None:
        raw_text = path.read_text(encoding="utf-8")
    else:
        raw_text = (
            resources.files("s1shell.fingerprint")
            .joinpath("signatures.yaml")
            .read_text(encoding="utf-8")
        )
    data = yaml.safe_load(raw_text) or {}
    raw_sigs = data.get("signatures", [])
    sigs: list[dict[str, Any]] = list(raw_sigs) if isinstance(raw_sigs, list) else []

    if extra_dir is not None and extra_dir.is_dir():
        for yaml_file in sorted(extra_dir.glob("*.y*ml")):
            try:
                extra_data = yaml.safe_load(yaml_file.read_text(encoding="utf-8")) or {}
            except (OSError, yaml.YAMLError):
                continue
            extra_sigs = extra_data.get("signatures", [])
            if isinstance(extra_sigs, list):
                sigs.extend(s for s in extra_sigs if isinstance(s, dict))

    # Pre-warm regex cache on load so per-match evaluation avoids recompiling
    for rule in sigs:
        for h_rule in rule.get("headers", []):
            _compile(str(h_rule.get("pattern", ".+")))
        for pat in rule.get("cookie_patterns", []):
            _compile(str(pat))
        for pat in rule.get("cnames", []):
            _compile(str(pat))
        if rule.get("tls_issuer_pattern"):
            _compile(str(rule["tls_issuer_pattern"]))
        if rule.get("meta_generator_pattern"):
            _compile(str(rule["meta_generator_pattern"]))

    return sigs


def _extract_cookie_names(headers: list[tuple[str, str]]) -> set[str]:
    names: set[str] = set()
    for key, val in headers:
        if key.lower() == "set-cookie" and "=" in val:
            cookie_name = val.split(";", 1)[0].split("=", 1)[0].strip()
            if cookie_name:
                names.add(cookie_name)
    return names


def _build_cpe(rule: dict[str, Any], version: str | None) -> str | None:
    cpe_vendor = str(rule.get("cpe_vendor") or "").strip().lower()
    cpe_product = str(rule.get("cpe_product") or "").strip().lower()
    if not cpe_vendor or not cpe_product or not version:
        return None
    clean_ver = re.sub(r"[^a-zA-Z0-9._-]", "", version.strip())
    if not clean_ver:
        return None
    return f"cpe:2.3:a:{cpe_vendor}:{cpe_product}:{clean_ver}:*:*:*:*:*:*:*"


def match_signatures(
    headers: list[tuple[str, str]],
    *,
    tls_issuer: str | None = None,
    cnames: Sequence[str] | None = None,
    html_analysis: HTMLPassiveAnalysis | dict[str, Any] | None = None,
    signatures: list[dict[str, Any]] | None = None,
) -> list[FingerprintMatch]:
    """Passively match headers, cookies, TLS issuer, CNAMEs, HTML hints, and JS libraries."""
    rules = signatures if signatures is not None else load_signatures()
    cookie_names = _extract_cookie_names(headers)
    cname_list = [str(c).strip().rstrip(".") for c in (cnames or []) if str(c).strip()]

    meta_gen: str | None = None
    html_hints: list[str] = []
    html_libs: list[str] = []
    if isinstance(html_analysis, HTMLPassiveAnalysis):
        meta_gen = html_analysis.meta_generator
        html_hints = list(html_analysis.framework_hints)
        html_libs = list(html_analysis.detected_libraries)
    elif isinstance(html_analysis, dict):
        raw_mg = html_analysis.get("meta_generator")
        meta_gen = str(raw_mg) if raw_mg else None
        raw_hints = html_analysis.get("framework_hints", [])
        if isinstance(raw_hints, list):
            html_hints = [str(h) for h in raw_hints if h]
        raw_libs = html_analysis.get("detected_libraries", [])
        if isinstance(raw_libs, list):
            html_libs = [str(lib) for lib in raw_libs if lib]

    lowered_headers: dict[str, list[str]] = {}
    for k, v in headers:
        lowered_headers.setdefault(k.lower(), []).append(v)

    matches: list[FingerprintMatch] = []
    for rule in rules:
        evidence: list[str] = []
        detected_version: str | None = None

        for h_rule in rule.get("headers", []):
            h_name = str(h_rule.get("name", "")).lower()
            pattern = _compile(str(h_rule.get("pattern", ".+")))
            for val in lowered_headers.get(h_name, []):
                matched = pattern.search(val)
                if matched:
                    evidence.append(f"header:{h_name}={val}")
                    if detected_version is None and matched.groups():
                        first_group = next((g for g in matched.groups() if g), None)
                        if first_group:
                            detected_version = first_group.strip()

        for cookie_name in rule.get("cookies", []):
            if str(cookie_name) in cookie_names:
                evidence.append(f"cookie:{cookie_name}")

        for cookie_pattern in rule.get("cookie_patterns", []):
            pat = _compile(str(cookie_pattern))
            for c_name in sorted(cookie_names):
                if pat.search(c_name):
                    evidence.append(f"cookie:{c_name}")

        issuer_pattern = rule.get("tls_issuer_pattern")
        if issuer_pattern and tls_issuer and _compile(str(issuer_pattern)).search(tls_issuer):
            evidence.append(f"tls_issuer:{tls_issuer}")

        for cname_pat in rule.get("cnames", []):
            c_re = _compile(str(cname_pat))
            for cname in cname_list:
                if c_re.search(cname):
                    evidence.append(f"cname:{cname}")

        mg_pattern = rule.get("meta_generator_pattern")
        if mg_pattern and meta_gen:
            mg_match = _compile(str(mg_pattern)).search(meta_gen)
            if mg_match:
                evidence.append(f"html_meta_generator:{meta_gen}")
                if detected_version is None and mg_match.groups():
                    first_group = next((g for g in mg_match.groups() if g), None)
                    if first_group:
                        detected_version = first_group.strip()

        for expected_hint in rule.get("html_hints", []):
            exp_low = str(expected_hint).lower()
            for obs in html_hints:
                obs_low = obs.lower()
                if obs_low == exp_low or obs_low.startswith(exp_low + ":"):
                    evidence.append(f"html_hint:{obs}")
                    if detected_version is None and ":" in obs:
                        detected_version = obs.split(":", 1)[1].strip() or None

        for expected_lib in rule.get("html_libraries", []):
            lib_low = str(expected_lib).lower()
            for obs_lib in html_libs:
                if "/" not in obs_lib:
                    continue
                obs_name, obs_ver = obs_lib.split("/", 1)
                if obs_name.lower() == lib_low:
                    evidence.append(f"html_library:{obs_lib}")
                    if detected_version is None and obs_ver.strip():
                        detected_version = obs_ver.strip()

        if evidence:
            base_conf = str(rule.get("confidence", "medium"))
            confidence = "high" if len(evidence) >= 2 else base_conf
            matches.append(
                FingerprintMatch(
                    vendor=str(rule.get("vendor", "Unknown")),
                    product=str(rule.get("product", "Unknown")),
                    category=str(rule.get("category", "unknown")),
                    confidence=confidence,
                    version=detected_version,
                    evidence=evidence,
                    cpe=_build_cpe(rule, detected_version),
                )
            )

    return matches
