"""Offline End-of-Life (EOL) software version checker for passive fingerprints."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from typing import Any

import yaml

_NUM_PARTS_RE = re.compile(r"\d+")


@dataclass(frozen=True)
class EOLStatus:
    """Offline EOL evaluation for a fingerprinted product and version."""

    product: str
    detected_version: str
    min_supported: str
    is_eol: bool
    note: str
    recommended: str


def _parse_version_tuple(version: str) -> tuple[int, ...] | None:
    parts = [int(tok) for tok in _NUM_PARTS_RE.findall(version)]
    if not parts:
        return None
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:4])


@lru_cache(maxsize=1)
def load_eol_rules() -> dict[str, dict[str, Any]]:
    """Load bundled offline `eol.yaml` product baselines keyed by lowercase product name."""
    raw = resources.files("s1shell.fingerprint").joinpath("eol.yaml").read_text(encoding="utf-8")
    doc = yaml.safe_load(raw) or {}
    out: dict[str, dict[str, Any]] = {}
    if isinstance(doc, dict):
        for entry in doc.get("products", []) or []:
            if isinstance(entry, dict) and entry.get("product"):
                out[str(entry["product"]).strip().lower()] = entry
    return out


def check_product_eol(product: str, version: str | None) -> EOLStatus | None:
    """Check whether `(product, version)` falls below the bundled offline EOL baseline."""
    if not version or not version.strip():
        return None
    rule = load_eol_rules().get(product.strip().lower())
    if rule is None:
        return None
    min_sup = str(rule.get("min_supported") or "").strip()
    det_tuple = _parse_version_tuple(version)
    min_tuple = _parse_version_tuple(min_sup)
    if det_tuple is None or min_tuple is None:
        return None
    is_eol = det_tuple < min_tuple
    if not is_eol:
        return None
    return EOLStatus(
        product=str(rule["product"]),
        detected_version=version.strip(),
        min_supported=min_sup,
        is_eol=True,
        note=str(rule.get("note") or f"{product} {version} is End-of-Life."),
        recommended=str(
            rule.get("recommended") or f"Upgrade {product} to a supported release (>= {min_sup})."
        ),
    )
