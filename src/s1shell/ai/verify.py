"""Deterministic anti-hallucination citation & grounding verifier for AI analyses."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_GHSA_RE = re.compile(r"\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b", re.IGNORECASE)
_FINDING_ID_RE = re.compile(
    r"\b(?:TLS|HDR|DNS|COOKIE|CORS|DISC|HTML|WK|METH|TRANS|EOL|LEAK|OIDC|JWKS|INTEL)"
    r"-[A-Z0-9][A-Z0-9_-]{1,28}\b"
)


@dataclass(frozen=True)
class GroundingReport:
    """Local deterministic verification comparing cited Finding/CVE IDs against input telemetry."""

    verified_refs: list[str] = field(default_factory=list)
    ungrounded_refs: list[str] = field(default_factory=list)
    total_cited: int = 0
    grounding_score: float | None = None
    note: str = ""


def _harvest_ids_from_text(text: str) -> set[str]:
    found: set[str] = set()
    for m in _CVE_RE.findall(text):
        found.add(m.upper())
    for m in _GHSA_RE.findall(text):
        found.add(m.upper())
    for m in _FINDING_ID_RE.findall(text):
        found.add(m.upper())
    return found


def extract_known_references(artifacts: list[Any]) -> set[str]:
    """Recursively extract ground-truth Finding IDs, CVE IDs, and GHSA IDs from input artifacts."""
    known: set[str] = set()

    def _walk(obj: Any) -> None:
        if isinstance(obj, dict):
            for key, val in obj.items():
                low_k = str(key).lower()
                if low_k in {"id", "cve_id", "vuln_id", "ghsa_id"} and isinstance(val, str):
                    cleaned = val.strip().upper()
                    if cleaned and (
                        _CVE_RE.fullmatch(cleaned)
                        or _GHSA_RE.fullmatch(cleaned)
                        or _FINDING_ID_RE.fullmatch(cleaned)
                    ):
                        known.add(cleaned)
                _walk(val)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item)
        elif isinstance(obj, str):
            known.update(_harvest_ids_from_text(obj))

    for art in artifacts:
        _walk(art)
    return known


def verify_analysis_grounding(
    analysis_text: str,
    known_refs: set[str],
) -> GroundingReport:
    """Cross-check every Finding/CVE/GHSA ID cited by the LLM against ground-truth input refs."""
    cited = sorted(_harvest_ids_from_text(analysis_text))
    if not cited:
        return GroundingReport(
            verified_refs=[],
            ungrounded_refs=[],
            total_cited=0,
            grounding_score=1.0 if known_refs else None,
            note="No specific Finding/CVE IDs cited in AI output.",
        )

    known_up = {ref.upper() for ref in known_refs}
    verified = [ref for ref in cited if ref in known_up]
    ungrounded = [ref for ref in cited if ref not in known_up]
    score = round(len(verified) / len(cited), 3)

    if ungrounded:
        note = (
            f"Verified {len(verified)}/{len(cited)} cited ID(s); "
            f"{len(ungrounded)} ungrounded reference(s) not present in input artifacts "
            f"({', '.join(ungrounded[:5])})."
        )
    else:
        note = (
            f"All {len(verified)} cited Finding/CVE reference(s) verified against input telemetry."
        )

    return GroundingReport(
        verified_refs=verified,
        ungrounded_refs=ungrounded,
        total_cited=len(cited),
        grounding_score=score,
        note=note,
    )
