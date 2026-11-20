"""Pure-Python FIRST CVSS v3.0 / v3.1 base score calculator for OSV and CVE vectors."""

from __future__ import annotations

import math

_AV_WEIGHTS: dict[str, float] = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC_WEIGHTS: dict[str, float] = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED: dict[str, float] = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED: dict[str, float] = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI_WEIGHTS: dict[str, float] = {"N": 0.85, "R": 0.62}
_CIA_WEIGHTS: dict[str, float] = {"N": 0.00, "L": 0.22, "H": 0.56}


def _roundup_cvss31(value: float) -> float:
    """FIRST CVSS v3.1 Appendix A deterministic Roundup function."""
    int_input = round(value * 100_000)
    if (int_input % 10_000) == 0:
        return int_input / 100_000.0
    return (math.floor(int_input / 10_000) + 1) / 10.0


def score_to_severity(score: float) -> str:
    """Map a numeric CVSS base score (`0.0–10.0`) to S1shell severity level."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFO"


def calculate_cvss3_base_score(vector: str) -> tuple[float, str] | None:
    """Compute `(base_score, severity)` from a `CVSS:3.0/...` or `CVSS:3.1/...` vector string."""
    cleaned = vector.strip().upper()
    if not cleaned.startswith(("CVSS:3.1/", "CVSS:3.0/")):
        return None

    metrics: dict[str, str] = {}
    for part in cleaned.split("/")[1:]:
        if ":" not in part:
            continue
        key, val = part.split(":", 1)
        metrics[key.strip()] = val.strip()

    try:
        av = _AV_WEIGHTS[metrics["AV"]]
        ac = _AC_WEIGHTS[metrics["AC"]]
        scope = metrics["S"]
        if scope not in {"U", "C"}:
            return None
        pr = (_PR_CHANGED if scope == "C" else _PR_UNCHANGED)[metrics["PR"]]
        ui = _UI_WEIGHTS[metrics["UI"]]
        conf = _CIA_WEIGHTS[metrics["C"]]
        integ = _CIA_WEIGHTS[metrics["I"]]
        avail = _CIA_WEIGHTS[metrics["A"]]
    except KeyError:
        return None

    iss = 1.0 - ((1.0 - conf) * (1.0 - integ) * (1.0 - avail))
    impact = 6.42 * iss if scope == "U" else 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0.0:
        base_score = 0.0
    elif scope == "U":
        base_score = _roundup_cvss31(min(impact + exploitability, 10.0))
    else:
        base_score = _roundup_cvss31(min(1.08 * (impact + exploitability), 10.0))

    return base_score, score_to_severity(base_score)
