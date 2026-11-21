"""Pure-Python FIRST CVSS v3.0 / v3.1 Base, Temporal & Environmental score calculator."""

from __future__ import annotations

import math
from dataclasses import dataclass

_AV_WEIGHTS: dict[str, float] = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC_WEIGHTS: dict[str, float] = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED: dict[str, float] = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED: dict[str, float] = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI_WEIGHTS: dict[str, float] = {"N": 0.85, "R": 0.62}
_CIA_WEIGHTS: dict[str, float] = {"N": 0.00, "L": 0.22, "H": 0.56}

_E_WEIGHTS: dict[str, float] = {"X": 1.00, "U": 0.91, "P": 0.94, "F": 0.97, "H": 1.00}
_RL_WEIGHTS: dict[str, float] = {"X": 1.00, "O": 0.95, "T": 0.96, "W": 0.97, "U": 1.00}
_RC_WEIGHTS: dict[str, float] = {"X": 1.00, "U": 0.92, "R": 0.96, "C": 1.00}
_REQ_WEIGHTS: dict[str, float] = {"X": 1.00, "L": 0.50, "M": 1.00, "H": 1.50}


@dataclass(frozen=True)
class CVSS3FullScore:
    """Complete FIRST CVSS v3.0/v3.1 base, sub-score, temporal, and environmental breakdown."""

    base_score: float
    base_severity: str
    exploitability_subscore: float
    impact_subscore: float
    temporal_score: float | None = None
    environmental_score: float | None = None


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


def calculate_cvss3_full(vector: str) -> CVSS3FullScore | None:
    """Compute FIRST CVSS v3.0/v3.1 Base, Temporal, Environmental, and sub-scores."""
    cleaned = vector.strip().upper()
    if not cleaned.startswith(("CVSS:3.1/", "CVSS:3.0/")):
        return None
    is_v31 = cleaned.startswith("CVSS:3.1/")

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

    # Temporal score (if any temporal metric supplied)
    has_temp = any(k in metrics for k in ("E", "RL", "RC"))
    e_w = _E_WEIGHTS.get(metrics.get("E", "X"), 1.0)
    rl_w = _RL_WEIGHTS.get(metrics.get("RL", "X"), 1.0)
    rc_w = _RC_WEIGHTS.get(metrics.get("RC", "X"), 1.0)
    temporal_score: float | None = (
        _roundup_cvss31(base_score * e_w * rl_w * rc_w) if has_temp else None
    )

    # Environmental score (if any environmental metric supplied)
    env_keys = ("CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA")
    has_env = any(k in metrics for k in env_keys)
    env_score: float | None = None
    if has_env:
        try:
            m_scope = metrics.get("MS", "X")
            eff_scope = scope if m_scope == "X" else m_scope
            if eff_scope not in {"U", "C"}:
                return None
            m_av = av if metrics.get("MAV", "X") == "X" else _AV_WEIGHTS[metrics["MAV"]]
            m_ac = ac if metrics.get("MAC", "X") == "X" else _AC_WEIGHTS[metrics["MAC"]]
            m_pr_code = metrics["PR"] if metrics.get("MPR", "X") == "X" else metrics["MPR"]
            m_pr = (_PR_CHANGED if eff_scope == "C" else _PR_UNCHANGED)[m_pr_code]
            m_ui = ui if metrics.get("MUI", "X") == "X" else _UI_WEIGHTS[metrics["MUI"]]
            m_c = conf if metrics.get("MC", "X") == "X" else _CIA_WEIGHTS[metrics["MC"]]
            m_i = integ if metrics.get("MI", "X") == "X" else _CIA_WEIGHTS[metrics["MI"]]
            m_a = avail if metrics.get("MA", "X") == "X" else _CIA_WEIGHTS[metrics["MA"]]
            cr = _REQ_WEIGHTS[metrics.get("CR", "X")]
            ir = _REQ_WEIGHTS[metrics.get("IR", "X")]
            ar = _REQ_WEIGHTS[metrics.get("AR", "X")]
        except KeyError:
            return None

        miss = min(1.0 - ((1.0 - cr * m_c) * (1.0 - ir * m_i) * (1.0 - ar * m_a)), 0.915)
        if eff_scope == "U":
            mod_impact = 6.42 * miss
        elif is_v31:
            mod_impact = 7.52 * (miss - 0.029) - 3.25 * ((miss * 0.9731 - 0.02) ** 13)
        else:
            mod_impact = 7.52 * (miss - 0.029) - 3.25 * ((miss - 0.02) ** 15)
        mod_exp = 8.22 * m_av * m_ac * m_pr * m_ui
        if mod_impact <= 0.0:
            env_score = 0.0
        elif eff_scope == "U":
            env_score = _roundup_cvss31(
                _roundup_cvss31(min(mod_impact + mod_exp, 10.0)) * e_w * rl_w * rc_w
            )
        else:
            env_score = _roundup_cvss31(
                _roundup_cvss31(min(1.08 * (mod_impact + mod_exp), 10.0)) * e_w * rl_w * rc_w
            )

    return CVSS3FullScore(
        base_score=base_score,
        base_severity=score_to_severity(base_score),
        exploitability_subscore=round(exploitability, 1),
        impact_subscore=round(max(impact, 0.0), 1),
        temporal_score=temporal_score,
        environmental_score=env_score,
    )


def calculate_cvss3_base_score(vector: str) -> tuple[float, str] | None:
    """Compute `(base_score, severity)` from a `CVSS:3.0/...` or `CVSS:3.1/...` vector string."""
    full = calculate_cvss3_full(vector)
    if full is None:
        return None
    return full.base_score, full.base_severity
