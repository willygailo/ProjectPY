"""Offline FIRST CVSS v3.0/v3.1 Base+Temporal+Environmental & CVSS v4.0 vector analyzer."""

from __future__ import annotations

from s1shell.analyze.models import CVSSAnalysisResult, CVSSMetricDetail
from s1shell.cve.cvss import calculate_cvss3_full, score_to_severity
from s1shell.errors import ValidationError

_V3_LABELS: dict[str, tuple[str, str, dict[str, str]]] = {
    "AV": (
        "base",
        "Attack Vector",
        {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    ),
    "AC": ("base", "Attack Complexity", {"L": "Low", "H": "High"}),
    "PR": ("base", "Privileges Required", {"N": "None", "L": "Low", "H": "High"}),
    "UI": ("base", "User Interaction", {"N": "None", "R": "Required"}),
    "S": ("base", "Scope", {"U": "Unchanged", "C": "Changed"}),
    "C": ("base", "Confidentiality", {"N": "None", "L": "Low", "H": "High"}),
    "I": ("base", "Integrity", {"N": "None", "L": "Low", "H": "High"}),
    "A": ("base", "Availability", {"N": "None", "L": "Low", "H": "High"}),
    "E": (
        "temporal",
        "Exploit Code Maturity",
        {
            "X": "Not Defined",
            "U": "Unproven",
            "P": "Proof-of-Concept",
            "F": "Functional",
            "H": "High",
        },
    ),
    "RL": (
        "temporal",
        "Remediation Level",
        {
            "X": "Not Defined",
            "O": "Official Fix",
            "T": "Temporary Fix",
            "W": "Workaround",
            "U": "Unavailable",
        },
    ),
    "RC": (
        "temporal",
        "Report Confidence",
        {"X": "Not Defined", "U": "Unknown", "R": "Reasonable", "C": "Confirmed"},
    ),
    "CR": (
        "environmental",
        "Confidentiality Requirement",
        {"X": "Not Defined", "L": "Low", "M": "Medium", "H": "High"},
    ),
    "IR": (
        "environmental",
        "Integrity Requirement",
        {"X": "Not Defined", "L": "Low", "M": "Medium", "H": "High"},
    ),
    "AR": (
        "environmental",
        "Availability Requirement",
        {"X": "Not Defined", "L": "Low", "M": "Medium", "H": "High"},
    ),
    "MAV": (
        "environmental",
        "Modified Attack Vector",
        {"X": "Not Defined", "N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    ),
    "MAC": (
        "environmental",
        "Modified Attack Complexity",
        {"X": "Not Defined", "L": "Low", "H": "High"},
    ),
    "MPR": (
        "environmental",
        "Modified Privileges Required",
        {"X": "Not Defined", "N": "None", "L": "Low", "H": "High"},
    ),
    "MUI": (
        "environmental",
        "Modified User Interaction",
        {"X": "Not Defined", "N": "None", "R": "Required"},
    ),
    "MS": (
        "environmental",
        "Modified Scope",
        {"X": "Not Defined", "U": "Unchanged", "C": "Changed"},
    ),
    "MC": (
        "environmental",
        "Modified Confidentiality",
        {"X": "Not Defined", "N": "None", "L": "Low", "H": "High"},
    ),
    "MI": (
        "environmental",
        "Modified Integrity",
        {"X": "Not Defined", "N": "None", "L": "Low", "H": "High"},
    ),
    "MA": (
        "environmental",
        "Modified Availability",
        {"X": "Not Defined", "N": "None", "L": "Low", "H": "High"},
    ),
}

_V4_LABELS: dict[str, tuple[str, str, dict[str, str]]] = {
    "AV": (
        "base",
        "Attack Vector",
        {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    ),
    "AC": ("base", "Attack Complexity", {"L": "Low", "H": "High"}),
    "AT": ("base", "Attack Requirements", {"N": "None", "P": "Present"}),
    "PR": ("base", "Privileges Required", {"N": "None", "L": "Low", "H": "High"}),
    "UI": ("base", "User Interaction", {"N": "None", "P": "Passive", "A": "Active"}),
    "VC": ("base", "Vulnerable System Confidentiality", {"H": "High", "L": "Low", "N": "None"}),
    "VI": ("base", "Vulnerable System Integrity", {"H": "High", "L": "Low", "N": "None"}),
    "VA": ("base", "Vulnerable System Availability", {"H": "High", "L": "Low", "N": "None"}),
    "SC": ("base", "Subsequent System Confidentiality", {"H": "High", "L": "Low", "N": "None"}),
    "SI": ("base", "Subsequent System Integrity", {"H": "High", "L": "Low", "N": "None"}),
    "SA": ("base", "Subsequent System Availability", {"H": "High", "L": "Low", "N": "None"}),
    "E": (
        "temporal",
        "Exploit Maturity",
        {"X": "Not Defined", "A": "Attacked", "P": "POC", "U": "Unreported"},
    ),
}


def analyze_cvss_vector(vector: str) -> CVSSAnalysisResult:
    """Validate, explain, and score a CVSS v3.0, v3.1, or v4.0 vector string offline."""
    cleaned = vector.strip().upper()
    if not cleaned:
        raise ValidationError("CVSS vector cannot be empty.")

    if cleaned.startswith(("CVSS:3.1/", "CVSS:3.0/")):
        version = cleaned.split("/", 1)[0].split(":", 1)[1]
        scored = calculate_cvss3_full(cleaned)
        if scored is None:
            raise ValidationError(
                f"Invalid CVSS v{version} vector '{vector}'. Must include AV, AC, PR, UI, S, C, I, "
                "A."
            )
        details: list[CVSSMetricDetail] = []
        notes: list[str] = []
        for part in cleaned.split("/")[1:]:
            if ":" not in part:
                continue
            k, v = part.split(":", 1)
            meta = _V3_LABELS.get(k)
            if meta is None:
                notes.append(f"Unrecognized metric `{k}:{v}` ignored.")
                continue
            grp, name, val_map = meta
            details.append(
                CVSSMetricDetail(
                    group=grp,
                    metric=k,
                    name=name,
                    code=v,
                    value_label=val_map.get(v, v),
                )
            )
        if scored.base_score >= 9.0:
            notes.append(
                "Critical CVSS base score (>= 9.0): prioritize immediate patch or compensating "
                "control."
            )
        elif scored.base_score >= 7.0:
            notes.append(
                "High CVSS base score (7.0-8.9): combine with CISA KEV and EPSS for SSVC triage."
            )
        return CVSSAnalysisResult(
            vector=cleaned,
            version=version,
            base_score=scored.base_score,
            base_severity=scored.base_severity,
            temporal_score=scored.temporal_score,
            temporal_severity=score_to_severity(scored.temporal_score)
            if scored.temporal_score is not None
            else None,
            environmental_score=scored.environmental_score,
            environmental_severity=(
                score_to_severity(scored.environmental_score)
                if scored.environmental_score is not None
                else None
            ),
            exploitability_subscore=scored.exploitability_subscore,
            impact_subscore=scored.impact_subscore,
            metrics=details,
            notes=notes,
        )

    if cleaned.startswith("CVSS:4.0/"):
        parts = cleaned.split("/")[1:]
        seen_keys: dict[str, str] = {}
        details = []
        notes = []
        for part in parts:
            if ":" not in part:
                continue
            k, v = part.split(":", 1)
            seen_keys[k] = v
            meta = _V4_LABELS.get(k)
            if meta is not None:
                grp, name, val_map = meta
                details.append(
                    CVSSMetricDetail(
                        group=grp,
                        metric=k,
                        name=name,
                        code=v,
                        value_label=val_map.get(v, v),
                    )
                )
            else:
                details.append(
                    CVSSMetricDetail(group="supplemental", metric=k, name=k, code=v, value_label=v)
                )
        req_v4 = {"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"}
        missing = sorted(req_v4 - set(seen_keys))
        if missing:
            raise ValidationError(
                f"Incomplete CVSS v4.0 vector: missing mandatory base metrics {', '.join(missing)}."
            )
        notes.append(
            "CVSS v4.0 vector structure validated and decoded; numeric CVSS v4.0 MacroVector "
            "interpolation is not approximated here — use FIRST's official v4.0 calculator for "
            "exact numeric score."
        )
        return CVSSAnalysisResult(
            vector=cleaned,
            version="4.0",
            base_score=None,
            base_severity=None,
            metrics=details,
            notes=notes,
        )

    raise ValidationError(
        f"Unsupported CVSS vector '{vector}'. Expected prefix `CVSS:3.1/`, `CVSS:3.0/`, or "
        "`CVSS:4.0/`."
    )
