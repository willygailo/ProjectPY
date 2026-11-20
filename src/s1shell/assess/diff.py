"""Posture drift detection comparing baseline vs current S1shell assessment artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from s1shell.assess.models import AssessmentDiffResult
from s1shell.errors import ValidationError


def _load_assess_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValidationError(f"Failed to read assessment artifact '{path}': {exc}") from exc
    if not isinstance(data, dict) or data.get("artifact_type") != "assess_report":
        raise ValidationError(
            f"File '{path}' is not a valid s1shell `assess_report` JSON artifact."
        )
    return data


def _extract_finding_map(data: dict[str, Any]) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for item in data.get("findings", []):
        if isinstance(item, dict) and item.get("id"):
            fid = str(item["id"])
            out[fid] = {
                "id": fid,
                "severity": str(item.get("severity", "INFO")),
                "category": str(item.get("category", "")),
                "title": str(item.get("title", "")),
            }
    return out


def _extract_cve_ids(data: dict[str, Any]) -> set[str]:
    cve_blk = data.get("cve")
    if not isinstance(cve_blk, dict):
        return set()
    return {
        str(r["cve_id"])
        for r in cve_blk.get("records", [])
        if isinstance(r, dict) and r.get("cve_id")
    }


def _extract_stack_labels(data: dict[str, Any]) -> set[str]:
    fp_blk = data.get("fingerprint")
    if not isinstance(fp_blk, dict):
        return set()
    labels: set[str] = set()
    for m in fp_blk.get("matches", []):
        if isinstance(m, dict) and m.get("product"):
            ver = str(m.get("version") or "").strip()
            labels.add(f"{m['product']} {ver}".strip())
    return labels


def _extract_cert_days(data: dict[str, Any]) -> int | None:
    prof = data.get("profile")
    if not isinstance(prof, dict):
        return None
    tls = prof.get("tls")
    if not isinstance(tls, dict):
        return None
    days = tls.get("days_remaining")
    return int(days) if isinstance(days, int) else None


def diff_assessments(baseline_path: Path, current_path: Path) -> AssessmentDiffResult:
    """Compare two saved `assess.json` artifacts and report posture drift."""
    base = _load_assess_json(baseline_path)
    curr = _load_assess_json(current_path)

    base_posture = base.get("posture", {}) if isinstance(base.get("posture"), dict) else {}
    curr_posture = curr.get("posture", {}) if isinstance(curr.get("posture"), dict) else {}

    score_before = int(base_posture.get("score", 0))
    score_after = int(curr_posture.get("score", 0))
    score_delta = score_after - score_before

    base_findings = _extract_finding_map(base)
    curr_findings = _extract_finding_map(curr)

    new_ids = sorted(set(curr_findings) - set(base_findings))
    resolved_ids = sorted(set(base_findings) - set(curr_findings))
    persisting_count = len(set(base_findings) & set(curr_findings))

    base_cves = _extract_cve_ids(base)
    curr_cves = _extract_cve_ids(curr)
    new_cves = sorted(curr_cves - base_cves)
    resolved_cves = sorted(base_cves - curr_cves)

    base_stack = _extract_stack_labels(base)
    curr_stack = _extract_stack_labels(curr)

    days_before = _extract_cert_days(base)
    days_after = _extract_cert_days(curr)
    cert_delta = (
        days_after - days_before
        if days_before is not None and days_after is not None
        else None
    )

    new_high_crit = any(
        curr_findings[fid]["severity"] in {"CRITICAL", "HIGH"} for fid in new_ids
    )
    regressed = score_delta < 0 or new_high_crit or bool(new_cves)

    return AssessmentDiffResult(
        baseline_path=str(baseline_path),
        current_path=str(current_path),
        baseline_url=str(base.get("url", "")),
        current_url=str(curr.get("url", "")),
        score_before=score_before,
        score_after=score_after,
        score_delta=score_delta,
        grade_before=str(base_posture.get("grade", "—")),
        grade_after=str(curr_posture.get("grade", "—")),
        risk_before=str(base_posture.get("risk_level", "—")),
        risk_after=str(curr_posture.get("risk_level", "—")),
        cert_days_delta=cert_delta,
        new_findings=[curr_findings[fid] for fid in new_ids],
        resolved_findings=[base_findings[fid] for fid in resolved_ids],
        persisting_count=persisting_count,
        new_cves=new_cves,
        resolved_cves=resolved_cves,
        stack_added=sorted(curr_stack - base_stack),
        stack_removed=sorted(base_stack - curr_stack),
        regressed=regressed,
    )
