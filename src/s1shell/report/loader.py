"""Loads and validates canonical JSON artifacts for report compilation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from s1shell import __version__
from s1shell.errors import ValidationError
from s1shell.models import utc_now_iso
from s1shell.report.models import ReportBundle, ReportMetadata
from s1shell.scope import ScopeManager


def _read_artifact_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValidationError(f"Failed to read artifact '{path}': {exc}") from exc
    if not isinstance(data, dict) or "artifact_type" not in data:
        raise ValidationError(
            f"Artifact '{path}' must be a JSON object containing 'artifact_type'."
        )
    return data


def _validate_artifact_structure(data: dict[str, Any], path: Path) -> None:
    atype = data.get("artifact_type")
    if atype == "profile_report":
        if (
            not isinstance(data.get("url"), str)
            or not isinstance(data.get("protocol"), dict)
            or not isinstance(data.get("headers"), dict)
        ):
            raise ValidationError(
                f"Profile artifact '{path}' is missing required 'url', 'protocol', or 'headers'."
            )
    elif atype == "fingerprint_report":
        if not isinstance(data.get("matches"), list):
            raise ValidationError(
                f"Fingerprint artifact '{path}' is missing required 'matches' list."
            )
    elif atype == "cve_report" and not isinstance(data.get("records"), list):
        raise ValidationError(f"CVE artifact '{path}' is missing required 'records' list.")
    elif atype == "assess_report":
        if not isinstance(data.get("profile"), dict) or not isinstance(data.get("posture"), dict):
            raise ValidationError(
                f"Assessment artifact '{path}' is missing required 'profile' or 'posture'."
            )


def load_artifacts(
    *,
    inputs: list[Path] | None = None,
    profile_paths: list[Path] | None = None,
    fingerprint_paths: list[Path] | None = None,
    cve_paths: list[Path] | None = None,
    operator: str,
    scope_manager: ScopeManager | None = None,
) -> ReportBundle:
    """Load, validate, and group artifacts plus matching scope attribution records."""
    profiles: list[dict[str, Any]] = []
    fingerprints: list[dict[str, Any]] = []
    cves: list[dict[str, Any]] = []
    posture: dict[str, Any] | None = None
    findings: list[dict[str, Any]] = []
    ai_analysis: dict[str, Any] | None = None

    for path in inputs or []:
        data = _read_artifact_json(path)
        _validate_artifact_structure(data, path)
        atype = data.get("artifact_type")
        if atype == "profile_report":
            profiles.append(data)
        elif atype == "fingerprint_report":
            fingerprints.append(data)
        elif atype == "cve_report":
            cves.append(data)
        elif atype == "assess_report":
            if isinstance(data.get("profile"), dict):
                profiles.append(data["profile"])
            if isinstance(data.get("fingerprint"), dict):
                fingerprints.append(data["fingerprint"])
            if isinstance(data.get("cve"), dict):
                cves.append(data["cve"])
            if isinstance(data.get("posture"), dict):
                posture = data["posture"]
            if isinstance(data.get("findings"), list):
                findings.extend(f for f in data["findings"] if isinstance(f, dict))
            if isinstance(data.get("ai_analysis"), dict):
                ai_analysis = data["ai_analysis"]
        else:
            raise ValidationError(f"Unsupported artifact_type '{atype}' in '{path}'.")

    for path in profile_paths or []:
        data = _read_artifact_json(path)
        if data.get("artifact_type") != "profile_report":
            raise ValidationError(f"Expected 'profile_report' in '{path}'.")
        _validate_artifact_structure(data, path)
        profiles.append(data)

    for path in fingerprint_paths or []:
        data = _read_artifact_json(path)
        if data.get("artifact_type") != "fingerprint_report":
            raise ValidationError(f"Expected 'fingerprint_report' in '{path}'.")
        _validate_artifact_structure(data, path)
        fingerprints.append(data)

    for path in cve_paths or []:
        data = _read_artifact_json(path)
        if data.get("artifact_type") != "cve_report":
            raise ValidationError(f"Expected 'cve_report' in '{path}'.")
        _validate_artifact_structure(data, path)
        cves.append(data)

    if not (profiles or fingerprints or cves):
        raise ValidationError(
            "Provide at least one artifact (--input, --profile, --fingerprint, or --cve)."
        )

    referenced_scope_ids: set[str] = set()
    fallback_refs: dict[str, str] = {}
    for item in [*profiles, *fingerprints]:
        sid = str(item.get("scope_id", "")).strip()
        if sid:
            referenced_scope_ids.add(sid)
            if item.get("auth_ref"):
                fallback_refs[sid] = str(item["auth_ref"])

    scope_entries: list[dict[str, Any]] = []
    if scope_manager is not None and scope_manager.scope_file.exists():
        loaded_entries = {e.id: e.to_dict() for e in scope_manager.load()}
        for sid in sorted(referenced_scope_ids):
            if sid in loaded_entries:
                scope_entries.append(loaded_entries[sid])
            else:
                scope_entries.append({"id": sid, "auth_ref": fallback_refs.get(sid, "unknown")})
    else:
        for sid in sorted(referenced_scope_ids):
            scope_entries.append({"id": sid, "auth_ref": fallback_refs.get(sid, "unknown")})

    metadata = ReportMetadata(
        generated_at_utc=utc_now_iso(),
        operator=operator.strip() or "unknown",
        tool_version=__version__,
        scope_entries=scope_entries,
    )
    return ReportBundle(
        metadata=metadata,
        profiles=profiles,
        fingerprints=fingerprints,
        cves=cves,
        posture=posture,
        findings=findings,
        ai_analysis=ai_analysis,
        generated_at_utc=metadata.generated_at_utc,
    )
