"""SARIF 2.1.0 serializer for S1shell defensive findings (GitHub/GitLab/DefectDojo ready)."""

from __future__ import annotations

import json
from typing import Any

from s1shell import __version__
from s1shell.config import DEFAULT_PROJECT_URL

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)

_SEV_TO_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

_SEV_TO_SCORE = {
    "CRITICAL": "9.5",
    "HIGH": "7.5",
    "MEDIUM": "5.0",
    "LOW": "2.5",
    "INFO": "0.0",
}


def build_sarif_payload(
    *,
    findings: list[dict[str, Any]],
    target_uri: str,
    tool_version: str = __version__,
    posture: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document dictionary from normalized finding dicts."""
    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in findings:
        rule_id = str(finding.get("id", "S1SHELL-FINDING"))
        severity = str(finding.get("severity", "INFO")).upper()
        category = str(finding.get("category", "posture"))
        title = str(finding.get("title", rule_id))
        evidence = str(finding.get("evidence", ""))
        remediation = str(finding.get("remediation", ""))
        cwe = finding.get("cwe")
        asvs = finding.get("asvs")

        if rule_id not in rules_by_id:
            tags = ["security", "defensive", category]
            if cwe:
                tags.append(f"external/cwe/{str(cwe).lower()}")
            if asvs:
                tags.append(f"owasp/asvs/{asvs}")
            rules_by_id[rule_id] = {
                "id": rule_id,
                "name": rule_id.replace("-", "_"),
                "shortDescription": {"text": title},
                "fullDescription": {"text": remediation or title},
                "help": {"text": remediation or title},
                "properties": {
                    "tags": tags,
                    "security-severity": _SEV_TO_SCORE.get(severity, "0.0"),
                    "category": category,
                },
            }

        msg = f"{title}. Evidence: {evidence}" if evidence else title
        res_entry: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _SEV_TO_LEVEL.get(severity, "note"),
            "message": {"text": msg},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": target_uri or "target://unknown"}
                    }
                }
            ],
            "properties": {
                "severity": severity,
                "category": category,
                "remediation": remediation,
            },
        }
        if cwe:
            res_entry["properties"]["cwe"] = str(cwe)
        if asvs:
            res_entry["properties"]["asvs"] = str(asvs)
        results.append(res_entry)

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "S1shell",
                "version": tool_version,
                "informationUri": DEFAULT_PROJECT_URL,
                "rules": list(rules_by_id.values()),
            }
        },
        "results": results,
    }
    if posture is not None:
        run["properties"] = {"posture": posture}

    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [run],
    }


def render_sarif(
    *,
    findings: list[dict[str, Any]],
    target_uri: str,
    tool_version: str = __version__,
    posture: dict[str, Any] | None = None,
) -> str:
    """Serialize findings into pretty-printed SARIF 2.1.0 JSON."""
    payload = build_sarif_payload(
        findings=findings,
        target_uri=target_uri,
        tool_version=tool_version,
        posture=posture,
    )
    return json.dumps(payload, indent=2)
