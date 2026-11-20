"""Unit tests for report artifact loading and scope attribution."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from s1shell.config import RuntimeConfig
from s1shell.errors import ValidationError
from s1shell.report.loader import load_artifacts
from s1shell.scope import ScopeManager

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_load_artifacts_combines_profile_fingerprint_and_cve(
    tmp_config: RuntimeConfig, tmp_path: Path
) -> None:
    fp_path = tmp_path / "fp.json"
    fp_path.write_text(
        json.dumps(
            {
                "artifact_type": "fingerprint_report",
                "target": "https://app.example.com",
                "mode": "from_profile",
                "scope_id": "acme0001",
                "auth_ref": "SOW-2026-014",
                "matches": [
                    {
                        "vendor": "Cloudflare",
                        "product": "Cloudflare CDN/WAF",
                        "category": "cdn",
                        "confidence": "high",
                        "evidence": ["header:cf-ray=123"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    cve_path = tmp_path / "cve.json"
    cve_path.write_text(
        json.dumps(
            {
                "artifact_type": "cve_report",
                "records": [
                    {
                        "cve_id": "CVE-2021-23017",
                        "published": "2021-06-01T14:15:08",
                        "description": "DNS resolver issue",
                        "cvss": {"base_score": 8.1, "severity": "HIGH"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    mgr = ScopeManager(FIXTURES / "sample_scope.yaml")
    bundle = load_artifacts(
        inputs=[FIXTURES / "sample_profile.json", fp_path, cve_path],
        operator="Alice Security",
        scope_manager=mgr,
    )

    assert len(bundle.profiles) == 1
    assert len(bundle.fingerprints) == 1
    assert len(bundle.cves) == 1
    assert bundle.metadata.operator == "Alice Security"
    assert bundle.metadata.scope_entries[0]["id"] == "acme0001"
    assert bundle.metadata.scope_entries[0]["owner"] == "ACME IT"


def test_load_artifacts_rejects_empty_or_invalid_inputs(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        load_artifacts(operator="Alice")

    bad = tmp_path / "bad.json"
    bad.write_text("{}", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_artifacts(inputs=[bad], operator="Alice")

    incomplete = tmp_path / "incomplete_profile.json"
    incomplete.write_text(json.dumps({"artifact_type": "profile_report"}), encoding="utf-8")
    with pytest.raises(ValidationError, match="missing required"):
        load_artifacts(inputs=[incomplete], operator="Alice")
