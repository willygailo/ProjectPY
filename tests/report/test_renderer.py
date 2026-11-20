"""Unit tests for ReportService rendering (JSON, Markdown, XSS-safe HTML)."""

from __future__ import annotations

import json
from pathlib import Path

from s1shell.config import RuntimeConfig
from s1shell.report.service import ReportService
from s1shell.scope import ScopeManager

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_report_renderer_escapes_html_xss_and_has_no_external_assets(
    tmp_config: RuntimeConfig, tmp_path: Path
) -> None:
    prof = json.loads((FIXTURES / "sample_profile.json").read_text(encoding="utf-8"))
    prof["headers"]["banner_disclosures"].append(
        {"header": "Server", "value": "<script>alert(1)</script>"}
    )
    prof_path = tmp_path / "xss_profile.json"
    prof_path.write_text(json.dumps(prof), encoding="utf-8")

    svc = ReportService(tmp_config, scope_manager=ScopeManager(FIXTURES / "sample_scope.yaml"))
    bundle = svc.build_bundle(inputs=[prof_path], operator="Bob <admin>")

    html_out = svc.render(bundle, fmt="html")
    assert "<script>alert(1)</script>" not in html_out
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_out
    assert "&lt;admin&gt;" in html_out
    assert "<script src=" not in html_out
    assert "<link " not in html_out
    assert "<img " not in html_out
    assert "Executive Summary" in html_out
    assert "Set-Cookie Attributes" in html_out
    assert "__cf_bm" in html_out

    md_out = svc.render(bundle, fmt="md")
    assert "# S1shell Authorized Assessment Report" in md_out
    assert "## Executive Summary" in md_out
    assert "__cf_bm" in md_out
    assert "SOW-2026-014" in md_out

    json_out = svc.render(bundle, fmt="json")
    parsed = json.loads(json_out)
    assert parsed["artifact_type"] == "assessment_report"
