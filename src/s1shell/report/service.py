"""Report rendering service producing JSON, Markdown, SARIF 2.1.0, or XSS-safe HTML."""

from __future__ import annotations

import getpass
from pathlib import Path

from jinja2 import Environment, PackageLoader

from s1shell.config import RuntimeConfig
from s1shell.errors import ValidationError
from s1shell.models import dumps_json
from s1shell.report.loader import load_artifacts
from s1shell.report.models import ReportBundle
from s1shell.report.sarif import render_sarif
from s1shell.scope import ScopeManager


def _md_cell(value: object) -> str:
    if value is None:
        return "—"
    text = str(value).strip()
    if not text:
        return "—"
    return text.replace("\r\n", " ").replace("\n", " ").replace("|", "\\|")


def _build_summary(bundle: ReportBundle) -> dict[str, int]:
    missing_headers = 0
    weak_headers = 0
    insecure_cookies = 0
    tls_warnings = 0

    for prof in bundle.profiles:
        headers_blk = prof.get("headers", {}) if isinstance(prof, dict) else {}
        for h in headers_blk.get("security_headers", []):
            status = str(h.get("status", ""))
            if status == "missing":
                missing_headers += 1
            elif status == "weak":
                weak_headers += 1
        for c in headers_blk.get("cookies", []):
            if not c.get("secure") or not c.get("http_only") or not c.get("same_site"):
                insecure_cookies += 1
        tls_blk = prof.get("tls") if isinstance(prof, dict) else None
        if isinstance(tls_blk, dict) and tls_blk.get("applicable"):
            days = tls_blk.get("days_remaining")
            sup = tls_blk.get("supported_versions", [])
            if (
                not tls_blk.get("verified", True)
                or (isinstance(days, int) and days <= 30)
                or any(v in {"TLSv1", "TLSv1.1"} for v in sup)
                or bool(tls_blk.get("cipher_weaknesses"))
            ):
                tls_warnings += 1

    fp_matches = sum(
        len(fp.get("matches", [])) for fp in bundle.fingerprints if isinstance(fp, dict)
    )
    cve_total = 0
    high_critical_cves = 0
    kev_cves = 0
    for cve_blk in bundle.cves:
        if not isinstance(cve_blk, dict):
            continue
        for rec in cve_blk.get("records", []):
            cve_total += 1
            if rec.get("in_kev"):
                kev_cves += 1
            cvss = rec.get("cvss")
            if isinstance(cvss, dict) and str(cvss.get("severity", "")).upper() in {
                "HIGH",
                "CRITICAL",
            }:
                high_critical_cves += 1

    return {
        "profiles": len(bundle.profiles),
        "missing_headers": missing_headers,
        "weak_headers": weak_headers,
        "insecure_cookies": insecure_cookies,
        "tls_warnings": tls_warnings,
        "fingerprint_matches": fp_matches,
        "cve_total": cve_total,
        "high_critical_cves": high_critical_cves,
        "kev_cves": kev_cves,
        "findings_total": len(bundle.findings),
    }


class ReportService:
    """Compiles artifacts into unified JSON, Markdown, SARIF, or self-contained HTML reports."""

    def __init__(self, cfg: RuntimeConfig, *, scope_manager: ScopeManager | None = None) -> None:
        self.cfg = cfg
        self.scope_manager = (
            scope_manager if scope_manager is not None else ScopeManager(cfg.scope_file)
        )
        self._html_env = Environment(
            loader=PackageLoader("s1shell.report", "templates"),
            autoescape=True,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        # Markdown text output should not HTML-escape quotes/apostrophes, though HTML uses html_env.
        self._md_env = Environment(
            loader=PackageLoader("s1shell.report", "templates"),
            autoescape=False,  # noqa: S701
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self._md_env.filters["md_cell"] = _md_cell

    def build_bundle(
        self,
        *,
        inputs: list[Path] | None = None,
        profile_paths: list[Path] | None = None,
        fingerprint_paths: list[Path] | None = None,
        cve_paths: list[Path] | None = None,
        operator: str | None = None,
    ) -> ReportBundle:
        """Load and validate input JSON files into a ReportBundle."""
        resolved_operator = operator or getpass.getuser() or "unknown"
        return load_artifacts(
            inputs=inputs,
            profile_paths=profile_paths,
            fingerprint_paths=fingerprint_paths,
            cve_paths=cve_paths,
            operator=resolved_operator,
            scope_manager=self.scope_manager,
        )

    def render_batch_html(self, batch: object, *, operator: str | None = None) -> str:
        """Render a self-contained autoescaped HTML dashboard for a batch assessment."""
        resolved_operator = (operator or getpass.getuser() or "unknown").strip() or "unknown"
        template = self._html_env.get_template("batch_report.html.j2")
        return template.render(batch=batch, operator=resolved_operator)

    def render(self, bundle: ReportBundle, *, fmt: str) -> str:
        """Render a ReportBundle in `json`, `md`, `html`, or `sarif` format."""
        norm_fmt = fmt.lower()
        summary = _build_summary(bundle)
        if norm_fmt == "json":
            return dumps_json(bundle)
        if norm_fmt == "sarif":
            target_uri = (
                str(bundle.profiles[0].get("url", "target://unknown"))
                if bundle.profiles and isinstance(bundle.profiles[0], dict)
                else "target://unknown"
            )
            return render_sarif(
                findings=bundle.findings,
                target_uri=target_uri,
                tool_version=bundle.metadata.tool_version,
                posture=bundle.posture,
            )
        if norm_fmt == "md":
            template = self._md_env.get_template("report.md.j2")
            return template.render(bundle=bundle, summary=summary)
        if norm_fmt == "html":
            template = self._html_env.get_template("report.html.j2")
            return template.render(bundle=bundle, summary=summary)
        raise ValidationError(
            f"Unsupported report format '{fmt}'. Choose json, md, html, or sarif."
        )
