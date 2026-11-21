"""Service orchestrator for `s1shell analyze` (CSP3, Email Auth, Offline Headers, CVSS)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from s1shell.analyze.csp import analyze_csp, extract_csp_from_artifact
from s1shell.analyze.cvss_tool import analyze_cvss_vector
from s1shell.analyze.email_auth import analyze_email_auth
from s1shell.analyze.headers import analyze_raw_headers
from s1shell.analyze.models import (
    CSPAnalysisResult,
    CVSSAnalysisResult,
    EmailAuthAnalysisResult,
    HeaderOfflineResult,
)
from s1shell.config import RuntimeConfig
from s1shell.errors import ValidationError
from s1shell.profile.dns_check import RecordResolver


class AnalyzeService:
    """Offline and passive DNS security analyzer service."""

    def __init__(self, cfg: RuntimeConfig | None = None) -> None:
        self.cfg = cfg if cfg is not None else RuntimeConfig.load()

    def csp(
        self,
        *,
        policy: str | None = None,
        file_path: Path | None = None,
    ) -> CSPAnalysisResult:
        """Evaluate a Content-Security-Policy string or saved profile/assess artifact."""
        if file_path is not None:
            extracted, src = extract_csp_from_artifact(file_path)
            return analyze_csp(extracted, source=src)
        if policy and policy.strip():
            return analyze_csp(policy, source="inline")
        raise ValidationError("Provide a CSP string or `--file / --from-profile PATH`.")

    def email(
        self,
        domain: str,
        *,
        spf_record: str | None = None,
        dmarc_record: str | None = None,
        dkim_record: str | None = None,
        dkim_selector: str | None = None,
        offline: bool = False,
        resolver_factory: Callable[[], RecordResolver] | None = None,
    ) -> EmailAuthAnalysisResult:
        """Audit SPF, DMARC, DKIM, MTA-STS, TLS-RPT, and BIMI records."""
        return analyze_email_auth(
            domain,
            spf_record=spf_record,
            dmarc_record=dmarc_record,
            dkim_record=dkim_record,
            dkim_selector=dkim_selector,
            offline=offline,
            timeout=self.cfg.timeout_seconds,
            resolver_factory=resolver_factory,
        )

    def headers(
        self,
        *,
        raw_text: str | None = None,
        file_path: Path | None = None,
        url: str = "https://offline.local/",
        preset: str = "web",
    ) -> HeaderOfflineResult:
        """Audit pasted or saved HTTP response headers completely offline."""
        if file_path is not None:
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                raise ValidationError(f"Failed to read headers file '{file_path}': {exc}") from exc
            return analyze_raw_headers(content, url=url, preset=preset, source=str(file_path))
        if raw_text and raw_text.strip():
            return analyze_raw_headers(raw_text, url=url, preset=preset, source="inline")
        raise ValidationError("Provide raw HTTP headers via `--file PATH` or stdin.")

    def cvss(self, vector: str) -> CVSSAnalysisResult:
        """Score and decode a CVSS v3.0, v3.1, or v4.0 vector string offline."""
        return analyze_cvss_vector(vector)
