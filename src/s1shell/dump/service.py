"""Authorized target evidence & surface artifact dump orchestrator (`s1shell dump`)."""

from __future__ import annotations

import time
from pathlib import Path

from s1shell.analyze.csp import analyze_csp
from s1shell.analyze.email_auth import analyze_email_auth
from s1shell.analyze.models import CSPAnalysisResult, EmailAuthAnalysisResult
from s1shell.assess.service import AssessService, _slugify_target
from s1shell.audit import AuditEvent, AuditLogger
from s1shell.config import RuntimeConfig
from s1shell.cve.service import CVEService
from s1shell.dump.exporter import export_evidence_bundle
from s1shell.dump.models import DumpResult
from s1shell.errors import ExitCode, S1ShellError
from s1shell.intel.models import CTLookupResult
from s1shell.intel.service import IntelService
from s1shell.profile.models import ProfileResult
from s1shell.profile.service import ProfileService, RawCaptureBundle
from s1shell.report.service import ReportService
from s1shell.scope import ScopeManager, parse_target
from s1shell.tor import is_v3_onion_host


def extract_csp_from_profile(profile: ProfileResult) -> str | None:
    """Return the first Content-Security-Policy header or meta CSP from a ProfileResult."""
    for name, value in profile.raw_headers:
        if name.lower() == "content-security-policy" and value.strip():
            return value.strip()
    if profile.html is not None and profile.html.meta_csp:
        return profile.html.meta_csp.strip()
    return None


def run_offline_deep_analyzers(
    profile: ProfileResult,
) -> tuple[CSPAnalysisResult | None, EmailAuthAnalysisResult | None, list[str]]:
    """Run zero-extra-packet CSP3 and offline Email Auth analyzers on observed telemetry."""
    warnings: list[str] = []
    csp_res: CSPAnalysisResult | None = None
    email_res: EmailAuthAnalysisResult | None = None

    csp_raw = extract_csp_from_profile(profile)
    if csp_raw:
        try:
            csp_res = analyze_csp(csp_raw, source=profile.url)
        except S1ShellError as exc:
            warnings.append(f"csp_analysis: {exc}")

    parsed = parse_target(profile.url)
    if (
        not parsed.is_ip
        and not is_v3_onion_host(parsed.host)
        and (profile.dns.spf or profile.dns.dmarc or profile.dns.security_checked)
    ):
        domain = profile.dns.apex_domain or parsed.host
        try:
            email_res = analyze_email_auth(
                domain,
                spf_record=profile.dns.spf,
                dmarc_record=profile.dns.dmarc,
                offline=True,
            )
        except S1ShellError as exc:
            warnings.append(f"email_auth: {exc}")

    return csp_res, email_res, warnings


class DumpService:
    """Executes fail-closed, scope-gated read-only target capture and evidence bundle export."""

    def __init__(
        self,
        cfg: RuntimeConfig,
        *,
        scope_manager: ScopeManager | None = None,
        audit_logger: AuditLogger | None = None,
        profile_service: ProfileService | None = None,
        assess_service: AssessService | None = None,
        cve_service: CVEService | None = None,
        intel_service: IntelService | None = None,
        report_service: ReportService | None = None,
    ) -> None:
        self.cfg = cfg
        self.scope_manager = (
            scope_manager
            if scope_manager is not None
            else ScopeManager(
                cfg.scope_file,
                tor_enabled=cfg.tor_enabled,
                tor_targets=cfg.tor_targets,
                tor_proxy=cfg.tor_proxy,
                tor_doh_url=cfg.tor_doh_url,
            )
        )
        self.audit_logger = audit_logger if audit_logger is not None else AuditLogger(cfg.audit_log)
        self.intel_service = (
            intel_service
            if intel_service is not None
            else IntelService(cfg, audit_logger=self.audit_logger)
        )
        self.report_service = (
            report_service
            if report_service is not None
            else ReportService(cfg, scope_manager=self.scope_manager)
        )
        self.assess_service = (
            assess_service
            if assess_service is not None
            else AssessService(
                cfg,
                scope_manager=self.scope_manager,
                audit_logger=self.audit_logger,
                profile_service=profile_service,
                cve_service=cve_service,
                intel_service=self.intel_service,
                report_service=self.report_service,
            )
        )

    def dump(
        self,
        raw_target: str,
        *,
        authorized: bool = False,
        out_dir: Path | None = None,
        include_body: bool = True,
        redact_body: bool = False,
        fast: bool = False,
        check_tls_versions: bool = True,
        check_dns_security: bool = True,
        check_well_known: bool = True,
        check_methods: bool = True,
        skip_cve: bool = False,
        enrich_cve: bool = True,
        run_intel: bool = True,
        run_ct: bool = True,
        offline: bool = False,
        min_cvss: float = 7.0,
        cve_limit: int = 10,
        preset: str = "web",
        operator: str | None = None,
        archive: bool = False,
    ) -> DumpResult:
        """Capture and export a complete chain-of-custody evidence bundle for an authorized URL."""
        started = time.monotonic()
        effective_skip_cve = True if fast else skip_cve
        effective_run_intel = False if fast else run_intel
        effective_run_ct = False if fast else run_ct

        capture_bucket: list[RawCaptureBundle] = []

        # Fail-closed: AssessService -> ProfileService -> authorize_and_run enforces
        # scope.yaml (exit 2) and --authorized (exit 3) BEFORE any output directory is created.
        assessment = self.assess_service.assess(
            raw_target,
            authorized=authorized,
            check_tls_versions=check_tls_versions,
            check_dns_security=check_dns_security,
            check_well_known=check_well_known,
            check_methods=check_methods,
            skip_cve=effective_skip_cve,
            enrich_cve=enrich_cve,
            run_intel=effective_run_intel,
            min_cvss=min_cvss,
            cve_limit=cve_limit,
            offline_cve=offline,
            preset=preset,
            include_remediation=True,
            operator=operator,
            out_dir=None,
            capture_out=capture_bucket,
        )

        warnings: list[str] = []
        if assessment.intel is not None and assessment.intel.warnings:
            warnings.extend(assessment.intel.warnings)

        # Optional passive Certificate Transparency lookup (zero target contact)
        ct_res: CTLookupResult | None = None
        parsed = parse_target(assessment.url)
        if effective_run_ct and not parsed.is_ip and not is_v3_onion_host(parsed.host):
            try:
                ct_res = self.intel_service.ct_lookup(parsed.host, offline=offline)
            except S1ShellError as exc:
                warnings.append(f"ct: {exc}")

        # Zero-extra-packet offline deep analyzers
        csp_res, email_res, an_warnings = run_offline_deep_analyzers(assessment.profile)
        warnings.extend(an_warnings)

        resolved_out = (
            out_dir if out_dir is not None else Path("results") / _slugify_target(raw_target)
        )
        capture = capture_bucket[0] if capture_bucket else None

        result = export_evidence_bundle(
            resolved_out,
            assessment=assessment,
            capture=capture,
            report_service=self.report_service,
            scope_manager=self.scope_manager,
            ct_result=ct_res,
            csp_result=csp_res,
            email_result=email_res,
            include_body=include_body,
            redact_body=redact_body,
            include_reports=True,
            operator=operator,
            archive=archive,
            warnings=warnings,
        )

        self.audit_logger.log(
            AuditEvent.create(
                category="target",
                command="dump",
                target=raw_target,
                resolved_ips=[assessment.pinned_ip],
                scope_id=assessment.scope_id,
                auth_ref=assessment.auth_ref,
                authorized_via=assessment.profile.authorized_via,
                outcome="success",
                exit_code=int(ExitCode.SUCCESS),
                duration_ms=int((time.monotonic() - started) * 1000),
            )
        )
        return result
