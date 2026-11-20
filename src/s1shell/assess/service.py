"""All-in-one authorized defensive assessment & sequential batch orchestrator."""

from __future__ import annotations

import getpass
import json
import re
import time
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

from s1shell import __version__
from s1shell.ai.models import AIAnalysisResult
from s1shell.ai.service import AIService
from s1shell.assess.models import (
    AssessmentResult,
    BatchAssessmentResult,
    BatchTargetSummary,
    RemediationSnippet,
)
from s1shell.assess.remediate import generate_remediation_plan
from s1shell.assess.scorer import evaluate_posture_with_suppressions, highest_severity
from s1shell.audit import AuditLogger
from s1shell.config import RuntimeConfig
from s1shell.cve.models import CVERecord, CVESearchFilter, CVESearchResult
from s1shell.cve.nvd import is_version_affected
from s1shell.cve.service import CVEService
from s1shell.errors import (
    ExitCode,
    OutOfScopeError,
    S1ShellError,
    UnauthorizedError,
    ValidationError,
)
from s1shell.fingerprint.matcher import match_signatures
from s1shell.fingerprint.models import FingerprintResult
from s1shell.fingerprint.service import FingerprintService
from s1shell.intel.models import IntelLookupResult
from s1shell.intel.service import IntelService
from s1shell.models import dumps_json, to_json_compatible, utc_now_iso
from s1shell.profile.service import ProfileService
from s1shell.report.models import ReportBundle, ReportMetadata
from s1shell.report.service import ReportService
from s1shell.scope import ScopeManager


def _slugify_target(raw: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "_", raw.strip()).strip("_")
    return slug[:80] or "target"


def build_report_bundle_from_assessment(
    result: AssessmentResult,
    *,
    operator: str | None = None,
    scope_manager: ScopeManager | None = None,
) -> ReportBundle:
    """Construct a complete ReportBundle preserving posture, findings, and AI analysis."""
    resolved_operator = (operator or getpass.getuser() or "unknown").strip() or "unknown"
    scope_entries: list[dict[str, object]] = []
    if scope_manager is not None and scope_manager.scope_file.exists():
        loaded = {e.id: e.to_dict() for e in scope_manager.load()}
        if result.scope_id in loaded:
            scope_entries.append(dict(loaded[result.scope_id]))
        else:
            scope_entries.append({"id": result.scope_id, "auth_ref": result.auth_ref})
    else:
        scope_entries.append({"id": result.scope_id, "auth_ref": result.auth_ref})

    metadata = ReportMetadata(
        generated_at_utc=utc_now_iso(),
        operator=resolved_operator,
        tool_version=__version__,
        scope_entries=scope_entries,
    )
    return ReportBundle(
        metadata=metadata,
        profiles=[to_json_compatible(result.profile)],
        fingerprints=[to_json_compatible(result.fingerprint)],
        cves=[to_json_compatible(result.cve)] if result.cve is not None else [],
        intel=[to_json_compatible(result.intel)] if result.intel is not None else [],
        posture=to_json_compatible(result.posture),
        findings=[to_json_compatible(f) for f in result.findings],
        ai_analysis=(
            to_json_compatible(result.ai_analysis) if result.ai_analysis is not None else None
        ),
        remediation_snippets=[to_json_compatible(s) for s in result.remediation_snippets],
        generated_at_utc=metadata.generated_at_utc,
    )


class AssessService:
    """Runs the unified profile -> fingerprint -> CVE -> posture -> remediation -> report flow."""

    def __init__(
        self,
        cfg: RuntimeConfig,
        *,
        scope_manager: ScopeManager | None = None,
        audit_logger: AuditLogger | None = None,
        profile_service: ProfileService | None = None,
        fingerprint_service: FingerprintService | None = None,
        cve_service: CVEService | None = None,
        intel_service: IntelService | None = None,
        report_service: ReportService | None = None,
        ai_service: AIService | None = None,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        self.cfg = cfg
        self.scope_manager = (
            scope_manager if scope_manager is not None else ScopeManager(cfg.scope_file)
        )
        self.audit_logger = audit_logger if audit_logger is not None else AuditLogger(cfg.audit_log)
        self.profile_service = (
            profile_service
            if profile_service is not None
            else ProfileService(
                cfg,
                scope_manager=self.scope_manager,
                audit_logger=self.audit_logger,
            )
        )
        self.fingerprint_service = (
            fingerprint_service
            if fingerprint_service is not None
            else FingerprintService(
                cfg,
                scope_manager=self.scope_manager,
                audit_logger=self.audit_logger,
            )
        )
        self.cve_service = (
            cve_service
            if cve_service is not None
            else CVEService(cfg, audit_logger=self.audit_logger)
        )
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
        self.ai_service = (
            ai_service if ai_service is not None else AIService(cfg, audit_logger=self.audit_logger)
        )
        self._sleeper = sleeper if sleeper is not None else time.sleep

    def assess(
        self,
        raw_target: str,
        *,
        authorized: bool = False,
        check_tls_versions: bool = True,
        check_dns_security: bool = True,
        check_well_known: bool = False,
        check_methods: bool = False,
        skip_cve: bool = False,
        enrich_cve: bool = False,
        run_intel: bool = False,
        min_cvss: float = 7.0,
        cve_limit: int = 10,
        offline_cve: bool = False,
        run_ai: bool = False,
        ai_provider: str | None = None,
        ai_mode: str = "triage",
        ai_redact: bool = False,
        preset: str = "web",
        ignore_findings: set[str] | None = None,
        include_remediation: bool = True,
        operator: str | None = None,
        out_dir: Path | None = None,
    ) -> AssessmentResult:
        """Execute a complete single-target read-only assessment pipeline."""
        if cve_limit <= 0:
            raise ValidationError("--cve-limit must be a positive integer.")

        prof = self.profile_service.profile(
            raw_target,
            authorized=authorized,
            check_tls_versions=check_tls_versions,
            check_dns_security=check_dns_security,
            check_well_known=check_well_known,
            check_methods=check_methods,
        )

        tls_issuer = prof.tls.issuer if prof.tls is not None else None
        fp_matches = match_signatures(
            prof.raw_headers,
            tls_issuer=tls_issuer,
            cnames=prof.dns.cname,
            html_analysis=prof.html,
            signatures=self.fingerprint_service.signatures,
        )
        fp = FingerprintResult(
            target=prof.target,
            url=prof.url,
            mode="from_profile",
            scope_id=prof.scope_id,
            auth_ref=prof.auth_ref,
            matches=fp_matches,
        )

        cve_res: CVESearchResult | None = None
        if not skip_cve and fp.matches:
            queries: list[tuple[str | None, str | None, str | None]] = []
            seen_keys: set[str] = set()
            keywords: list[str] = []
            cpes: list[str] = []

            for match in fp.matches:
                if match.cpe:
                    dk = f"cpe:{match.cpe.lower()}"
                    if dk not in seen_keys:
                        seen_keys.add(dk)
                        cpes.append(match.cpe)
                        queries.append((None, match.cpe, match.version))
                else:
                    kw = f"{match.product} {match.version or ''}".strip()
                    dk = f"kw:{kw.lower()}"
                    if kw and dk not in seen_keys:
                        seen_keys.add(dk)
                        keywords.append(kw)
                        queries.append((kw, None, match.version))

            combined: dict[str, CVERecord] = {}
            all_cached = True
            for kw_q, cpe_str, version in queries:
                sub = self.cve_service.search(
                    CVESearchFilter(
                        keyword=kw_q,
                        cpe=cpe_str,
                        min_cvss=min_cvss,
                        limit=cve_limit,
                    ),
                    offline=offline_cve,
                    enrich=enrich_cve,
                )
                all_cached = all_cached and sub.cached
                cpe_vendor: str | None = None
                cpe_product: str | None = None
                if cpe_str:
                    parts = cpe_str.split(":")
                    if len(parts) >= 5:
                        cpe_vendor = parts[3]
                        cpe_product = parts[4]
                for rec in sub.records:
                    if version and rec.cpe_ranges:
                        affected = is_version_affected(
                            version,
                            rec.cpe_ranges,
                            cpe_vendor=cpe_vendor,
                            cpe_product=cpe_product,
                        )
                        if affected is False:
                            continue
                        rec = replace(rec, version_verified=affected)
                    combined.setdefault(rec.cve_id, rec)

            ordered = sorted(
                combined.values(),
                key=lambda r: (
                    1 if r.in_kev else 0,
                    r.epss_score if r.epss_score is not None else -1.0,
                    r.cvss.base_score if r.cvss else -1.0,
                    r.published,
                ),
                reverse=True,
            )[:cve_limit]
            cve_res = CVESearchResult(
                query={
                    "keywords": keywords,
                    "cpes": cpes,
                    "min_cvss": min_cvss,
                    "limit": cve_limit,
                    "enriched": enrich_cve,
                },
                cached=all_cached,
                records=ordered,
            )

        intel_res: IntelLookupResult | None = None
        if run_intel:
            intel_res = self.intel_service.lookup(
                prof.url,
                pinned_ip=prof.pinned_ip,
                sources=("vt", "greynoise", "urlscan", "rdap"),
                offline=offline_cve,
            )

        posture, findings, suppressed = evaluate_posture_with_suppressions(
            prof,
            fp,
            cve_res,
            intel=intel_res,
            preset=preset,
            ignore_findings=ignore_findings,
        )

        rem_snippets: list[RemediationSnippet] = []
        if include_remediation and findings:
            rem_plan = generate_remediation_plan(
                target_url=prof.url,
                findings=findings,
                fingerprint_matches=[to_json_compatible(m) for m in fp.matches],
                stack="auto",
            )
            rem_snippets = rem_plan.snippets

        ai_res: AIAnalysisResult | None = None
        if run_ai:
            summary_payload = {
                "target": prof.url,
                "preset": preset,
                "posture": to_json_compatible(posture),
                "findings": [to_json_compatible(f) for f in findings],
                "matches": [to_json_compatible(m) for m in fp.matches],
                "cve_count": len(cve_res.records) if cve_res else 0,
                "kev_count": (sum(1 for r in cve_res.records if r.in_kev) if cve_res else 0),
            }
            ai_prompt = (
                "Provide a concise defensive executive summary and prioritized remediation "
                "plan for this authorized target assessment:\n\n"
                '<untrusted_telemetry source="assessment_summary">\n'
                f"{json.dumps(summary_payload, indent=2)}\n"
                "</untrusted_telemetry>"
            )
            ai_res = self.ai_service.analyze(
                prompt=ai_prompt,
                provider=ai_provider,
                mode=ai_mode,
                redact=ai_redact,
            )

        result = AssessmentResult(
            target=prof.target,
            url=prof.url,
            pinned_ip=prof.pinned_ip,
            scope_id=prof.scope_id,
            auth_ref=prof.auth_ref,
            posture=posture,
            findings=findings,
            profile=prof,
            fingerprint=fp,
            cve=cve_res,
            intel=intel_res,
            ai_analysis=ai_res,
            preset=preset.strip().lower(),
            suppressed_findings=suppressed,
            remediation_snippets=rem_snippets,
        )

        if out_dir is not None:
            resolved_dir = out_dir.expanduser().resolve()
            resolved_dir.mkdir(parents=True, exist_ok=True)
            saved: list[str] = []

            prof_path = resolved_dir / "profile.json"
            prof_path.write_text(dumps_json(prof), encoding="utf-8")
            saved.append(str(prof_path))

            fp_path = resolved_dir / "fingerprint.json"
            fp_path.write_text(dumps_json(fp), encoding="utf-8")
            saved.append(str(fp_path))

            if cve_res is not None:
                cve_path = resolved_dir / "cves.json"
                cve_path.write_text(dumps_json(cve_res), encoding="utf-8")
                saved.append(str(cve_path))

            if intel_res is not None:
                intel_path = resolved_dir / "intel.json"
                intel_path.write_text(dumps_json(intel_res), encoding="utf-8")
                saved.append(str(intel_path))

            bundle = build_report_bundle_from_assessment(
                result,
                operator=operator,
                scope_manager=self.scope_manager,
            )
            md_path = resolved_dir / "report.md"
            md_path.write_text(self.report_service.render(bundle, fmt="md"), encoding="utf-8")
            saved.append(str(md_path))

            html_path = resolved_dir / "report.html"
            html_path.write_text(self.report_service.render(bundle, fmt="html"), encoding="utf-8")
            saved.append(str(html_path))

            sarif_path = resolved_dir / "report.sarif"
            sarif_path.write_text(self.report_service.render(bundle, fmt="sarif"), encoding="utf-8")
            saved.append(str(sarif_path))

            assess_path = resolved_dir / "assess.json"
            saved.append(str(assess_path))
            result = replace(result, saved_files=saved)
            assess_path.write_text(dumps_json(result), encoding="utf-8")

        return result

    def assess_batch(
        self,
        targets: list[str],
        *,
        authorized: bool = False,
        delay_seconds: float = 0.5,
        check_tls_versions: bool = True,
        check_dns_security: bool = True,
        check_well_known: bool = False,
        check_methods: bool = False,
        skip_cve: bool = False,
        enrich_cve: bool = False,
        run_intel: bool = False,
        min_cvss: float = 7.0,
        cve_limit: int = 10,
        offline_cve: bool = False,
        run_ai: bool = False,
        ai_provider: str | None = None,
        ai_mode: str = "triage",
        ai_redact: bool = False,
        preset: str = "web",
        ignore_findings: set[str] | None = None,
        include_remediation: bool = True,
        operator: str | None = None,
        out_dir: Path | None = None,
    ) -> BatchAssessmentResult:
        """Sequentially assess multiple targets (`concurrency=1`) enforcing scope per target."""
        clean_targets = [t.strip() for t in targets if t.strip() and not t.strip().startswith("#")]
        if not clean_targets:
            raise ValidationError("No targets provided for batch assessment.")
        if delay_seconds < 0:
            raise ValidationError("--delay must be >= 0.")

        summaries: list[BatchTargetSummary] = []
        saved_files: list[str] = []
        scores: list[int] = []
        succeeded = 0
        blocked = 0
        errored = 0

        resolved_out = out_dir.expanduser().resolve() if out_dir is not None else None
        if resolved_out is not None:
            resolved_out.mkdir(parents=True, exist_ok=True)

        for idx, raw_target in enumerate(clean_targets):
            if idx > 0 and delay_seconds > 0:
                self._sleeper(delay_seconds)
            target_dir = (
                resolved_out / f"{idx + 1:02d}_{_slugify_target(raw_target)}"
                if resolved_out is not None
                else None
            )
            try:
                res = self.assess(
                    raw_target,
                    authorized=authorized,
                    check_tls_versions=check_tls_versions,
                    check_dns_security=check_dns_security,
                    check_well_known=check_well_known,
                    check_methods=check_methods,
                    skip_cve=skip_cve,
                    enrich_cve=enrich_cve,
                    run_intel=run_intel,
                    min_cvss=min_cvss,
                    cve_limit=cve_limit,
                    offline_cve=offline_cve,
                    run_ai=run_ai,
                    ai_provider=ai_provider,
                    ai_mode=ai_mode,
                    ai_redact=ai_redact,
                    preset=preset,
                    ignore_findings=ignore_findings,
                    include_remediation=include_remediation,
                    operator=operator,
                    out_dir=target_dir,
                )
                succeeded += 1
                scores.append(res.posture.score)
                saved_files.extend(res.saved_files)
                summaries.append(
                    BatchTargetSummary(
                        target=raw_target,
                        status="ok",
                        exit_code=int(ExitCode.SUCCESS),
                        url=res.url,
                        score=res.posture.score,
                        grade=res.posture.grade,
                        risk_level=res.posture.risk_level,
                        highest_severity=highest_severity(res.findings),
                        finding_count=len(res.findings),
                        cve_count=len(res.cve.records) if res.cve else 0,
                    )
                )
            except OutOfScopeError as exc:
                blocked += 1
                summaries.append(
                    BatchTargetSummary(
                        target=raw_target,
                        status="blocked_out_of_scope",
                        exit_code=int(ExitCode.OUT_OF_SCOPE),
                        error=str(exc),
                    )
                )
            except UnauthorizedError as exc:
                blocked += 1
                summaries.append(
                    BatchTargetSummary(
                        target=raw_target,
                        status="blocked_unauthorized",
                        exit_code=int(ExitCode.UNAUTHORIZED),
                        error=str(exc),
                    )
                )
            except S1ShellError as exc:
                errored += 1
                summaries.append(
                    BatchTargetSummary(
                        target=raw_target,
                        status="error",
                        exit_code=int(exc.exit_code),
                        error=str(exc),
                    )
                )

        avg = round(sum(scores) / len(scores), 1) if scores else None
        batch_res = BatchAssessmentResult(
            targets_total=len(clean_targets),
            succeeded=succeeded,
            blocked=blocked,
            errored=errored,
            average_score=avg,
            results=summaries,
            saved_files=saved_files,
        )
        if resolved_out is not None:
            html_path = resolved_out / "batch_report.html"
            html_path.write_text(
                self.report_service.render_batch_html(batch_res, operator=operator),
                encoding="utf-8",
            )
            summary_path = resolved_out / "batch_summary.json"
            batch_res = replace(
                batch_res,
                saved_files=[*saved_files, str(html_path), str(summary_path)],
            )
            summary_path.write_text(dumps_json(batch_res), encoding="utf-8")
        return batch_res
