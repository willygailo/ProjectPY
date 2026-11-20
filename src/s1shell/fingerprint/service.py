"""Passive fingerprinting service supporting offline profile reuse and guarded live fetch."""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from s1shell.audit import AuditLogger
from s1shell.config import RuntimeConfig
from s1shell.errors import ValidationError
from s1shell.fingerprint.matcher import load_signatures, match_signatures
from s1shell.fingerprint.models import FingerprintResult
from s1shell.guard import TargetContext, authorize_and_run
from s1shell.profile.html_check import analyze_html_body
from s1shell.profile.tls_check import inspect_tls
from s1shell.scope import ScopeManager
from s1shell.target_fetch import TLSInspectorFn, fetch_target_snapshot


class FingerprintService:
    """Runs passive software/CDN/WAF identification from one normal response or saved profile."""

    def __init__(
        self,
        cfg: RuntimeConfig,
        *,
        scope_manager: ScopeManager | None = None,
        audit_logger: AuditLogger | None = None,
        tls_inspector: TLSInspectorFn | None = None,
        http_transport: httpx.BaseTransport | None = None,
        cafile: str | None = None,
        signatures_path: Path | None = None,
    ) -> None:
        self.cfg = cfg
        self.scope_manager = (
            scope_manager if scope_manager is not None else ScopeManager(cfg.scope_file)
        )
        self.audit_logger = audit_logger if audit_logger is not None else AuditLogger(cfg.audit_log)
        self.tls_inspector = tls_inspector if tls_inspector is not None else inspect_tls
        self.http_transport = http_transport
        self.cafile = cafile
        self.signatures = load_signatures(
            signatures_path,
            extra_dir=cfg.signatures_dir if signatures_path is None else None,
        )

    def from_profile(self, profile_path: Path) -> FingerprintResult:
        """Passively fingerprint using a previously saved `profile` JSON artifact (offline)."""
        try:
            data = json.loads(profile_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ValidationError(
                f"Failed to read profile artifact '{profile_path}': {exc}"
            ) from exc

        if not isinstance(data, dict) or data.get("artifact_type") != "profile_report":
            raise ValidationError(
                f"File '{profile_path}' is not a valid s1shell profile_report artifact."
            )

        raw_headers = [
            (str(pair[0]), str(pair[1]))
            for pair in data.get("raw_headers", [])
            if isinstance(pair, (list, tuple)) and len(pair) == 2
        ]
        tls_block = data.get("tls")
        tls_issuer = tls_block.get("issuer") if isinstance(tls_block, dict) else None
        dns_block = data.get("dns")
        cnames = dns_block.get("cname", []) if isinstance(dns_block, dict) else []
        html_block = data.get("html") if isinstance(data.get("html"), dict) else None

        matches = match_signatures(
            raw_headers,
            tls_issuer=str(tls_issuer) if tls_issuer else None,
            cnames=cnames if isinstance(cnames, list) else [],
            html_analysis=html_block,
            signatures=self.signatures,
        )
        return FingerprintResult(
            target=str(data.get("target", "")),
            url=str(data.get("url", "")),
            mode="from_profile",
            scope_id=str(data.get("scope_id", "")),
            auth_ref=str(data.get("auth_ref", "")),
            matches=matches,
        )

    def inspect_target(self, raw_target: str, *, authorized: bool = False) -> FingerprintResult:
        """Fetch one normal response behind the policy gate and identify technologies."""

        def _execute(ctx: TargetContext) -> FingerprintResult:
            parsed = ctx.parsed_target
            entry = ctx.scope_result.matched_entry
            pinned_ip = ctx.scope_result.pinned_ip
            assert entry is not None and pinned_ip is not None

            snapshot = fetch_target_snapshot(
                self.cfg,
                parsed=parsed,
                pinned_ip=pinned_ip,
                pinned_ips=ctx.scope_result.resolved_ips,
                tls_inspector=self.tls_inspector,
                http_transport=self.http_transport,
                cafile=self.cafile,
                check_tls_versions=False,
            )
            tls_issuer = snapshot.tls.issuer if snapshot.tls is not None else None
            html_analysis = analyze_html_body(
                snapshot.response.body,
                headers=snapshot.response.headers,
                page_url=snapshot.url,
            )

            matches = match_signatures(
                snapshot.response.headers,
                tls_issuer=tls_issuer,
                html_analysis=html_analysis if html_analysis.analyzed else None,
                signatures=self.signatures,
            )
            return FingerprintResult(
                target=raw_target,
                url=snapshot.url,
                mode="live",
                scope_id=entry.id,
                auth_ref=entry.auth_ref,
                matches=matches,
            )

        return authorize_and_run(
            raw_target,
            command="fingerprint",
            scope_manager=self.scope_manager,
            audit_logger=self.audit_logger,
            authorized_flag=authorized,
            action=_execute,
        )
