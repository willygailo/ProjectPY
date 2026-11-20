"""Target profiling orchestrator gated by Scope -> Authorization -> Audit."""

from __future__ import annotations

import ssl

import httpx

from s1shell.audit import AuditLogger
from s1shell.config import RuntimeConfig
from s1shell.guard import TargetContext, authorize_and_run
from s1shell.profile.dns_check import RecordResolver, collect_dns_records
from s1shell.profile.header_check import analyze_headers, detect_http3_from_alt_svc
from s1shell.profile.html_check import analyze_html_body
from s1shell.profile.models import DNSRecords, ProfileResult, ProtocolInfo, WellKnownCheck
from s1shell.profile.tls_check import inspect_tls
from s1shell.profile.well_known import inspect_http_methods, inspect_well_known
from s1shell.scope import ScopeManager
from s1shell.target_fetch import TLSInspectorFn, fetch_target_snapshot
from s1shell.tor import TorDoHResolver, is_v3_onion_host


class ProfileService:
    """Executes single-target, read-only profiling behind the mandatory policy gate."""

    def __init__(
        self,
        cfg: RuntimeConfig,
        *,
        scope_manager: ScopeManager | None = None,
        audit_logger: AuditLogger | None = None,
        dns_resolver: RecordResolver | None = None,
        tls_inspector: TLSInspectorFn | None = None,
        http_transport: httpx.BaseTransport | None = None,
        cafile: str | None = None,
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
        self.dns_resolver = dns_resolver
        self.tls_inspector = tls_inspector if tls_inspector is not None else inspect_tls
        self.http_transport = http_transport
        self.cafile = cafile

    def profile(
        self,
        raw_target: str,
        *,
        authorized: bool = False,
        check_tls_versions: bool = False,
        check_dns_security: bool = False,
        check_well_known: bool = False,
        check_methods: bool = False,
    ) -> ProfileResult:
        """Profile a single authorized target (1 HTTP request + 1 TLS handshake by default)."""

        def _execute(ctx: TargetContext) -> ProfileResult:
            parsed = ctx.parsed_target
            scope_entry = ctx.scope_result.matched_entry
            pinned_ip = ctx.scope_result.pinned_ip
            assert scope_entry is not None and pinned_ip is not None

            if not parsed.is_ip and is_v3_onion_host(parsed.host):
                dns_records = DNSRecords(
                    errors=["Clearnet DNS skipped for authorized Tor v3 .onion service"]
                )
            else:
                effective_dns_resolver = self.dns_resolver
                if effective_dns_resolver is None and self.cfg.tor_enabled and self.cfg.tor_targets:
                    effective_dns_resolver = TorDoHResolver(
                        self.cfg.tor_proxy,
                        doh_url=self.cfg.tor_doh_url,
                        timeout=min(self.cfg.timeout_seconds, 10.0),
                    )
                dns_records = collect_dns_records(
                    parsed.host,
                    is_ip=parsed.is_ip,
                    timeout=min(self.cfg.timeout_seconds, 5.0),
                    resolver=effective_dns_resolver,
                    include_security=check_dns_security,
                )

            snapshot = fetch_target_snapshot(
                self.cfg,
                parsed=parsed,
                pinned_ip=pinned_ip,
                pinned_ips=ctx.scope_result.resolved_ips,
                tls_inspector=self.tls_inspector,
                http_transport=self.http_transport,
                cafile=self.cafile,
                check_tls_versions=check_tls_versions,
            )
            effective_ip = snapshot.connected_ip or pinned_ip
            resp = snapshot.response
            alt_svc = next((v for k, v in resp.headers if k.lower() == "alt-svc"), None)
            location = (
                next((v for k, v in resp.headers if k.lower() == "location"), None)
                if 300 <= resp.status_code < 400
                else None
            )

            verify_arg: ssl.SSLContext | bool = True
            if self.cafile is not None:
                verify_arg = ssl.create_default_context(cafile=self.cafile)
            elif snapshot.tls is not None and not snapshot.tls.verified:
                verify_arg = False

            allowed_methods: list[str] = []
            risky_methods: list[str] = []
            if check_methods:
                allowed_methods, risky_methods = inspect_http_methods(
                    self.cfg,
                    parsed=parsed,
                    pinned_ip=effective_ip,
                    pinned_ips=ctx.scope_result.resolved_ips,
                    verify=verify_arg,
                    http_transport=self.http_transport,
                )

            protocol = ProtocolInfo(
                status_code=resp.status_code,
                http_version=resp.http_version,
                alpn_protocol=(
                    snapshot.alpn_protocol or ("h2" if "2" in resp.http_version else "http/1.1")
                ),
                http3_advertised=detect_http3_from_alt_svc(alt_svc),
                alt_svc=alt_svc,
                redirect_location=location,
                body_truncated=resp.truncated,
                methods_checked=check_methods,
                allowed_methods=allowed_methods,
                risky_methods=risky_methods,
            )
            header_analysis = analyze_headers(resp.headers, is_https=snapshot.is_https)
            html_analysis = analyze_html_body(
                resp.body,
                headers=resp.headers,
                page_url=snapshot.url,
            )

            well_known: WellKnownCheck | None = None
            if check_well_known:
                well_known = inspect_well_known(
                    self.cfg,
                    parsed=parsed,
                    pinned_ip=effective_ip,
                    pinned_ips=ctx.scope_result.resolved_ips,
                    verify=verify_arg,
                    http_transport=self.http_transport,
                )

            return ProfileResult(
                target=raw_target,
                url=snapshot.url,
                pinned_ip=effective_ip,
                scope_id=scope_entry.id,
                auth_ref=scope_entry.auth_ref,
                authorized_via=ctx.authorized_via,
                dns=dns_records,
                protocol=protocol,
                tls=snapshot.tls,
                headers=header_analysis,
                raw_headers=resp.headers,
                html=html_analysis if html_analysis.analyzed else None,
                well_known=well_known,
            )

        return authorize_and_run(
            raw_target,
            command="profile",
            scope_manager=self.scope_manager,
            audit_logger=self.audit_logger,
            authorized_flag=authorized,
            action=_execute,
        )
