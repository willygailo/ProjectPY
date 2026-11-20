"""Top-level CLI command routing, shared flags, and exit-code mapping."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, TextIO

from s1shell import __version__
from s1shell.ai.client import SUPPORTED_AI_MODES
from s1shell.ai.service import AIService
from s1shell.assess.diff import diff_assessments
from s1shell.assess.scorer import check_policy_gate
from s1shell.assess.service import AssessService
from s1shell.audit import AuditLogger
from s1shell.completion import generate_completion
from s1shell.config import SUPPORTED_AI_PROVIDERS, RuntimeConfig
from s1shell.cve.models import CVESearchFilter
from s1shell.cve.service import CVEService
from s1shell.doctor import run_doctor
from s1shell.errors import ExitCode, PolicyGateError, S1ShellError, ValidationError
from s1shell.fingerprint.service import FingerprintService
from s1shell.mcp_server import S1ShellMCPServer
from s1shell.models import utc_now
from s1shell.output import (
    make_console,
    render_ai_analysis,
    render_ai_env_status,
    render_assessment_diff,
    render_assessment_result,
    render_audit_events,
    render_audit_verify,
    render_batch_assessment,
    render_cve_result,
    render_doctor_report,
    render_fingerprint_result,
    render_profile_result,
    render_scope_check,
    render_scope_entries,
    write_or_print,
)
from s1shell.profile.service import ProfileService
from s1shell.report.service import ReportService
from s1shell.scope import ScopeManager, parse_expiry


def _shared_flags_parser() -> argparse.ArgumentParser:
    """Parent parser for common flags accepted before or after subcommands."""
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--format",
        dest="fmt",
        choices=["table", "json", "md", "html", "sarif"],
        default=argparse.SUPPRESS,
        help="Output format (default depends on command).",
    )
    common.add_argument(
        "--out",
        type=Path,
        default=argparse.SUPPRESS,
        help="Write output to FILE instead of stdout.",
    )
    common.add_argument(
        "--verbose",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Enable verbose diagnostics on stderr.",
    )
    common.add_argument(
        "--no-color",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Disable ANSI terminal colors.",
    )
    common.add_argument(
        "--authorized",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Confirm operator authorization for target-touching actions.",
    )
    common.add_argument(
        "--scope-file",
        type=Path,
        default=argparse.SUPPRESS,
        help="Override path to scope.yaml.",
    )
    common.add_argument(
        "--home",
        type=Path,
        default=argparse.SUPPRESS,
        help="Override S1shell state directory (default: ~/.s1shell or S1SHELL_HOME).",
    )
    return common


def build_parser() -> argparse.ArgumentParser:
    """Build the S1shell argparse command tree."""
    common = _shared_flags_parser()
    parser = argparse.ArgumentParser(
        prog="s1shell",
        parents=[common],
        description=(
            "S1shell: Authorized CVE research, scoped target profiling, "
            "passive fingerprinting, posture scoring, drift diffing, and reporting."
        ),
    )
    parser.add_argument("--version", action="version", version=f"s1shell {__version__}")
    modules = parser.add_subparsers(dest="module", required=True)

    # --- scope ---
    scope_p = modules.add_parser("scope", parents=[common], help="Manage authorized target scope.")
    scope_cmds = scope_p.add_subparsers(dest="command", required=True)

    s_add = scope_cmds.add_parser(
        "add", parents=[common], help="Add an authorized scope or exclusion entry."
    )
    s_add.add_argument("target", help="Hostname, *.domain, IP, CIDR, or URL prefix.")
    s_add.add_argument("--owner", required=True, help="System owner or client name.")
    s_add.add_argument("--ref", required=True, help="Ticket, contract, or SOW reference.")
    s_add.add_argument("--expires", required=True, help="Expiry date (YYYY-MM-DD or ISO-8601).")
    s_add.add_argument(
        "--include-subdomains",
        action="store_true",
        help="Also authorize/exclude subdomains of a domain/URL entry.",
    )
    s_add.add_argument(
        "--exclude",
        action="store_true",
        help="Mark this entry as a deny/exclusion rule overriding broader allow rules.",
    )
    s_add.add_argument("--notes", default=None, help="Optional authorization note.")
    s_add.add_argument(
        "--replace",
        action="store_true",
        help="Replace an existing active entry for the same target.",
    )

    scope_cmds.add_parser("list", parents=[common], help="List configured scope entries.")

    s_check = scope_cmds.add_parser("check", parents=[common], help="Check if target is in scope.")
    s_check.add_argument("target", help="URL, domain, or IP to check.")

    s_rm = scope_cmds.add_parser("remove", parents=[common], help="Remove a scope entry.")
    s_rm.add_argument("identifier", help="Entry ID or exact target string.")

    s_exp = scope_cmds.add_parser("expire", parents=[common], help="Show or prune expired entries.")
    s_exp.add_argument(
        "--prune", action="store_true", help="Remove expired entries from scope.yaml."
    )

    # --- cve ---
    cve_p = modules.add_parser("cve", parents=[common], help="Research CVEs via NVD & CVE.org.")
    cve_cmds = cve_p.add_subparsers(dest="command", required=True)

    c_search = cve_cmds.add_parser("search", parents=[common], help="Search CVEs by keyword/CPE.")
    c_search.add_argument("--keyword", default=None, help="Keyword query (e.g. 'nginx 1.18').")
    c_search.add_argument("--cpe", default=None, help="CPE 2.3 match string.")
    c_search.add_argument(
        "--from-fingerprint",
        type=Path,
        default=None,
        help="Correlate detected stack products from a saved `fingerprint` JSON artifact.",
    )
    c_search.add_argument("--min-cvss", type=float, default=None, help="Minimum CVSS base score.")
    c_search.add_argument(
        "--severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default=None,
        help="Filter by CVSS severity band.",
    )
    c_search.add_argument("--published-after", default=None, help="YYYY-MM-DD lower date bound.")
    c_search.add_argument("--published-before", default=None, help="YYYY-MM-DD upper date bound.")
    c_search.add_argument("--limit", type=int, default=25, help="Max records to display.")
    c_search.add_argument(
        "--enrich",
        action="store_true",
        help="Enrich results with CISA KEV status and FIRST EPSS scores (cached locally).",
    )
    c_search.add_argument(
        "--kev-only",
        action="store_true",
        help="Return only CVEs listed in CISA Known Exploited Vulnerabilities (implies --enrich).",
    )
    c_search.add_argument("--refresh", action="store_true", help="Bypass cache read.")
    c_search.add_argument("--offline", action="store_true", help="Read from local cache only.")

    c_get = cve_cmds.add_parser("get", parents=[common], help="Look up a specific CVE ID.")
    c_get.add_argument("cve_id", help="CVE identifier (e.g. CVE-2021-23017).")
    c_get.add_argument(
        "--enrich",
        action="store_true",
        help="Enrich CVE record with CISA KEV and FIRST EPSS metadata.",
    )
    c_get.add_argument("--refresh", action="store_true", help="Bypass cache read.")
    c_get.add_argument("--offline", action="store_true", help="Read from local cache only.")

    c_cache = cve_cmds.add_parser("cache", parents=[common], help="Manage local CVE cache.")
    c_cache_cmds = c_cache.add_subparsers(dest="cache_cmd", required=True)
    c_cache_cmds.add_parser("clear", parents=[common], help="Clear cached CVE entries.")

    # --- profile ---
    prof_p = modules.add_parser(
        "profile", parents=[common], help="Read-only DNS/TLS/HTTP/HTML profiling."
    )
    prof_p.add_argument("target", help="Authorized URL, domain, IPv4, or IPv6.")
    prof_p.add_argument(
        "--tls-versions",
        action="store_true",
        help="Run bounded TLS 1.0–1.3 support checks in addition to primary handshake.",
    )
    prof_p.add_argument(
        "--dns-security",
        action="store_true",
        help="Also query passive DNS hygiene records (CAA, SPF, DMARC, DNSSEC, dangling CNAME).",
    )
    prof_p.add_argument(
        "--well-known",
        action="store_true",
        help="Also perform read-only checks on /.well-known/security.txt and /robots.txt.",
    )

    # --- fingerprint ---
    fp_p = modules.add_parser(
        "fingerprint", parents=[common], help="Passive software, CDN, and WAF identification."
    )
    fp_p.add_argument("target", nargs="?", default=None, help="Authorized target URL/domain/IP.")
    fp_p.add_argument(
        "--from-profile",
        type=Path,
        default=None,
        help="Inspect a saved `profile` JSON artifact offline (zero network requests).",
    )

    # --- report ---
    rep_p = modules.add_parser(
        "report", parents=[common], help="Compile CVE, profile, fingerprint, and assess reports."
    )
    rep_cmds = rep_p.add_subparsers(dest="command", required=True)
    r_build = rep_cmds.add_parser("build", parents=[common], help="Build combined report.")
    r_build.add_argument(
        "--input",
        dest="inputs",
        action="append",
        type=Path,
        default=[],
        help="Input JSON artifact (auto-detected by artifact_type; repeatable).",
    )
    r_build.add_argument(
        "--profile",
        dest="profiles",
        action="append",
        type=Path,
        default=[],
        help="Profile JSON artifact (repeatable).",
    )
    r_build.add_argument(
        "--fingerprint",
        dest="fingerprints",
        action="append",
        type=Path,
        default=[],
        help="Fingerprint JSON artifact (repeatable).",
    )
    r_build.add_argument(
        "--cve",
        dest="cves",
        action="append",
        type=Path,
        default=[],
        help="CVE JSON artifact (repeatable).",
    )
    r_build.add_argument("--operator", default=None, help="Operator name recorded in report.")

    # --- audit ---
    aud_p = modules.add_parser("audit", parents=[common], help="Inspect or verify audit log.")
    aud_cmds = aud_p.add_subparsers(dest="command", required=True)
    a_list = aud_cmds.add_parser("list", parents=[common], help="Show recent audit log events.")
    a_list.add_argument("--limit", type=int, default=50, help="Maximum recent events to show.")
    a_list.add_argument(
        "--category",
        choices=["target", "intel", "scope"],
        default=None,
        help="Filter audit events by category.",
    )
    a_list.add_argument(
        "--outcome",
        choices=["success", "blocked_out_of_scope", "blocked_unauthorized", "error"],
        default=None,
        help="Filter audit events by outcome.",
    )
    a_list.add_argument("--command", dest="filter_command", default=None, help="Filter by command.")
    a_list.add_argument(
        "--target", dest="filter_target", default=None, help="Substring target filter."
    )
    aud_cmds.add_parser(
        "verify",
        parents=[common],
        help="Verify SHA-256 hash chain integrity of audit.log.",
    )

    # --- doctor ---
    modules.add_parser(
        "doctor",
        parents=[common],
        help="Run local diagnostics on environment, permissions, scope, audit, and cache.",
    )

    # --- completion ---
    comp_p = modules.add_parser(
        "completion",
        parents=[common],
        help="Generate shell completion script (bash, zsh, or fish).",
    )
    comp_p.add_argument("shell", choices=["bash", "zsh", "fish"], help="Target shell.")

    # --- ai ---
    ai_p = modules.add_parser(
        "ai",
        parents=[common],
        help="AI `.env` management (Anthropic/Ollama/OpenAI-compat/Gemini) & defensive triage.",
    )
    ai_cmds = ai_p.add_subparsers(dest="command", required=True)

    ai_env = ai_cmds.add_parser(
        "env",
        parents=[common],
        help="Show or update AI provider, API key, endpoint URL, and model in `.env`.",
    )
    ai_env.add_argument(
        "--provider",
        choices=list(SUPPORTED_AI_PROVIDERS),
        default=None,
        help="Select AI provider (anthropic, ollama, openai_compat, gemini).",
    )
    ai_env.add_argument("--base-url", default=None, help="Override API endpoint URL.")
    ai_env.add_argument("--set-key", default=None, help="Set API key for the active provider.")
    ai_env.add_argument("--model", default=None, help="Set model ID for the active provider.")
    ai_env.add_argument(
        "--env-file",
        type=Path,
        default=None,
        help="Target `.env` file path when saving settings (default: <home>/.env).",
    )

    ai_analyze = ai_cmds.add_parser(
        "analyze",
        parents=[common],
        help="Run defensive AI triage over saved S1shell JSON artifacts or a prompt.",
    )
    ai_analyze.add_argument(
        "--input",
        dest="inputs",
        action="append",
        type=Path,
        default=[],
        help="S1shell JSON artifact to analyze (repeatable).",
    )
    ai_analyze.add_argument(
        "--prompt",
        default=None,
        help="Defensive analysis instruction or question.",
    )
    ai_analyze.add_argument(
        "--provider",
        choices=list(SUPPORTED_AI_PROVIDERS),
        default=None,
        help="Override active AI provider for this run.",
    )
    ai_analyze.add_argument("--base-url", default=None, help="Override AI endpoint URL.")
    ai_analyze.add_argument("--model", default=None, help="Override model ID.")
    ai_analyze.add_argument(
        "--mode",
        choices=list(SUPPORTED_AI_MODES),
        default="triage",
        help="Defensive analysis style: triage, executive, or remediate (config snippets).",
    )
    ai_analyze.add_argument(
        "--redact",
        action="store_true",
        help="Anonymize hostnames, IPs, scope IDs, and cookies before sending to AI.",
    )
    ai_analyze.add_argument(
        "--max-tokens",
        type=int,
        default=1024,
        help="Maximum response tokens (default: 1024).",
    )

    # --- assess ---
    assess_p = modules.add_parser(
        "assess",
        parents=[common],
        help="All-in-one authorized assessment (profile, fingerprint, CVE, posture, report).",
    )
    assess_p.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Authorized URL, domain, IPv4, or IPv6 (omit when using --targets-file).",
    )
    assess_p.add_argument(
        "--targets-file",
        type=Path,
        default=None,
        help="Assess newline-delimited targets sequentially (concurrency=1, scope-gated).",
    )
    assess_p.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Seconds to pause between targets in --targets-file mode (default: 0.5).",
    )
    assess_p.add_argument(
        "--no-tls-versions",
        action="store_true",
        help="Skip bounded TLS 1.0–1.3 protocol matrix check.",
    )
    assess_p.add_argument(
        "--no-dns-security",
        action="store_true",
        help="Skip passive DNS hygiene queries (CAA/SPF/DMARC/DNSSEC/dangling CNAME).",
    )
    assess_p.add_argument(
        "--well-known",
        action="store_true",
        help="Also perform read-only checks on /.well-known/security.txt and /robots.txt.",
    )
    assess_p.add_argument(
        "--skip-cve",
        action="store_true",
        help="Skip public NVD/CVE correlation.",
    )
    assess_p.add_argument(
        "--enrich-cve",
        action="store_true",
        help="Enrich correlated CVEs with CISA KEV & FIRST EPSS risk intelligence.",
    )
    assess_p.add_argument(
        "--min-cvss",
        type=float,
        default=7.0,
        help="Minimum CVSS base score for correlated CVEs (default: 7.0).",
    )
    assess_p.add_argument(
        "--cve-limit",
        type=int,
        default=10,
        help="Maximum correlated CVEs to include (default: 10).",
    )
    assess_p.add_argument(
        "--offline",
        action="store_true",
        help="Read correlated CVEs from local SQLite cache only.",
    )
    assess_p.add_argument(
        "--ai",
        action="store_true",
        help="Include defensive AI triage (Anthropic, local Ollama, OpenAI-compat, or Gemini).",
    )
    assess_p.add_argument(
        "--ai-provider",
        choices=list(SUPPORTED_AI_PROVIDERS),
        default=None,
        help="Override AI provider when --ai is enabled.",
    )
    assess_p.add_argument(
        "--ai-mode",
        choices=list(SUPPORTED_AI_MODES),
        default="triage",
        help="AI analysis mode when --ai is enabled (triage, executive, remediate).",
    )
    assess_p.add_argument(
        "--redact",
        action="store_true",
        help="Redact sensitive hostnames/IPs/scope metadata before sending to cloud AI.",
    )
    assess_p.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=None,
        help="CI policy gate: exit code 4 if any finding meets or exceeds severity.",
    )
    assess_p.add_argument(
        "--min-score",
        type=int,
        default=None,
        help="CI policy gate: exit code 4 if posture score falls below INT (0-100).",
    )
    assess_p.add_argument(
        "--operator",
        default=None,
        help="Operator name recorded in generated report bundles.",
    )
    assess_p.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Save all JSON/SARIF artifacts and HTML/MD reports into DIR.",
    )

    # --- diff ---
    diff_p = modules.add_parser(
        "diff",
        parents=[common],
        help="Compare baseline vs current assess.json artifacts for security posture drift.",
    )
    diff_p.add_argument("baseline", type=Path, help="Path to older baseline assess.json.")
    diff_p.add_argument("current", type=Path, help="Path to newer current assess.json.")
    diff_p.add_argument(
        "--fail-on-regression",
        action="store_true",
        help="CI gate: exit code 4 if posture score dropped or new HIGH/CRITICAL/CVE appeared.",
    )

    # --- mcp ---
    mcp_p = modules.add_parser(
        "mcp",
        parents=[common],
        help="Run S1shell's strictly read-only offline/intel MCP server (stdio JSON-RPC 2.0).",
    )
    mcp_cmds = mcp_p.add_subparsers(dest="command", required=True)
    mcp_cmds.add_parser(
        "serve",
        parents=[common],
        help="Start read-only offline MCP server over stdin/stdout.",
    )

    return parser


def _opt(args: argparse.Namespace, name: str, default: Any = None) -> Any:
    return getattr(args, name, default)


def dispatch(
    args: argparse.Namespace,
    *,
    scope_manager: ScopeManager | None = None,
    cve_service: CVEService | None = None,
    profile_service: ProfileService | None = None,
    fingerprint_service: FingerprintService | None = None,
    report_service: ReportService | None = None,
    ai_service: AIService | None = None,
    assess_service: AssessService | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Execute a parsed CLI command and return an ExitCode int."""
    err_stream = stderr if stderr is not None else sys.stderr
    cfg = RuntimeConfig.from_env(
        home_override=_opt(args, "home"),
        scope_file_override=_opt(args, "scope_file"),
    )
    no_color = bool(_opt(args, "no_color", False))
    out_file: Path | None = _opt(args, "out")
    authorized = bool(_opt(args, "authorized", False))
    console = make_console(no_color=no_color, file=stdout)

    scope_mgr = scope_manager if scope_manager is not None else ScopeManager(cfg.scope_file)
    audit_log = AuditLogger(cfg.audit_log)

    if args.module == "scope":
        fmt = str(_opt(args, "fmt", "table"))
        if args.command == "add":
            if parse_expiry(args.expires) < utc_now():
                err_stream.write(
                    f"Warning: expiry '{args.expires}' is already in the past; "
                    "entry will not authorize targets.\n"
                )
            entry = scope_mgr.add(
                args.target,
                owner=args.owner,
                auth_ref=args.ref,
                expires=args.expires,
                include_subdomains=bool(args.include_subdomains),
                notes=args.notes,
                replace=bool(args.replace),
                exclude=bool(args.exclude),
            )
            render_scope_entries(
                [entry], fmt=fmt, console=console, out_file=out_file, stdout=stdout
            )
            return int(ExitCode.SUCCESS)
        if args.command == "list":
            render_scope_entries(
                scope_mgr.load(), fmt=fmt, console=console, out_file=out_file, stdout=stdout
            )
            return int(ExitCode.SUCCESS)
        if args.command == "check":
            scope_res = scope_mgr.check_target(args.target)
            render_scope_check(
                scope_res, fmt=fmt, console=console, out_file=out_file, stdout=stdout
            )
            return int(ExitCode.SUCCESS if scope_res.in_scope else ExitCode.OUT_OF_SCOPE)
        if args.command == "remove":
            removed = scope_mgr.remove(args.identifier)
            if not removed:
                raise ValidationError(f"No scope entry matched '{args.identifier}'.")
            render_scope_entries(
                removed, fmt=fmt, console=console, out_file=out_file, stdout=stdout
            )
            return int(ExitCode.SUCCESS)
        if args.command == "expire":
            expired = scope_mgr.expire(prune=bool(args.prune))
            render_scope_entries(
                expired, fmt=fmt, console=console, out_file=out_file, stdout=stdout
            )
            return int(ExitCode.SUCCESS)

    if args.module == "cve":
        fmt = str(_opt(args, "fmt", "table"))
        cve_svc = (
            cve_service if cve_service is not None else CVEService(cfg, audit_logger=audit_log)
        )
        if args.command == "search":
            search_filter = CVESearchFilter(
                keyword=args.keyword,
                cpe=args.cpe,
                min_cvss=args.min_cvss,
                severity=args.severity,
                published_after=args.published_after,
                published_before=args.published_before,
                limit=args.limit,
                kev_only=bool(args.kev_only),
            )
            enrich_flag = bool(args.enrich or args.kev_only)
            if args.from_fingerprint is not None:
                if args.keyword or args.cpe:
                    raise ValidationError(
                        "Cannot combine --from-fingerprint with --keyword or --cpe."
                    )
                cve_res = cve_svc.search_from_fingerprint(
                    args.from_fingerprint,
                    filters=search_filter,
                    refresh=bool(args.refresh),
                    offline=bool(args.offline),
                    enrich=enrich_flag,
                )
            else:
                cve_res = cve_svc.search(
                    search_filter,
                    refresh=bool(args.refresh),
                    offline=bool(args.offline),
                    enrich=enrich_flag,
                )
            render_cve_result(cve_res, fmt=fmt, console=console, out_file=out_file, stdout=stdout)
            return int(ExitCode.SUCCESS)
        if args.command == "get":
            cve_get_res = cve_svc.get(
                args.cve_id,
                refresh=bool(args.refresh),
                offline=bool(args.offline),
                enrich=bool(args.enrich),
            )
            render_cve_result(
                cve_get_res, fmt=fmt, console=console, out_file=out_file, stdout=stdout
            )
            return int(ExitCode.SUCCESS)
        if args.command == "cache" and args.cache_cmd == "clear":
            cleared = cve_svc.clear_cache()
            write_or_print(
                f"Cleared {cleared} cached CVE entries.", out_file=out_file, stdout=stdout
            )
            return int(ExitCode.SUCCESS)

    if args.module == "profile":
        fmt = str(_opt(args, "fmt", "table"))
        prof_svc = (
            profile_service
            if profile_service is not None
            else ProfileService(cfg, scope_manager=scope_mgr, audit_logger=audit_log)
        )
        extra_kwargs: dict[str, Any] = {}
        if args.dns_security:
            extra_kwargs["check_dns_security"] = True
        if args.well_known:
            extra_kwargs["check_well_known"] = True
        prof_res = prof_svc.profile(
            args.target,
            authorized=authorized,
            check_tls_versions=bool(args.tls_versions),
            **extra_kwargs,
        )
        render_profile_result(prof_res, fmt=fmt, console=console, out_file=out_file, stdout=stdout)
        return int(ExitCode.SUCCESS)

    if args.module == "fingerprint":
        fmt = str(_opt(args, "fmt", "table"))
        fp_svc = (
            fingerprint_service
            if fingerprint_service is not None
            else FingerprintService(cfg, scope_manager=scope_mgr, audit_logger=audit_log)
        )
        if args.from_profile is not None:
            fp_res = fp_svc.from_profile(args.from_profile)
        elif args.target:
            fp_res = fp_svc.inspect_target(args.target, authorized=authorized)
        else:
            raise ValidationError("Provide a target or --from-profile FILE for `fingerprint`.")
        render_fingerprint_result(
            fp_res, fmt=fmt, console=console, out_file=out_file, stdout=stdout
        )
        return int(ExitCode.SUCCESS)

    if args.module == "report" and args.command == "build":
        fmt = str(_opt(args, "fmt", "md"))
        rep_svc = (
            report_service
            if report_service is not None
            else ReportService(cfg, scope_manager=scope_mgr)
        )
        bundle = rep_svc.build_bundle(
            inputs=args.inputs,
            profile_paths=args.profiles,
            fingerprint_paths=args.fingerprints,
            cve_paths=args.cves,
            operator=args.operator,
        )
        rendered = rep_svc.render(bundle, fmt=fmt)
        write_or_print(rendered, out_file=out_file, stdout=stdout)
        return int(ExitCode.SUCCESS)

    if args.module == "audit":
        fmt = str(_opt(args, "fmt", "table"))
        if args.command == "list":
            events = audit_log.read_recent(
                limit=args.limit,
                category=args.category,
                outcome=args.outcome,
                command=args.filter_command,
                target=args.filter_target,
            )
            render_audit_events(
                events, fmt=fmt, console=console, out_file=out_file, stdout=stdout
            )
            return int(ExitCode.SUCCESS)
        if args.command == "verify":
            verify_res = audit_log.verify()
            render_audit_verify(
                verify_res, fmt=fmt, console=console, out_file=out_file, stdout=stdout
            )
            return int(ExitCode.SUCCESS if verify_res.valid else ExitCode.ERROR)

    if args.module == "doctor":
        fmt = str(_opt(args, "fmt", "table"))
        doc_report = run_doctor(cfg)
        render_doctor_report(doc_report, fmt=fmt, console=console, out_file=out_file, stdout=stdout)
        return int(ExitCode.SUCCESS if doc_report.healthy else ExitCode.ERROR)

    if args.module == "completion":
        script = generate_completion(args.shell)
        write_or_print(script, out_file=out_file, stdout=stdout)
        return int(ExitCode.SUCCESS)

    if args.module == "ai":
        fmt = str(_opt(args, "fmt", "table"))
        ai_svc = ai_service if ai_service is not None else AIService(cfg, audit_logger=audit_log)
        if args.command == "env":
            if (
                args.set_key is not None
                or args.model is not None
                or args.provider is not None
                or args.base_url is not None
            ):
                env_res = ai_svc.save_env(
                    api_key=args.set_key,
                    model=args.model,
                    provider=args.provider,
                    base_url=args.base_url,
                    env_file=args.env_file,
                )
            else:
                env_res = ai_svc.env_status()
            render_ai_env_status(
                env_res, fmt=fmt, console=console, out_file=out_file, stdout=stdout
            )
            return int(ExitCode.SUCCESS)
        if args.command == "analyze":
            analysis_res = ai_svc.analyze(
                inputs=args.inputs,
                prompt=args.prompt,
                model=args.model,
                provider=args.provider,
                base_url=args.base_url,
                mode=args.mode,
                redact=bool(args.redact),
                max_tokens=args.max_tokens,
            )
            render_ai_analysis(
                analysis_res, fmt=fmt, console=console, out_file=out_file, stdout=stdout
            )
            return int(ExitCode.SUCCESS)

    if args.module == "assess":
        fmt = str(_opt(args, "fmt", "table"))
        assess_svc = (
            assess_service
            if assess_service is not None
            else AssessService(cfg, scope_manager=scope_mgr, audit_logger=audit_log)
        )
        rep_svc = (
            report_service
            if report_service is not None
            else ReportService(cfg, scope_manager=scope_mgr)
        )
        if args.targets_file is not None:
            if args.target:
                raise ValidationError("Cannot combine a positional target with --targets-file.")
            try:
                raw_lines = args.targets_file.read_text(encoding="utf-8").splitlines()
            except OSError as exc:
                raise ValidationError(
                    f"Failed to read targets file '{args.targets_file}': {exc}"
                ) from exc
            batch_res = assess_svc.assess_batch(
                raw_lines,
                authorized=authorized,
                delay_seconds=args.delay,
                check_tls_versions=not bool(args.no_tls_versions),
                check_dns_security=not bool(args.no_dns_security),
                check_well_known=bool(args.well_known),
                skip_cve=bool(args.skip_cve),
                enrich_cve=bool(args.enrich_cve),
                min_cvss=args.min_cvss,
                cve_limit=args.cve_limit,
                offline_cve=bool(args.offline),
                run_ai=bool(args.ai),
                ai_provider=args.ai_provider,
                ai_mode=args.ai_mode,
                ai_redact=bool(args.redact),
                operator=args.operator,
                out_dir=args.out_dir,
            )
            render_batch_assessment(
                batch_res, fmt=fmt, console=console, out_file=out_file, stdout=stdout
            )
            if args.min_score is not None and (
                batch_res.average_score is None or batch_res.average_score < args.min_score
            ):
                raise PolicyGateError(
                    f"Batch average score ({batch_res.average_score}) is below --min-score {args.min_score}."
                )
            return int(ExitCode.SUCCESS)

        if not args.target:
            raise ValidationError("Provide a target or --targets-file FILE for `assess`.")

        assess_res = assess_svc.assess(
            args.target,
            authorized=authorized,
            check_tls_versions=not bool(args.no_tls_versions),
            check_dns_security=not bool(args.no_dns_security),
            check_well_known=bool(args.well_known),
            skip_cve=bool(args.skip_cve),
            enrich_cve=bool(args.enrich_cve),
            min_cvss=args.min_cvss,
            cve_limit=args.cve_limit,
            offline_cve=bool(args.offline),
            run_ai=bool(args.ai),
            ai_provider=args.ai_provider,
            ai_mode=args.ai_mode,
            ai_redact=bool(args.redact),
            operator=args.operator,
            out_dir=args.out_dir,
        )
        render_assessment_result(
            assess_res,
            fmt=fmt,
            console=console,
            out_file=out_file,
            stdout=stdout,
            report_service=rep_svc,
            operator=args.operator,
        )
        gate_failure = check_policy_gate(
            assess_res.posture,
            assess_res.findings,
            fail_on=args.fail_on,
            min_score=args.min_score,
        )
        if gate_failure:
            raise PolicyGateError(f"CI policy gate failed: {gate_failure}")
        return int(ExitCode.SUCCESS)

    if args.module == "diff":
        fmt = str(_opt(args, "fmt", "table"))
        diff_res = diff_assessments(args.baseline, args.current)
        render_assessment_diff(diff_res, fmt=fmt, console=console, out_file=out_file, stdout=stdout)
        if args.fail_on_regression and diff_res.regressed:
            raise PolicyGateError(
                f"Posture regression detected (score delta {diff_res.score_delta:+d}, "
                f"new findings={len(diff_res.new_findings)}, new CVEs={len(diff_res.new_cves)})."
            )
        return int(ExitCode.SUCCESS)

    if args.module == "mcp" and args.command == "serve":
        mcp_srv = S1ShellMCPServer(
            cfg,
            cve_service=cve_service,
            fingerprint_service=fingerprint_service,
            scope_manager=scope_mgr,
            audit_logger=audit_log,
        )
        return mcp_srv.serve_stdio(stdout=stdout)

    err_stream.write("Unknown command.\n")
    return int(ExitCode.ERROR)


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """CLI entry point returning POSIX exit code."""
    err_stream = stderr if stderr is not None else sys.stderr
    parser = build_parser()
    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
        return code

    verbose = bool(_opt(args, "verbose", False))
    try:
        return dispatch(args, stdout=stdout, stderr=err_stream)
    except S1ShellError as exc:
        err_stream.write(f"Error: {exc}\n")
        return int(exc.exit_code)
    except Exception as exc:
        if verbose:
            import traceback

            traceback.print_exc(file=err_stream)
        else:
            err_stream.write(f"Unexpected error: {exc}\n")
        return int(ExitCode.ERROR)
