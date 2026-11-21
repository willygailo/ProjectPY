"""Top-level CLI command routing, shared flags, and exit-code mapping."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, TextIO

from s1shell import DEV_CREDIT, __version__
from s1shell.ai.client import SUPPORTED_AI_MODES
from s1shell.ai.pipelines import SUPPORTED_AI_PIPELINES
from s1shell.ai.service import AIService
from s1shell.analyze.service import AnalyzeService
from s1shell.assess.diff import diff_assessments
from s1shell.assess.remediate import SUPPORTED_STACKS, generate_remediation_from_file
from s1shell.assess.scorer import SUPPORTED_PRESETS, check_policy_gate
from s1shell.assess.service import AssessService
from s1shell.audit import AuditEvent, AuditLogger
from s1shell.codec.codecs import SUPPORTED_DECODERS, SUPPORTED_ENCODERS
from s1shell.codec.service import CodecService
from s1shell.completion import generate_completion
from s1shell.config import SUPPORTED_AI_PROVIDERS, RuntimeConfig
from s1shell.cve.audit_deps import DependencyAuditService
from s1shell.cve.models import CVESearchFilter
from s1shell.cve.service import CVEService
from s1shell.doctor import run_doctor
from s1shell.errors import ExitCode, PolicyGateError, S1ShellError, ValidationError
from s1shell.fingerprint.service import FingerprintService
from s1shell.help_guide import (
    build_parser_epilog,
    build_subcommand_epilog,
    render_check_report,
    render_cli_guide,
    render_full_manual,
    render_module_guide,
)
from s1shell.intel.service import SUPPORTED_INTEL_SOURCES, IntelService
from s1shell.mcp_server import (
    DEFAULT_MCP_HOST,
    DEFAULT_MCP_PORT,
    SUPPORTED_MCP_CLIENTS,
    S1ShellMCPServer,
    build_mcp_client_config,
    ping_mcp_http,
)
from s1shell.models import dumps_json, utc_now
from s1shell.output import (
    make_console,
    render_ai_analysis,
    render_ai_env_status,
    render_ai_investigation,
    render_ai_skill_detail,
    render_ai_skills_catalog,
    render_assessment_diff,
    render_assessment_result,
    render_audit_events,
    render_audit_verify,
    render_batch_assessment,
    render_codec_hash,
    render_codec_inspect,
    render_codec_transform,
    render_config_scan,
    render_csp_analysis,
    render_ct_lookup,
    render_cve_result,
    render_cvss_analysis,
    render_dependency_audit,
    render_doctor_report,
    render_email_analysis,
    render_fingerprint_result,
    render_ghsa_advisories,
    render_header_analysis,
    render_intel_env,
    render_intel_lookup,
    render_mcp_ping,
    render_profile_result,
    render_rdap_lookup,
    render_remediation_plan,
    render_sbom_result,
    render_scope_check,
    render_scope_entries,
    render_scope_import,
    render_secret_scan,
    render_tor_check,
    render_tor_status,
    write_or_print,
)
from s1shell.profile.service import ProfileService
from s1shell.report.service import ReportService
from s1shell.scan.service import ScanService
from s1shell.scope import ScopeManager, parse_expiry
from s1shell.tor import probe_local_tor_port, validate_tor_proxy_url, verify_tor_egress

_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


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
    common.add_argument(
        "--tor",
        action="store_true",
        default=argparse.SUPPRESS,
        help=(
            "Route passive OSINT, CVE, SBOM, cloud AI, and authorized .onion traffic via "
            "local Tor SOCKS5h (fail-closed; zero DNS leaks)."
        ),
    )
    common.add_argument(
        "--tor-targets",
        action="store_true",
        default=argparse.SUPPRESS,
        help=(
            "With `--tor`, also route authorized clearnet target URL/domain checks "
            "(DoH DNS, SOCKS5h TLS, single-GET HTTP) through Tor (zero IP/DNS leak)."
        ),
    )
    common.add_argument(
        "--tor-proxy",
        default=argparse.SUPPRESS,
        help="Custom local loopback Tor SOCKS5h URL (default: socks5h://127.0.0.1:9050).",
    )
    return common


def _enrich_parser_help(parser: argparse.ArgumentParser) -> None:
    """Attach RawDescriptionHelpFormatter and rich usage examples to every subparser."""
    for action in parser._actions:
        mod_choices = getattr(action, "choices", None)
        if not isinstance(mod_choices, dict):
            continue
        for mod_name, mod_parser in mod_choices.items():
            if not isinstance(mod_parser, argparse.ArgumentParser):
                continue
            mod_parser.formatter_class = argparse.RawDescriptionHelpFormatter
            mod_parser.epilog = build_parser_epilog(str(mod_name))
            for sub_action in mod_parser._actions:
                sub_choices = getattr(sub_action, "choices", None)
                if not isinstance(sub_choices, dict):
                    continue
                for sub_name, sub_parser in sub_choices.items():
                    if isinstance(sub_parser, argparse.ArgumentParser):
                        sub_parser.formatter_class = argparse.RawDescriptionHelpFormatter
                        sub_parser.epilog = build_subcommand_epilog(str(mod_name), str(sub_name))


def build_parser() -> argparse.ArgumentParser:
    """Build the S1shell argparse command tree."""
    common = _shared_flags_parser()
    parser = argparse.ArgumentParser(
        prog="s1shell",
        parents=[common],
        add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            f"S1shell v{__version__} ({DEV_CREDIT}): Authorized CVE/SBOM research, "
            "scoped target profiling, passive fingerprinting, posture scoring, "
            "remediation playbooks, defensive AI, MCP server, and reporting."
        ),
        epilog=(
            "Run `s1shell --check` for live local diagnostics + full usage guide, "
            "`s1shell help <module>` for detailed module options, or `s1shell help --all` "
            f"for the complete manual. [{DEV_CREDIT}]"
        ),
    )
    parser.add_argument(
        "-h",
        "--help",
        dest="show_help",
        action="store_true",
        default=False,
        help="Show S1shell CLI overview, modules, workflows, and usage guide.",
    )
    parser.add_argument(
        "--help-all",
        dest="show_help_all",
        action="store_true",
        default=False,
        help="Show complete CLI manual for every module, subcommand, and example.",
    )
    parser.add_argument(
        "--check",
        dest="run_check",
        action="store_true",
        default=False,
        help="Run local readiness check (`doctor`) + show full CLI usage guide.",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"s1shell {__version__} ({DEV_CREDIT})",
    )
    modules = parser.add_subparsers(dest="module", required=False)

    # --- scope ---
    scope_p = modules.add_parser("scope", parents=[common], help="Manage authorized target scope.")
    scope_cmds = scope_p.add_subparsers(dest="command", required=False)

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

    s_imp = scope_cmds.add_parser(
        "import",
        parents=[common],
        help="Bulk-import newline-delimited targets (prefix `!` marks exclusions).",
    )
    s_imp.add_argument("file", type=Path, help="Path to scope target list file.")
    s_imp.add_argument("--owner", required=True, help="System owner or client name.")
    s_imp.add_argument("--ref", required=True, help="Ticket, contract, or SOW reference.")
    s_imp.add_argument("--expires", required=True, help="Expiry date (YYYY-MM-DD or ISO-8601).")
    s_imp.add_argument("--include-subdomains", action="store_true", help="Authorize subdomains.")
    s_imp.add_argument("--exclude", action="store_true", help="Import all lines as exclusions.")
    s_imp.add_argument("--notes", default=None, help="Optional authorization note.")
    s_imp.add_argument("--replace", action="store_true", help="Replace matching active entries.")
    s_imp.add_argument("--dry-run", action="store_true", help="Validate without writing scope.")

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
    cve_p = modules.add_parser(
        "cve", parents=[common], help="Research CVEs & audit lockfiles/SBOMs (zero target contact)."
    )
    cve_cmds = cve_p.add_subparsers(dest="command", required=False)

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
        help="Return only CVEs listed in CISA KEV (implies --enrich).",
    )
    c_search.add_argument("--refresh", action="store_true", help="Bypass cache read.")
    c_search.add_argument("--offline", action="store_true", help="Read from local cache only.")

    c_get = cve_cmds.add_parser("get", parents=[common], help="Look up one or more CVE IDs.")
    c_get.add_argument("cve_ids", nargs="+", help="One or more CVE IDs (e.g. CVE-2021-23017).")
    c_get.add_argument(
        "--enrich",
        action="store_true",
        help="Enrich CVE record(s) with CISA KEV and FIRST EPSS metadata.",
    )
    c_get.add_argument("--refresh", action="store_true", help="Bypass cache read.")
    c_get.add_argument("--offline", action="store_true", help="Read from local cache only.")

    c_audit = cve_cmds.add_parser(
        "audit",
        parents=[common],
        help="Audit lockfile, SBOM (CycloneDX/SPDX), or directory of lockfiles via OSV.dev.",
    )
    c_audit.add_argument(
        "file",
        type=Path,
        help="Path to lockfile, CycloneDX/SPDX SBOM, or project directory.",
    )
    c_audit.add_argument(
        "--recursive",
        action="store_true",
        help="Recursively discover and audit all supported lockfiles/SBOMs inside a directory.",
    )
    c_audit.add_argument(
        "--enrich",
        action="store_true",
        help="Enrich matched CVE aliases with CISA KEV & FIRST EPSS scores.",
    )
    c_audit.add_argument(
        "--kev-only",
        action="store_true",
        help="Return only vulnerabilities listed in CISA KEV (implies --enrich).",
    )
    c_audit.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=None,
        help="CI policy gate: exit code 4 if any dependency vulnerability meets/exceeds severity.",
    )
    c_audit.add_argument("--refresh", action="store_true", help="Bypass cache read.")
    c_audit.add_argument("--offline", action="store_true", help="Read from local cache only.")

    c_cache = cve_cmds.add_parser("cache", parents=[common], help="Manage local CVE cache.")
    c_cache_cmds = c_cache.add_subparsers(dest="cache_cmd", required=False)
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
        help="Also query passive DNS hygiene records (CAA, SPF, DMARC, MTA-STS, DNSSEC, MX/NS).",
    )
    prof_p.add_argument(
        "--well-known",
        action="store_true",
        help="Also perform read-only checks on /.well-known/security.txt and /robots.txt.",
    )
    prof_p.add_argument(
        "--check-methods",
        action="store_true",
        help="Also send 1 read-only OPTIONS request to inspect advertised Allow methods.",
    )

    # --- fingerprint ---
    fp_p = modules.add_parser(
        "fingerprint", parents=[common], help="Passive software, CDN, WAF, and JS lib detection."
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
    rep_cmds = rep_p.add_subparsers(dest="command", required=False)
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
    aud_cmds = aud_p.add_subparsers(dest="command", required=False)
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
        help=(
            "AI `.env` management (builtin/Ollama/Anthropic/OpenAI-compat/Gemini) "
            "& defensive triage."
        ),
    )
    ai_cmds = ai_p.add_subparsers(dest="command", required=False)

    ai_env = ai_cmds.add_parser(
        "env",
        parents=[common],
        help="Show or update AI provider, API key, endpoint URL, and model in `.env`.",
    )
    ai_env.add_argument(
        "--provider",
        choices=list(SUPPORTED_AI_PROVIDERS),
        default=None,
        help="Select AI provider (anthropic, ollama, openai_compat, gemini, builtin).",
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
        "--skill",
        default=None,
        help="Apply a curated defensive AI skill (see `s1shell ai skills list`).",
    )
    ai_analyze.add_argument(
        "--pipeline",
        choices=list(SUPPORTED_AI_PIPELINES),
        default=None,
        help="Run a multi-stage reasoning pipeline (deep-triage, purple-team, executive-pack).",
    )
    ai_analyze.add_argument(
        "--structured",
        action="store_true",
        help="Enforce a validated JSON schema response with 1-shot automatic repair.",
    )
    ai_analyze.add_argument(
        "--redact",
        action="store_true",
        help="Anonymize hostnames, IPv4/IPv6, emails, scope IDs, auth headers & cookies.",
    )
    ai_analyze.add_argument(
        "--restore",
        action="store_true",
        help="With --redact, restore placeholders back to local values after AI inference.",
    )
    ai_analyze.add_argument(
        "--raw-context",
        action="store_true",
        help="Disable smart signal-first artifact distillation and pass raw JSON slices.",
    )
    ai_analyze.add_argument(
        "--local-only",
        action="store_true",
        help="Air-gap guard: refuse any AI endpoint that is not localhost/loopback.",
    )
    ai_analyze.add_argument(
        "--fallback",
        choices=list(SUPPORTED_AI_PROVIDERS),
        default=None,
        help="Optional fallback AI provider if the primary endpoint fails.",
    )
    ai_analyze.add_argument(
        "--cache",
        action="store_true",
        help="Cache single-shot AI responses locally in SQLite to avoid redundant token usage.",
    )
    ai_analyze.add_argument(
        "--refresh",
        action="store_true",
        help="Bypass cached AI response when --cache is enabled.",
    )
    ai_analyze.add_argument(
        "--max-tokens",
        type=int,
        default=1024,
        help="Maximum response tokens (default: 1024).",
    )

    ai_skills = ai_cmds.add_parser(
        "skills",
        parents=[common],
        help="List or inspect bundled and custom (~/.s1shell/skills.d) defensive AI skills.",
    )
    ai_skills_cmds = ai_skills.add_subparsers(dest="skills_cmd", required=False)
    ai_skills_cmds.add_parser("list", parents=[common], help="List all available AI skills.")
    ai_skill_show = ai_skills_cmds.add_parser(
        "show", parents=[common], help="Show full prompt details for one AI skill."
    )
    ai_skill_show.add_argument("skill_id", help="Skill ID (e.g. attack-path-modeling).")

    ai_inv = ai_cmds.add_parser(
        "investigate",
        parents=[common],
        help="Run a bounded read-only ReAct AI investigation using offline/passive tools only.",
    )
    ai_inv.add_argument(
        "--input",
        dest="inputs",
        action="append",
        type=Path,
        default=[],
        help="S1shell JSON artifact or engagement directory (repeatable).",
    )
    ai_inv.add_argument(
        "--goal",
        required=True,
        help="Defensive investigation goal (e.g. 'Prioritize KEV & origin exposure').",
    )
    ai_inv.add_argument(
        "--max-steps",
        type=int,
        default=5,
        help="Maximum bounded tool/reasoning steps (1–8, default: 5).",
    )
    ai_inv.add_argument(
        "--provider",
        choices=list(SUPPORTED_AI_PROVIDERS),
        default=None,
        help="Override active AI provider.",
    )
    ai_inv.add_argument("--base-url", default=None, help="Override AI endpoint URL.")
    ai_inv.add_argument("--model", default=None, help="Override model ID.")
    ai_inv.add_argument("--redact", action="store_true", help="Anonymize sensitive telemetry.")
    ai_inv.add_argument("--restore", action="store_true", help="Restore redacted placeholders.")
    ai_inv.add_argument(
        "--local-only",
        action="store_true",
        help="Air-gap guard: refuse any non-loopback AI endpoint.",
    )
    ai_inv.add_argument(
        "--max-tokens",
        type=int,
        default=1200,
        help="Maximum response tokens per step (default: 1200).",
    )

    ai_chat = ai_cmds.add_parser(
        "chat",
        parents=[common],
        help="Interactive multi-turn defensive AI copilot grounded on saved artifacts.",
    )
    ai_chat.add_argument(
        "--input",
        dest="inputs",
        action="append",
        type=Path,
        default=[],
        help="S1shell JSON artifact or engagement directory (repeatable).",
    )
    ai_chat.add_argument("--skill", default=None, help="Initial defensive skill ID.")
    ai_chat.add_argument(
        "--provider",
        choices=list(SUPPORTED_AI_PROVIDERS),
        default=None,
        help="Override active AI provider.",
    )
    ai_chat.add_argument("--base-url", default=None, help="Override AI endpoint URL.")
    ai_chat.add_argument("--model", default=None, help="Override model ID.")
    ai_chat.add_argument("--redact", action="store_true", help="Anonymize sensitive telemetry.")
    ai_chat.add_argument("--restore", action="store_true", help="Restore redacted placeholders.")
    ai_chat.add_argument(
        "--local-only",
        action="store_true",
        help="Air-gap guard: refuse any non-loopback AI endpoint.",
    )
    ai_chat.add_argument("--max-tokens", type=int, default=1024, help="Max tokens per reply.")

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
        "--preset",
        choices=list(SUPPORTED_PRESETS),
        default="web",
        help="Posture scoring profile: web (default), api (skip HTML/frame noise), or strict.",
    )
    assess_p.add_argument(
        "--ignore-finding",
        dest="ignore_findings",
        action="append",
        default=[],
        help="Waive/suppress a specific finding ID (repeatable, recorded transparently).",
    )
    assess_p.add_argument(
        "--no-tls-versions",
        action="store_true",
        help="Skip bounded TLS 1.0–1.3 protocol matrix check.",
    )
    assess_p.add_argument(
        "--no-dns-security",
        action="store_true",
        help="Skip passive DNS hygiene queries (CAA/SPF/DMARC/MTA-STS/DNSSEC/dangling CNAME).",
    )
    assess_p.add_argument(
        "--well-known",
        action="store_true",
        help="Also perform read-only checks on /.well-known/security.txt and /robots.txt.",
    )
    assess_p.add_argument(
        "--check-methods",
        action="store_true",
        help="Also send 1 read-only OPTIONS request to inspect advertised HTTP methods.",
    )
    assess_p.add_argument(
        "--no-remediate",
        action="store_true",
        help="Skip generating offline hardening config snippets in the assessment bundle.",
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
        "--intel",
        action="store_true",
        help="Run passive third-party threat intel (VirusTotal, GreyNoise, urlscan.io).",
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
        help="Include defensive AI triage (builtin, Ollama, Anthropic, OpenAI-compat, or Gemini).",
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
        "--ai-skill",
        default=None,
        help="Curated defensive AI skill to apply when --ai is enabled.",
    )
    assess_p.add_argument(
        "--ai-pipeline",
        choices=list(SUPPORTED_AI_PIPELINES),
        default=None,
        help="Multi-stage AI reasoning pipeline when --ai is enabled.",
    )
    assess_p.add_argument(
        "--redact",
        action="store_true",
        help="Redact sensitive hostnames/IPs/scope metadata before sending to cloud AI.",
    )
    assess_p.add_argument(
        "--restore",
        action="store_true",
        help="Restore redacted placeholders locally after AI inference.",
    )
    assess_p.add_argument(
        "--local-only",
        action="store_true",
        help="Air-gap guard: only permit localhost/loopback AI endpoints when --ai is set.",
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

    # --- remediate ---
    rem_p = modules.add_parser(
        "remediate",
        parents=[common],
        help="Generate deterministic offline hardening config snippets from assess.json.",
    )
    rem_p.add_argument("assess_file", type=Path, help="Path to saved S1shell assess.json.")
    rem_p.add_argument(
        "--stack",
        choices=list(SUPPORTED_STACKS),
        default="auto",
        help="Target stack template (auto, nginx, apache, caddy, express, generic).",
    )

    # --- intel ---
    intel_p = modules.add_parser(
        "intel",
        parents=[common],
        help="Passive threat intelligence (VirusTotal, GreyNoise, urlscan.io, GitHub GHSA).",
    )
    intel_cmds = intel_p.add_subparsers(dest="command", required=False)

    i_env = intel_cmds.add_parser(
        "env",
        parents=[common],
        help="Show masked status or save NVD/GitHub/VT/GreyNoise/urlscan API keys to `.env`.",
    )
    i_env.add_argument("--set-nvd-key", default=None, help="Save NVD_API_KEY.")
    i_env.add_argument("--set-github-key", default=None, help="Save GITHUB_TOKEN.")
    i_env.add_argument("--set-vt-key", default=None, help="Save VIRUSTOTAL_API_KEY.")
    i_env.add_argument("--set-greynoise-key", default=None, help="Save GREYNOISE_API_KEY.")
    i_env.add_argument("--set-urlscan-key", default=None, help="Save URLSCAN_API_KEY.")
    i_env.add_argument(
        "--env-file",
        type=Path,
        default=None,
        help="Target `.env` file path when saving keys (default: <home>/.env).",
    )

    i_look = intel_cmds.add_parser(
        "lookup",
        parents=[common],
        help="Query passive VirusTotal, GreyNoise, and urlscan.io feeds (zero target contact).",
    )
    i_look.add_argument("indicator", help="Domain, URL, or IP address to look up passively.")
    i_look.add_argument(
        "--pinned-ip",
        default=None,
        help="Optional IPv4 address for GreyNoise lookup alongside a domain.",
    )
    i_look.add_argument(
        "--sources",
        default=None,
        help=f"Comma-separated feeds ({','.join(SUPPORTED_INTEL_SOURCES)}). Default: all.",
    )
    i_look.add_argument("--refresh", action="store_true", help="Bypass local cache.")
    i_look.add_argument("--offline", action="store_true", help="Read from local cache only.")

    i_adv = intel_cmds.add_parser(
        "advisory",
        parents=[common],
        help="Query GitHub Security Advisories (GHSA) by CVE ID or ecosystem+package.",
    )
    i_adv.add_argument("--cve", dest="cve_id", default=None, help="CVE ID (e.g. CVE-2023-45803).")
    i_adv.add_argument(
        "--ecosystem",
        default=None,
        help="Package ecosystem (pip, npm, go, rust, maven, nuget, composer, rubygems).",
    )
    i_adv.add_argument("--package", default=None, help="Package name (e.g. requests).")
    i_adv.add_argument("--limit", type=int, default=15, help="Max advisories to return.")
    i_adv.add_argument("--refresh", action="store_true", help="Bypass local cache.")
    i_adv.add_argument("--offline", action="store_true", help="Read from local cache only.")

    i_ct = intel_cmds.add_parser(
        "ct",
        parents=[common],
        help="Passive Certificate Transparency log lookup via crt.sh (zero target contact).",
    )
    i_ct.add_argument("domain", help="Domain name to inspect in public CT logs.")
    i_ct.add_argument(
        "--export-candidates",
        type=Path,
        default=None,
        help="Write discovered subdomains to FILE for authorization review before `scope import`.",
    )
    i_ct.add_argument("--refresh", action="store_true", help="Bypass local cache.")
    i_ct.add_argument("--offline", action="store_true", help="Read from local cache only.")

    i_rdap = intel_cmds.add_parser(
        "rdap",
        parents=[common],
        help="Query RFC 7480-7484 RDAP domain or IP/ASN registration data (no API key).",
    )
    i_rdap.add_argument("indicator", help="Domain name or IP address for RDAP lookup.")
    i_rdap.add_argument("--refresh", action="store_true", help="Bypass local cache.")
    i_rdap.add_argument("--offline", action="store_true", help="Read from local cache only.")

    # --- codec ---
    codec_p = modules.add_parser(
        "codec",
        parents=[common],
        help="Offline decoder, encoder, smart token/cert/hash inspector, & checksums.",
    )
    codec_cmds = codec_p.add_subparsers(dest="command", required=False)

    c_dec = codec_cmds.add_parser(
        "decode",
        parents=[common],
        help="Decode Base64/Hex/URL/HTML/Unicode/SAML/JWT/Gzip/Auto (offline).",
    )
    c_dec.add_argument(
        "input",
        nargs="?",
        default=None,
        help="Text to decode, `-` for stdin, or omit when piping or using --file.",
    )
    c_dec.add_argument(
        "-e",
        "--encoding",
        default="auto",
        help=f"Decoder name (default: auto). Supported: {', '.join(SUPPORTED_DECODERS)}.",
    )
    c_dec.add_argument(
        "--chain",
        default=None,
        help="Comma-separated ordered decoder pipeline (e.g. url,base64,gzip).",
    )
    c_dec.add_argument("--file", type=Path, default=None, help="Read raw bytes from FILE.")
    c_dec.add_argument(
        "--shift", type=int, default=13, help="Caesar cipher shift amount (default: 13)."
    )
    c_dec.add_argument(
        "--all-shifts",
        action="store_true",
        help="With `-e caesar`, include all 25 shift candidates.",
    )
    c_dec.add_argument(
        "--max-depth",
        type=int,
        default=6,
        help="Max recursive layers for `-e auto` (1–12, default: 6).",
    )
    c_dec.add_argument(
        "--raw",
        action="store_true",
        help="Print only the decoded text directly (ideal for shell piping).",
    )

    c_enc = codec_cmds.add_parser(
        "encode",
        parents=[common],
        help="Encode text or files with a single codec or ordered --chain pipeline (offline).",
    )
    c_enc.add_argument(
        "input",
        nargs="?",
        default=None,
        help="Text to encode, `-` for stdin, or omit when piping or using --file.",
    )
    c_enc.add_argument(
        "-e",
        "--encoding",
        default=None,
        help=f"Encoder name. Supported: {', '.join(SUPPORTED_ENCODERS)}.",
    )
    c_enc.add_argument(
        "--chain",
        default=None,
        help="Comma-separated ordered encoder pipeline (e.g. gzip,base64url).",
    )
    c_enc.add_argument("--file", type=Path, default=None, help="Read raw bytes from FILE.")
    c_enc.add_argument(
        "--shift", type=int, default=13, help="Caesar cipher shift amount (default: 13)."
    )
    c_enc.add_argument(
        "--raw",
        action="store_true",
        help="Print only the encoded text directly (ideal for shell piping).",
    )

    c_ins = codec_cmds.add_parser(
        "inspect",
        parents=[common],
        help="Smart offline inspector for JWT, X.509 PEM/DER, hashes, epochs, & nested encodings.",
    )
    c_ins.add_argument(
        "input",
        nargs="?",
        default=None,
        help="Artifact string to inspect, `-` for stdin, or omit when using --file.",
    )
    c_ins.add_argument("--file", type=Path, default=None, help="Read artifact bytes from FILE.")
    c_ins.add_argument(
        "--max-depth",
        type=int,
        default=6,
        help="Max recursive layers for nested encoding detection (default: 6).",
    )

    c_hash = codec_cmds.add_parser(
        "hash",
        parents=[common],
        help="Compute MD5/SHA-1/SHA-256/SHA-384/SHA-512/BLAKE2b/CRC32 & Shannon entropy.",
    )
    c_hash.add_argument(
        "input",
        nargs="?",
        default=None,
        help="Text to hash, `-` for stdin, or omit when using --file.",
    )
    c_hash.add_argument("--file", type=Path, default=None, help="Read raw bytes from FILE.")
    c_hash.add_argument(
        "--algos",
        default=None,
        help="Comma-separated algorithms (default: md5,sha1,sha256,sha384,sha512,blake2b,crc32).",
    )

    # --- scan ---
    scan_p = modules.add_parser(
        "scan",
        parents=[common],
        help="Offline local security scanner: secrets, IaC/config audit, & CycloneDX 1.5 SBOM.",
    )
    scan_cmds = scan_p.add_subparsers(dest="command", required=False)

    sc_sec = scan_cmds.add_parser(
        "secrets",
        parents=[common],
        help="Scan local files, repositories, or git diffs for exposed secrets (redacted).",
    )
    sc_sec.add_argument(
        "path",
        nargs="?",
        type=Path,
        default=Path("."),
        help="File or repository directory to scan (default: current directory).",
    )
    sc_sec.add_argument(
        "--no-gitignore",
        action="store_true",
        help="Do not skip files matching root `.gitignore`.",
    )
    sc_sec.add_argument(
        "--git-staged",
        action="store_true",
        help="Scan only currently staged `git diff --cached` additions (ideal for pre-commit).",
    )
    sc_sec.add_argument(
        "--git-diff",
        default=None,
        help="Scan only added lines in `git diff <REF>` (e.g. `HEAD~1` or `main...HEAD`).",
    )
    sc_sec.add_argument(
        "--fail-on",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default=None,
        help="Exit 4 if any secret finding meets or exceeds this severity.",
    )

    sc_cfg = scan_cmds.add_parser(
        "config",
        parents=[common],
        help="Audit Dockerfiles, K8s manifests, GitHub Actions, Compose, NGINX, SSHd & .env.",
    )
    sc_cfg.add_argument(
        "path",
        nargs="?",
        type=Path,
        default=Path("."),
        help="Config file or repository directory to audit (default: current directory).",
    )
    sc_cfg.add_argument(
        "--fail-on",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default=None,
        help="Exit 4 if any IaC/config finding meets or exceeds this severity.",
    )

    sc_sbom = scan_cmds.add_parser(
        "sbom",
        parents=[common],
        help="Generate a CycloneDX 1.5 JSON SBOM from local lockfiles, manifests & Dockerfiles.",
    )
    sc_sbom.add_argument(
        "path",
        nargs="?",
        type=Path,
        default=Path("."),
        help="Project directory or dependency manifest (default: current directory).",
    )
    sc_sbom.add_argument(
        "--no-recursive",
        action="store_true",
        help="Only inspect top-level directory without recursing into subdirectories.",
    )
    sc_sbom.add_argument(
        "--raw-bom",
        action="store_true",
        help="Emit raw CycloneDX 1.5 JSON directly (compatible with `s1shell cve audit`).",
    )

    # --- analyze ---
    an_p = modules.add_parser(
        "analyze",
        parents=[common],
        help=(
            "Deep offline/passive security analyzers: CSP3, Email Auth (SPF/DMARC/DKIM), "
            "Headers & CVSS."
        ),
    )
    an_cmds = an_p.add_subparsers(dest="command", required=False)

    an_csp = an_cmds.add_parser(
        "csp",
        parents=[common],
        help="Evaluate a Content-Security-Policy for bypass gadgets, directives & hardening.",
    )
    an_csp.add_argument("policy", nargs="?", default=None, help="Raw CSP policy string.")
    an_csp.add_argument(
        "--file",
        "--from-profile",
        dest="file",
        type=Path,
        default=None,
        help="Read CSP from a text file or saved S1shell `profile.json` / `assess.json`.",
    )

    an_email = an_cmds.add_parser(
        "email",
        parents=[common],
        help="Audit SPF, DMARC, DKIM key strength, MTA-STS, & TLS-RPT anti-spoofing defenses.",
    )
    an_email.add_argument("domain", help="Domain name to audit (e.g. example.com).")
    an_email.add_argument("--spf", default=None, help="Analyze an explicit SPF TXT record offline.")
    an_email.add_argument(
        "--dmarc", default=None, help="Analyze an explicit DMARC TXT record offline."
    )
    an_email.add_argument(
        "--dkim", default=None, help="Analyze an explicit DKIM TXT record offline."
    )
    an_email.add_argument(
        "--selector",
        default=None,
        help="DKIM selector name (e.g. `google`, `selector1`, `default`) for DNS or labeling.",
    )
    an_email.add_argument(
        "--offline",
        action="store_true",
        help="Disable live DNS lookups (evaluate supplied `--spf`/`--dmarc`/`--dkim` only).",
    )

    an_hdr = an_cmds.add_parser(
        "headers",
        parents=[common],
        help="Audit raw HTTP response headers (curl -i / Burp / profile.json) completely offline.",
    )
    an_hdr.add_argument(
        "input",
        nargs="?",
        default=None,
        help="Inline header block, `-` for stdin, or omit when using `--file`.",
    )
    an_hdr.add_argument(
        "--file",
        type=Path,
        default=None,
        help="Read raw HTTP headers or saved `profile.json`/`assess.json` from FILE.",
    )
    an_hdr.add_argument(
        "--url",
        default="https://offline.local/",
        help="Logical target URL context for HTTPS/HSTS scoring (default: https://offline.local/).",
    )
    an_hdr.add_argument(
        "--preset",
        choices=SUPPORTED_PRESETS,
        default="web",
        help="Posture preset: web (default), api, or strict.",
    )

    an_cvss = an_cmds.add_parser(
        "cvss",
        parents=[common],
        help="Calculate and decode FIRST CVSS v3.0/v3.1 (Base/Temporal/Env) & v4.0 vectors.",
    )
    an_cvss.add_argument(
        "vector",
        help="CVSS vector string (e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`).",
    )

    # --- mcp ---
    mcp_p = modules.add_parser(
        "mcp",
        parents=[common],
        help="Run S1shell's online Streamable HTTP or local stdio read-only MCP server.",
    )
    mcp_cmds = mcp_p.add_subparsers(dest="command", required=False)
    mcp_serve = mcp_cmds.add_parser(
        "serve",
        parents=[common],
        help="Start read-only MCP server over local stdio or online Streamable HTTP.",
    )
    mcp_serve.add_argument(
        "--transport",
        choices=("stdio", "http"),
        default="stdio",
        help="MCP transport: local `stdio` (default) or online Streamable `http`.",
    )
    mcp_serve.add_argument(
        "--host",
        default=DEFAULT_MCP_HOST,
        help=f"Bind address for `--transport http` (default: {DEFAULT_MCP_HOST}).",
    )
    mcp_serve.add_argument(
        "--port",
        type=int,
        default=DEFAULT_MCP_PORT,
        help=f"TCP port for `--transport http` (default: {DEFAULT_MCP_PORT}).",
    )
    mcp_serve.add_argument(
        "--token",
        default=None,
        help="Bearer auth token for `--transport http` (or set S1SHELL_MCP_TOKEN).",
    )
    mcp_serve.add_argument(
        "--generate-token",
        action="store_true",
        help="Auto-generate a random Bearer token on startup and print it to stderr.",
    )
    mcp_serve.add_argument(
        "--allow-origin",
        action="append",
        default=[],
        help="Allowlisted HTTP Origin URL for browser/web MCP clients (repeatable).",
    )
    mcp_serve.add_argument(
        "--allow-scoped-targets",
        action="store_true",
        help=(
            "Opt-in: expose fail-closed read-only target tools (`s1shell_profile`, "
            "`s1shell_fingerprint`, `s1shell_assess`). Requires `--authorized`."
        ),
    )

    mcp_cfg = mcp_cmds.add_parser(
        "config",
        parents=[common],
        help="Generate ready-to-paste MCP client JSON config (HTTP or stdio).",
    )
    mcp_cfg.add_argument(
        "client",
        nargs="?",
        default="http",
        choices=SUPPORTED_MCP_CLIENTS,
        help="Target MCP client preset (default: http).",
    )
    mcp_cfg.add_argument(
        "--transport",
        choices=("http", "stdio"),
        default="http",
        help="Config transport mode (default: http).",
    )
    mcp_cfg.add_argument(
        "--url",
        default=f"http://{DEFAULT_MCP_HOST}:{DEFAULT_MCP_PORT}/mcp",
        help="Online MCP server URL for `--transport http`.",
    )
    mcp_cfg.add_argument("--token", default=None, help="Optional Bearer token to embed in config.")
    mcp_cfg.add_argument(
        "--allow-scoped-targets",
        action="store_true",
        help="Include `--allow-scoped-targets --authorized` in generated stdio args.",
    )

    mcp_ping = mcp_cmds.add_parser(
        "ping",
        parents=[common],
        help="Verify connectivity & capabilities of a running online HTTP MCP server.",
    )
    mcp_ping.add_argument(
        "--url",
        default=f"http://{DEFAULT_MCP_HOST}:{DEFAULT_MCP_PORT}/mcp",
        help="Running MCP Streamable HTTP endpoint URL.",
    )
    mcp_ping.add_argument(
        "--token",
        default=None,
        help="Optional Bearer token (falls back to S1SHELL_MCP_TOKEN).",
    )

    # --- tor ---
    tor_p = modules.add_parser(
        "tor",
        parents=[common],
        help="Check local Tor SOCKS5h readiness (`status`) or verify live Tor exit (`check`).",
    )
    tor_cmds = tor_p.add_subparsers(dest="command", required=False)
    tor_cmds.add_parser(
        "status",
        parents=[common],
        help="Offline local check for Tor binary, socksio, and loopback SOCKS5h port.",
    )
    tor_cmds.add_parser(
        "check",
        parents=[common],
        help="Verify live Tor exit egress via check.torproject.org over SOCKS5h (fail-closed).",
    )

    # --- help ---
    help_p = modules.add_parser(
        "help",
        parents=[common],
        help="Show full CLI usage guide, workflows, or detailed help for one module/subcommand.",
    )
    help_p.add_argument(
        "topic",
        nargs="?",
        default=None,
        help="Optional module name (e.g. assess, scope, intel, cve, ai, codec, mcp, tor).",
    )
    help_p.add_argument(
        "subtopic",
        nargs="?",
        default=None,
        help="Optional subcommand name (e.g. `s1shell help cve audit`).",
    )
    help_p.add_argument(
        "--all",
        dest="help_all",
        action="store_true",
        help="Show complete CLI manual with all modules, subcommands, and examples.",
    )

    # --- check ---
    modules.add_parser(
        "check",
        parents=[common],
        help=(
            "Run local readiness check (`doctor`) + show full CLI usage guide (alias for --check)."
        ),
    )

    _enrich_parser_help(parser)
    return parser


def _opt(args: argparse.Namespace, name: str, default: Any = None) -> Any:
    return getattr(args, name, default)


def dispatch(
    args: argparse.Namespace,
    *,
    parser: argparse.ArgumentParser | None = None,
    scope_manager: ScopeManager | None = None,
    cve_service: CVEService | None = None,
    dep_audit_service: DependencyAuditService | None = None,
    intel_service: IntelService | None = None,
    profile_service: ProfileService | None = None,
    fingerprint_service: FingerprintService | None = None,
    report_service: ReportService | None = None,
    ai_service: AIService | None = None,
    assess_service: AssessService | None = None,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Execute a parsed CLI command and return an ExitCode int."""
    err_stream = stderr if stderr is not None else sys.stderr
    tor_flag = _opt(args, "tor")
    tor_targets_flag = _opt(args, "tor_targets")
    tor_proxy_arg = _opt(args, "tor_proxy")
    cfg = RuntimeConfig.from_env(
        home_override=_opt(args, "home"),
        scope_file_override=_opt(args, "scope_file"),
        tor_enabled=True if tor_flag else None,
        tor_targets=True if tor_targets_flag else None,
        tor_proxy=str(tor_proxy_arg) if tor_proxy_arg else None,
    )
    if cfg.tor_targets and not cfg.tor_enabled:
        raise ValidationError("`--tor-targets` requires `--tor` (or S1SHELL_TOR=1).")
    if cfg.tor_enabled:
        validate_tor_proxy_url(cfg.tor_proxy)

    no_color = bool(_opt(args, "no_color", False))
    out_file: Path | None = _opt(args, "out")
    authorized = bool(_opt(args, "authorized", False))
    console = make_console(no_color=no_color, file=stdout)

    if bool(_opt(args, "show_help_all", False)):
        render_full_manual(
            fmt=str(_opt(args, "fmt", "table")),
            console=console,
            out_file=out_file,
            stdout=stdout,
        )
        return int(ExitCode.SUCCESS)

    if bool(_opt(args, "run_check", False)) or args.module == "check":
        doc_report = run_doctor(cfg)
        render_check_report(
            doc_report,
            fmt=str(_opt(args, "fmt", "table")),
            console=console,
            out_file=out_file,
            stdout=stdout,
        )
        return int(ExitCode.SUCCESS if doc_report.healthy else ExitCode.ERROR)

    if args.module == "help":
        help_fmt = str(_opt(args, "fmt", "table"))
        if bool(_opt(args, "help_all", False)):
            render_full_manual(fmt=help_fmt, console=console, out_file=out_file, stdout=stdout)
        elif _opt(args, "topic"):
            render_module_guide(
                str(args.topic),
                subcommand_name=_opt(args, "subtopic"),
                parser=parser if parser is not None else build_parser(),
                fmt=help_fmt,
                console=console,
                out_file=out_file,
                stdout=stdout,
            )
        else:
            render_cli_guide(fmt=help_fmt, console=console, out_file=out_file, stdout=stdout)
        return int(ExitCode.SUCCESS)

    if bool(_opt(args, "show_help", False)) or args.module is None:
        help_fmt = str(_opt(args, "fmt", "table"))
        if args.module:
            render_module_guide(
                str(args.module),
                subcommand_name=_opt(args, "command"),
                parser=parser if parser is not None else build_parser(),
                fmt=help_fmt,
                console=console,
                out_file=out_file,
                stdout=stdout,
            )
        else:
            render_cli_guide(fmt=help_fmt, console=console, out_file=out_file, stdout=stdout)
        return int(ExitCode.SUCCESS)

    subcommand_modules = {
        "scope",
        "cve",
        "report",
        "audit",
        "ai",
        "intel",
        "codec",
        "scan",
        "analyze",
        "mcp",
        "tor",
    }
    if args.module in subcommand_modules and not _opt(args, "command"):
        render_module_guide(
            str(args.module),
            parser=parser if parser is not None else build_parser(),
            fmt=str(_opt(args, "fmt", "table")),
            console=console,
            out_file=out_file,
            stdout=stdout,
        )
        return int(ExitCode.SUCCESS)

    if args.module == "cve" and _opt(args, "command") == "cache" and not _opt(args, "cache_cmd"):
        render_module_guide(
            "cve",
            subcommand_name="cache",
            parser=parser if parser is not None else build_parser(),
            fmt=str(_opt(args, "fmt", "table")),
            console=console,
            out_file=out_file,
            stdout=stdout,
        )
        return int(ExitCode.SUCCESS)

    if args.module == "ai" and _opt(args, "command") == "skills" and not _opt(args, "skills_cmd"):
        render_module_guide(
            "ai",
            subcommand_name="skills",
            parser=parser if parser is not None else build_parser(),
            fmt=str(_opt(args, "fmt", "table")),
            console=console,
            out_file=out_file,
            stdout=stdout,
        )
        return int(ExitCode.SUCCESS)

    scope_mgr = (
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
        if args.command == "import":
            try:
                raw_lines = args.file.read_text(encoding="utf-8").splitlines()
            except OSError as exc:
                raise ValidationError(f"Failed to read scope file '{args.file}': {exc}") from exc
            imp_res = scope_mgr.import_targets(
                raw_lines,
                source=str(args.file),
                owner=args.owner,
                auth_ref=args.ref,
                expires=args.expires,
                include_subdomains=bool(args.include_subdomains),
                notes=args.notes,
                replace=bool(args.replace),
                exclude=bool(args.exclude),
                dry_run=bool(args.dry_run),
            )
            render_scope_import(imp_res, fmt=fmt, console=console, out_file=out_file, stdout=stdout)
            return int(ExitCode.SUCCESS if not imp_res.errors else ExitCode.ERROR)
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
            cve_get_res = cve_svc.get_many(
                list(args.cve_ids),
                refresh=bool(args.refresh),
                offline=bool(args.offline),
                enrich=bool(args.enrich),
            )
            render_cve_result(
                cve_get_res, fmt=fmt, console=console, out_file=out_file, stdout=stdout
            )
            return int(ExitCode.SUCCESS)
        if args.command == "audit":
            dep_svc = (
                dep_audit_service
                if dep_audit_service is not None
                else DependencyAuditService(cfg, audit_logger=audit_log)
            )
            dep_res = dep_svc.audit_path(
                args.file,
                recursive=bool(args.recursive),
                offline=bool(args.offline),
                refresh=bool(args.refresh),
                enrich=bool(args.enrich or args.kev_only),
                kev_only=bool(args.kev_only),
            )
            render_dependency_audit(
                dep_res, fmt=fmt, console=console, out_file=out_file, stdout=stdout
            )
            if args.fail_on:
                threshold = _SEV_RANK.get(args.fail_on.upper(), 99)
                breaching = [
                    v
                    for v in dep_res.vulnerabilities
                    if _SEV_RANK.get("CRITICAL" if v.in_kev else v.severity.upper(), 99)
                    <= threshold
                ]
                if breaching:
                    raise PolicyGateError(
                        f"Dependency audit CI gate failed: {len(breaching)} vulnerability(ies) "
                        f"at or above {args.fail_on}."
                    )
            return int(ExitCode.SUCCESS)
        if args.command == "cache":
            if args.cache_cmd == "clear":
                cleared = cve_svc.clear_cache()
                write_or_print(
                    f"Cleared {cleared} cached CVE entries.", out_file=out_file, stdout=stdout
                )
                return int(ExitCode.SUCCESS)
            render_module_guide(
                "cve",
                subcommand_name="cache",
                parser=parser if parser is not None else build_parser(),
                fmt=fmt,
                console=console,
                out_file=out_file,
                stdout=stdout,
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
        if args.check_methods:
            extra_kwargs["check_methods"] = True
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
            render_audit_events(events, fmt=fmt, console=console, out_file=out_file, stdout=stdout)
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
                skill=args.skill,
                pipeline=args.pipeline,
                structured=bool(args.structured),
                redact=bool(args.redact),
                restore=bool(args.restore),
                compact=not bool(args.raw_context),
                local_only=bool(args.local_only),
                fallback_provider=args.fallback,
                use_cache=bool(args.cache),
                refresh_cache=bool(args.refresh),
                max_tokens=args.max_tokens,
            )
            render_ai_analysis(
                analysis_res, fmt=fmt, console=console, out_file=out_file, stdout=stdout
            )
            return int(ExitCode.SUCCESS)
        if args.command == "skills":
            if args.skills_cmd == "list":
                cat = ai_svc.list_skills()
                render_ai_skills_catalog(
                    cat, fmt=fmt, console=console, out_file=out_file, stdout=stdout
                )
                return int(ExitCode.SUCCESS)
            if args.skills_cmd == "show":
                sk = ai_svc.get_skill(args.skill_id)
                render_ai_skill_detail(
                    sk, fmt=fmt, console=console, out_file=out_file, stdout=stdout
                )
                return int(ExitCode.SUCCESS)
            render_module_guide(
                "ai",
                subcommand_name="skills",
                parser=parser if parser is not None else build_parser(),
                fmt=fmt,
                console=console,
                out_file=out_file,
                stdout=stdout,
            )
            return int(ExitCode.SUCCESS)
        if args.command == "investigate":
            inv_res = ai_svc.investigate(
                inputs=args.inputs,
                goal=args.goal,
                model=args.model,
                provider=args.provider,
                base_url=args.base_url,
                max_steps=args.max_steps,
                max_tokens=args.max_tokens,
                redact=bool(args.redact),
                restore=bool(args.restore),
                local_only=bool(args.local_only),
            )
            render_ai_investigation(
                inv_res, fmt=fmt, console=console, out_file=out_file, stdout=stdout
            )
            return int(ExitCode.SUCCESS)
        if args.command == "chat":
            return ai_svc.chat(
                inputs=args.inputs,
                skill=args.skill,
                model=args.model,
                provider=args.provider,
                base_url=args.base_url,
                redact=bool(args.redact),
                restore=bool(args.restore),
                local_only=bool(args.local_only),
                max_tokens=args.max_tokens,
                stdin=stdin,
                stdout=stdout,
            )

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
        ignored = {fid.strip() for fid in args.ignore_findings if fid.strip()}
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
                check_methods=bool(args.check_methods),
                skip_cve=bool(args.skip_cve),
                enrich_cve=bool(args.enrich_cve),
                run_intel=bool(args.intel),
                min_cvss=args.min_cvss,
                cve_limit=args.cve_limit,
                offline_cve=bool(args.offline),
                run_ai=bool(args.ai),
                ai_provider=args.ai_provider,
                ai_mode=args.ai_mode,
                ai_skill=args.ai_skill,
                ai_pipeline=args.ai_pipeline,
                ai_redact=bool(args.redact),
                ai_restore=bool(args.restore),
                ai_local_only=bool(args.local_only),
                preset=args.preset,
                ignore_findings=ignored or None,
                include_remediation=not bool(args.no_remediate),
                operator=args.operator,
                out_dir=args.out_dir,
            )
            render_batch_assessment(
                batch_res,
                fmt=fmt,
                console=console,
                out_file=out_file,
                stdout=stdout,
                report_service=rep_svc,
                operator=args.operator,
            )
            if args.fail_on:
                threshold = _SEV_RANK.get(args.fail_on.upper(), 99)
                breached = [
                    r.target
                    for r in batch_res.results
                    if r.highest_severity
                    and _SEV_RANK.get(r.highest_severity.upper(), 99) <= threshold
                ]
                if breached:
                    raise PolicyGateError(
                        f"Batch CI policy gate failed: {len(breached)} target(s) met or exceeded "
                        f"--fail-on {args.fail_on} ({', '.join(breached[:5])})."
                    )
            if args.min_score is not None and (
                batch_res.average_score is None or batch_res.average_score < args.min_score
            ):
                raise PolicyGateError(
                    f"Batch average score ({batch_res.average_score}) is below "
                    f"--min-score {args.min_score}."
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
            check_methods=bool(args.check_methods),
            skip_cve=bool(args.skip_cve),
            enrich_cve=bool(args.enrich_cve),
            run_intel=bool(args.intel),
            min_cvss=args.min_cvss,
            cve_limit=args.cve_limit,
            offline_cve=bool(args.offline),
            run_ai=bool(args.ai),
            ai_provider=args.ai_provider,
            ai_mode=args.ai_mode,
            ai_skill=args.ai_skill,
            ai_pipeline=args.ai_pipeline,
            ai_redact=bool(args.redact),
            ai_restore=bool(args.restore),
            ai_local_only=bool(args.local_only),
            preset=args.preset,
            ignore_findings=ignored or None,
            include_remediation=not bool(args.no_remediate),
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

    if args.module == "remediate":
        fmt = str(_opt(args, "fmt", "md"))
        plan = generate_remediation_from_file(args.assess_file, stack=args.stack)
        render_remediation_plan(plan, fmt=fmt, console=console, out_file=out_file, stdout=stdout)
        return int(ExitCode.SUCCESS)

    if args.module == "intel":
        fmt = str(_opt(args, "fmt", "table"))
        i_svc = (
            intel_service
            if intel_service is not None
            else IntelService(cfg, audit_logger=audit_log)
        )
        if args.command == "env":
            if any(
                val is not None
                for val in (
                    args.set_nvd_key,
                    args.set_github_key,
                    args.set_vt_key,
                    args.set_greynoise_key,
                    args.set_urlscan_key,
                )
            ):
                i_env_res = i_svc.save_env(
                    nvd_key=args.set_nvd_key,
                    github_token=args.set_github_key,
                    vt_key=args.set_vt_key,
                    greynoise_key=args.set_greynoise_key,
                    urlscan_key=args.set_urlscan_key,
                    env_file=args.env_file,
                )
            else:
                i_env_res = i_svc.env_status()
            render_intel_env(i_env_res, fmt=fmt, console=console, out_file=out_file, stdout=stdout)
            return int(ExitCode.SUCCESS)
        if args.command == "lookup":
            src_list = [s.strip() for s in args.sources.split(",")] if args.sources else None
            look_res = i_svc.lookup(
                args.indicator,
                pinned_ip=args.pinned_ip,
                sources=src_list,
                offline=bool(args.offline),
                refresh=bool(args.refresh),
            )
            render_intel_lookup(
                look_res, fmt=fmt, console=console, out_file=out_file, stdout=stdout
            )
            return int(ExitCode.SUCCESS)
        if args.command == "advisory":
            adv_res = i_svc.advisories(
                cve_id=args.cve_id,
                ecosystem=args.ecosystem,
                package=args.package,
                limit=args.limit,
                offline=bool(args.offline),
                refresh=bool(args.refresh),
            )
            render_ghsa_advisories(
                adv_res, fmt=fmt, console=console, out_file=out_file, stdout=stdout
            )
            return int(ExitCode.SUCCESS)
        if args.command == "ct":
            ct_res = i_svc.ct_lookup(
                args.domain,
                offline=bool(args.offline),
                refresh=bool(args.refresh),
                export_candidates=args.export_candidates,
            )
            render_ct_lookup(ct_res, fmt=fmt, console=console, out_file=out_file, stdout=stdout)
            return int(ExitCode.SUCCESS)
        if args.command == "rdap":
            rdap_res = i_svc.rdap_lookup(
                args.indicator,
                offline=bool(args.offline),
                refresh=bool(args.refresh),
            )
            render_rdap_lookup(rdap_res, fmt=fmt, console=console, out_file=out_file, stdout=stdout)
            return int(ExitCode.SUCCESS)

    if args.module == "codec":
        fmt = str(_opt(args, "fmt", "table"))
        c_svc = CodecService()
        raw_stdin: bytes | None = None
        if args.file is None and (args.input == "-" or args.input is None):
            in_stream = stdin if stdin is not None else sys.stdin
            if stdin is not None or not in_stream.isatty():
                raw_text = in_stream.read()
                if args.input == "-" or raw_text:
                    raw_stdin = raw_text.encode("utf-8")
        data, src_label = c_svc.read_input_bytes(
            text=args.input,
            file_path=args.file,
            stdin_bytes=raw_stdin,
        )
        if args.command == "decode":
            chain_list = (
                [s.strip() for s in args.chain.split(",") if s.strip()] if args.chain else None
            )
            dec_res = c_svc.decode(
                data,
                encoding=args.encoding,
                chain=chain_list,
                shift=args.shift,
                all_shifts=bool(args.all_shifts),
                max_depth=args.max_depth,
            )
            if args.raw:
                write_or_print(dec_res.output_text, out_file=out_file, stdout=stdout)
            else:
                render_codec_transform(
                    dec_res, fmt=fmt, console=console, out_file=out_file, stdout=stdout
                )
            return int(ExitCode.SUCCESS)
        if args.command == "encode":
            chain_list = (
                [s.strip() for s in args.chain.split(",") if s.strip()] if args.chain else None
            )
            enc_res = c_svc.encode(
                data,
                encoding=args.encoding,
                chain=chain_list,
                shift=args.shift,
            )
            if args.raw:
                write_or_print(enc_res.output_text, out_file=out_file, stdout=stdout)
            else:
                render_codec_transform(
                    enc_res, fmt=fmt, console=console, out_file=out_file, stdout=stdout
                )
            return int(ExitCode.SUCCESS)
        if args.command == "inspect":
            ins_res = c_svc.inspect(data, max_depth=args.max_depth)
            render_codec_inspect(
                ins_res, fmt=fmt, console=console, out_file=out_file, stdout=stdout
            )
            return int(ExitCode.SUCCESS)
        if args.command == "hash":
            algos = [a.strip() for a in args.algos.split(",") if a.strip()] if args.algos else None
            h_res = c_svc.hash_data(data, source=src_label, algos=algos)
            render_codec_hash(h_res, fmt=fmt, console=console, out_file=out_file, stdout=stdout)
            return int(ExitCode.SUCCESS)

    if args.module == "scan":
        fmt = str(_opt(args, "fmt", "table"))
        s_svc = ScanService(cfg, audit_logger=audit_log)
        if args.command == "secrets":
            sec_res = s_svc.secrets(
                args.path,
                respect_gitignore=not bool(args.no_gitignore),
                git_staged=bool(args.git_staged),
                git_diff=args.git_diff,
            )
            render_secret_scan(sec_res, fmt=fmt, console=console, out_file=out_file, stdout=stdout)
            if (
                args.fail_on
                and sec_res.highest_severity
                and _SEV_RANK.get(sec_res.highest_severity, 99)
                <= _SEV_RANK.get(args.fail_on.upper(), 99)
            ):
                raise PolicyGateError(
                    f"Secret scan CI gate failed: {len(sec_res.findings)} finding(s), "
                    f"highest severity {sec_res.highest_severity} >= {args.fail_on.upper()}."
                )
            return int(ExitCode.SUCCESS)
        if args.command == "config":
            cfg_res = s_svc.config(args.path)
            render_config_scan(cfg_res, fmt=fmt, console=console, out_file=out_file, stdout=stdout)
            if (
                args.fail_on
                and cfg_res.highest_severity
                and _SEV_RANK.get(cfg_res.highest_severity, 99)
                <= _SEV_RANK.get(args.fail_on.upper(), 99)
            ):
                raise PolicyGateError(
                    f"Config scan CI gate failed: {len(cfg_res.findings)} finding(s), "
                    f"highest severity {cfg_res.highest_severity} >= {args.fail_on.upper()}."
                )
            return int(ExitCode.SUCCESS)
        if args.command == "sbom":
            sbom_res = s_svc.sbom(args.path, recursive=not bool(args.no_recursive))
            render_sbom_result(
                sbom_res,
                fmt=fmt,
                raw_bom=bool(args.raw_bom),
                console=console,
                out_file=out_file,
                stdout=stdout,
            )
            return int(ExitCode.SUCCESS)

    if args.module == "analyze":
        fmt = str(_opt(args, "fmt", "table"))
        an_svc = AnalyzeService(cfg)
        if args.command == "csp":
            csp_res = an_svc.csp(policy=args.policy, file_path=args.file)
            render_csp_analysis(csp_res, fmt=fmt, console=console, out_file=out_file, stdout=stdout)
            return int(ExitCode.SUCCESS)
        if args.command == "email":
            em_res = an_svc.email(
                args.domain,
                spf_record=args.spf,
                dmarc_record=args.dmarc,
                dkim_record=args.dkim,
                dkim_selector=args.selector,
                offline=bool(args.offline),
            )
            render_email_analysis(
                em_res, fmt=fmt, console=console, out_file=out_file, stdout=stdout
            )
            return int(ExitCode.SUCCESS)
        if args.command == "headers":
            raw_hdr_text: str | None = args.input
            if args.file is None and (args.input == "-" or args.input is None):
                in_stream = stdin if stdin is not None else sys.stdin
                if stdin is not None or not in_stream.isatty():
                    raw_hdr_text = in_stream.read()
            hdr_res = an_svc.headers(
                raw_text=raw_hdr_text,
                file_path=args.file,
                url=args.url,
                preset=args.preset,
            )
            render_header_analysis(
                hdr_res, fmt=fmt, console=console, out_file=out_file, stdout=stdout
            )
            return int(ExitCode.SUCCESS)
        if args.command == "cvss":
            cvss_res = an_svc.cvss(args.vector)
            render_cvss_analysis(
                cvss_res, fmt=fmt, console=console, out_file=out_file, stdout=stdout
            )
            return int(ExitCode.SUCCESS)

    if args.module == "mcp":
        fmt = str(_opt(args, "fmt", "table"))
        if args.command == "serve":
            mcp_srv = S1ShellMCPServer(
                cfg,
                cve_service=cve_service,
                dep_audit_service=dep_audit_service,
                intel_service=intel_service,
                fingerprint_service=fingerprint_service,
                profile_service=profile_service,
                ai_service=ai_service,
                scope_manager=scope_mgr,
                audit_logger=audit_log,
                allow_scoped_targets=bool(_opt(args, "allow_scoped_targets", False)),
                authorized=authorized,
            )
            if _opt(args, "transport", "stdio") == "http":
                return mcp_srv.serve_http(
                    host=str(_opt(args, "host", DEFAULT_MCP_HOST)),
                    port=int(_opt(args, "port", DEFAULT_MCP_PORT)),
                    auth_token=_opt(args, "token"),
                    generate_token=bool(_opt(args, "generate_token", False)),
                    allowed_origins=list(_opt(args, "allow_origin", []) or []),
                    stderr=err_stream,
                )
            return mcp_srv.serve_stdio(stdout=stdout)
        if args.command == "config":
            cfg_json = build_mcp_client_config(
                args.client,
                transport=args.transport,
                url=args.url,
                token=args.token,
                allow_scoped_targets=bool(_opt(args, "allow_scoped_targets", False)),
            )
            write_or_print(dumps_json(cfg_json), out_file=out_file, stdout=stdout)
            return int(ExitCode.SUCCESS)
        if args.command == "ping":
            import os

            tok = args.token or os.environ.get("S1SHELL_MCP_TOKEN") or None
            ping_res = ping_mcp_http(args.url, token=tok, timeout=cfg.timeout_seconds)
            render_mcp_ping(ping_res, fmt=fmt, console=console, out_file=out_file, stdout=stdout)
            return int(ExitCode.SUCCESS)

    if args.module == "tor":
        fmt = str(_opt(args, "fmt", "table"))
        if args.command == "status":
            t_stat = probe_local_tor_port(cfg.tor_proxy)
            render_tor_status(t_stat, fmt=fmt, console=console, out_file=out_file, stdout=stdout)
            return int(ExitCode.SUCCESS)
        if args.command == "check":
            import time as _time

            t0 = _time.monotonic()
            try:
                t_chk = verify_tor_egress(cfg.tor_proxy, timeout=max(cfg.timeout_seconds, 15.0))
            except S1ShellError as exc:
                audit_log.log(
                    AuditEvent.create(
                        category="intel",
                        command="tor_check",
                        target="check.torproject.org",
                        outcome="error",
                        exit_code=int(exc.exit_code),
                        duration_ms=int((_time.monotonic() - t0) * 1000),
                        error=str(exc),
                    )
                )
                raise
            audit_log.log(
                AuditEvent.create(
                    category="intel",
                    command="tor_check",
                    target="check.torproject.org",
                    resolved_ips=[t_chk.exit_ip] if t_chk.exit_ip else [],
                    outcome="success",
                    exit_code=int(ExitCode.SUCCESS),
                    duration_ms=t_chk.latency_ms,
                )
            )
            render_tor_check(t_chk, fmt=fmt, console=console, out_file=out_file, stdout=stdout)
            return int(ExitCode.SUCCESS)

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
        return dispatch(args, parser=parser, stdout=stdout, stderr=err_stream)
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
