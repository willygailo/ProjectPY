"""Comprehensive CLI usage guide, quickstart manual, and `--check` renderer."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from s1shell import DEV_CREDIT, __developer__, __version__
from s1shell.doctor import DoctorReport
from s1shell.errors import ValidationError
from s1shell.models import dumps_json
from s1shell.output import write_or_print


@dataclass(frozen=True)
class SubcommandGuide:
    """Documentation entry for a single nested subcommand."""

    name: str
    usage: str
    summary: str
    examples: tuple[str, ...] = ()


@dataclass(frozen=True)
class ModuleGuide:
    """Documentation entry for a top-level S1shell CLI module."""

    name: str
    group: str
    network: str
    summary: str
    usage: str
    subcommands: tuple[SubcommandGuide, ...] = ()
    key_flags: tuple[str, ...] = ()
    examples: tuple[str, ...] = ()


@dataclass(frozen=True)
class WorkflowGuide:
    """End-to-end operational workflow snippet."""

    title: str
    description: str
    commands: tuple[str, ...] = field(default_factory=tuple)


GLOBAL_FLAGS: tuple[tuple[str, str], ...] = (
    ("--check", "Run local diagnostics (`doctor`) + show full CLI usage guide."),
    ("-h, --help", "Show S1shell CLI overview, modules, workflows, and usage guide."),
    ("--help-all", "Show complete manual for every module, subcommand, and example."),
    ("-V, --version", f"Show S1shell version and developer credit ({DEV_CREDIT})."),
    ("--format FMT", "Output format: table, json, md, html, sarif (depends on command)."),
    ("--out FILE", "Write rendered output to FILE instead of stdout."),
    ("--authorized", "Confirm operator authorization for scoped target-touching actions."),
    ("--scope-file FILE", "Override path to scope.yaml."),
    ("--home DIR", "Override state directory (default: ~/.s1shell or $S1SHELL_HOME)."),
    ("--tor", "Route passive OSINT, CVE, SBOM, cloud AI, & .onion via local Tor SOCKS5h."),
    ("--tor-targets", "With --tor, also route authorized public targets over Tor (zero leak)."),
    ("--tor-proxy URL", "Custom local loopback Tor proxy URL (default: socks5h://127.0.0.1:9050)."),
    ("--no-color", "Disable ANSI terminal colors."),
    ("--verbose", "Print full tracebacks to stderr on unexpected errors."),
)

EXIT_CODES: tuple[tuple[str, str], ...] = (
    ("0", "Success"),
    ("1", "Validation, network, diagnostic, or runtime error"),
    ("2", "Target out of scope, excluded, expired, or unsafe IP resolution"),
    ("3", "Operator authorization not confirmed (pass --authorized or confirm TTY)"),
    ("4", "CI policy gate breached (--fail-on, --min-score, --fail-on-regression)"),
)

GROUP_ORDER: tuple[str, ...] = (
    "Target Profiling & Assessment",
    "Passive OSINT, CVE & SBOM",
    "Defensive AI, Offline Codec, Reports & MCP",
    "Setup, Scope Governance & Diagnostics",
)

MODULE_GUIDES: tuple[ModuleGuide, ...] = (
    ModuleGuide(
        name="assess",
        group="Target Profiling & Assessment",
        network="Scoped Target + Passive Feeds",
        summary=(
            "All-in-one authorized assessment: DNS/TLS/HTTP/HTML profile, passive "
            "fingerprint, EOL/CVE/KEV/EPSS, passive intel, posture score, playbook & reports."
        ),
        usage="s1shell assess <target | --targets-file FILE> --authorized [options]",
        key_flags=(
            "--authorized",
            "--targets-file FILE",
            "--preset {web,api,strict}",
            "--enrich-cve",
            "--intel",
            "--well-known",
            "--check-methods",
            "--ai / --ai-skill / --ai-pipeline",
            "--fail-on SEV / --min-score N",
            "--out-dir DIR",
            "--dump-evidence [--no-body] [--redact-body]",
        ),
        examples=(
            (
                "s1shell assess https://example.com --authorized --enrich-cve --intel "
                "--well-known --check-methods --out-dir ./results/example"
            ),
            (
                "s1shell assess https://api.example.com --authorized --preset api "
                "--fail-on HIGH --min-score 80 --format sarif --out target.sarif"
            ),
            (
                "s1shell assess https://example.com --authorized --ai --ai-provider builtin "
                "--ai-skill attack-path-modeling --out-dir ./results/example"
            ),
            (
                "s1shell assess --targets-file targets.txt --authorized --delay 1.0 "
                "--out-dir ./results/batch"
            ),
        ),
    ),
    ModuleGuide(
        name="dump",
        group="Target Profiling & Assessment",
        network="Scoped Target (Read-Only) + Optional Passive Feeds",
        summary=(
            "Export a complete 0700/0600 chain-of-custody evidence bundle from an authorized URL: "
            "raw headers & bounded body, TLS PEM chain, DNS JSON, RFC well-known files, surface "
            "entities CSV/JSON, offline CSP3/email/hardening analyses, reports, & SHA-256 manifest."
        ),
        usage="s1shell dump <target_url> --authorized --out-dir DIR [options]",
        key_flags=(
            "--authorized",
            "--out-dir DIR",
            "--no-body",
            "--redact-body",
            "--fast",
            "--skip-cve / --skip-intel / --skip-ct",
            "--preset {web,api,strict}",
            "--archive",
        ),
        examples=(
            "s1shell dump https://example.com --authorized --out-dir ./results/example-dump",
            (
                "s1shell dump https://example.com --authorized --fast --redact-body "
                "--archive --out-dir ./results/example-fast"
            ),
            "s1shell analyze headers --file ./results/example-dump/raw/response_headers.txt",
            "s1shell codec inspect --file ./results/example-dump/raw/tls_chain.pem",
        ),
    ),
    ModuleGuide(
        name="profile",
        group="Target Profiling & Assessment",
        network="Scoped Target (Read-Only)",
        summary=(
            "Read-only single-GET target profiler: DNS hygiene (CAA/SPF/DMARC/DNSSEC), "
            "TLS/X.509 chain, security headers, cookies, contacts/keys & surface entities."
        ),
        usage="s1shell profile <target> --authorized [options]",
        key_flags=(
            "--authorized",
            "--tls-versions",
            "--dns-security",
            "--well-known",
            "--check-methods",
            "--format {table,json,md}",
            "--out FILE",
        ),
        examples=(
            (
                "s1shell profile https://example.com --authorized --tls-versions "
                "--dns-security --well-known --check-methods"
            ),
            (
                "s1shell profile https://example.com --authorized --format json "
                "--out ./results/profile.json"
            ),
        ),
    ),
    ModuleGuide(
        name="fingerprint",
        group="Target Profiling & Assessment",
        network="Offline (--from-profile) or 1 GET",
        summary=(
            "Passive server, CDN, WAF, framework & client-side JS library detection "
            "(81 bundled rules + custom signatures.d) with CPE 2.3 & offline EOL flags."
        ),
        usage="s1shell fingerprint [<target> --authorized | --from-profile FILE]",
        key_flags=(
            "--from-profile FILE",
            "--authorized",
            "--format {table,json,md}",
            "--out FILE",
        ),
        examples=(
            "s1shell fingerprint --from-profile ./results/profile.json",
            "s1shell fingerprint https://example.com --authorized --format json",
        ),
    ),
    ModuleGuide(
        name="remediate",
        group="Target Profiling & Assessment",
        network="Offline (Zero Network)",
        summary=(
            "Generate deterministic stack-tailored defensive hardening config snippets "
            "(nginx, apache, caddy, express, dns, security.txt) from assess.json."
        ),
        usage="s1shell remediate <assess.json> [--stack auto|nginx|apache|caddy|express|generic]",
        key_flags=("--stack STACK", "--format {md,table,json}", "--out FILE"),
        examples=(
            "s1shell remediate ./results/example/assess.json --stack auto",
            (
                "s1shell remediate ./results/example/assess.json --stack nginx "
                "--format md --out hardening.md"
            ),
        ),
    ),
    ModuleGuide(
        name="diff",
        group="Target Profiling & Assessment",
        network="Offline (Zero Network)",
        summary=(
            "Compare baseline vs current assess.json artifacts to detect security "
            "posture drift, new/resolved findings, and CI regressions."
        ),
        usage="s1shell diff <baseline.json> <current.json> [--fail-on-regression]",
        key_flags=("--fail-on-regression", "--format {table,json,md}", "--out FILE"),
        examples=(
            "s1shell diff ./results/base/assess.json ./results/retest/assess.json",
            (
                "s1shell diff ./results/base/assess.json ./results/retest/assess.json "
                "--fail-on-regression --format md"
            ),
        ),
    ),
    ModuleGuide(
        name="intel",
        group="Passive OSINT, CVE & SBOM",
        network="Passive Public Feeds (Zero Target Contact)",
        summary=(
            "Zero-target-contact passive OSINT across VirusTotal v3, GreyNoise, "
            "urlscan.io Search, GitHub Advisories (GHSA), crt.sh CT logs, & RDAP."
        ),
        usage="s1shell intel <env|lookup|advisory|ct|rdap> [options]",
        subcommands=(
            SubcommandGuide(
                "env",
                "s1shell intel env [--set-nvd-key KEY] [--set-github-key KEY] ...",
                "Show masked API key status or save NVD/GitHub/VT/GreyNoise/urlscan keys (0600).",
                (
                    "s1shell intel env",
                    "s1shell intel env --set-nvd-key YOUR_KEY --set-vt-key YOUR_VT_KEY",
                ),
            ),
            SubcommandGuide(
                "lookup",
                "s1shell intel lookup <domain|url|ip> [--sources vt,greynoise,urlscan,rdap]",
                "Passive multi-feed reputation, historical scans, and registration lookup.",
                (
                    "s1shell intel lookup example.com",
                    "s1shell intel lookup example.com --sources vt,urlscan,rdap --format json",
                ),
            ),
            SubcommandGuide(
                "ct",
                "s1shell intel ct <domain> [--export-candidates FILE]",
                "Query crt.sh Certificate Transparency logs for passive SAN subdomains.",
                (
                    "s1shell intel ct example.com",
                    "s1shell intel ct example.com --export-candidates candidates.txt",
                ),
            ),
            SubcommandGuide(
                "rdap",
                "s1shell intel rdap <domain|url|ip>",
                "Query RFC 7480-7484 RDAP registrar, lock, DNSSEC, contacts, & IP CIDR data.",
                ("s1shell intel rdap example.com", "s1shell intel rdap 1.1.1.1"),
            ),
            SubcommandGuide(
                "advisory",
                "s1shell intel advisory [--cve CVE-ID | --ecosystem ECO --package PKG]",
                "Query GitHub Security Advisories (GHSA) by CVE or ecosystem+package.",
                (
                    "s1shell intel advisory --cve CVE-2023-45803",
                    "s1shell intel advisory --ecosystem pip --package requests",
                ),
            ),
        ),
        key_flags=("--sources", "--export-candidates FILE", "--refresh", "--offline", "--tor"),
        examples=(
            "s1shell intel ct example.com --export-candidates subs.txt",
            "s1shell intel rdap example.com",
            "s1shell intel lookup example.com --sources vt,greynoise,urlscan,rdap",
            "s1shell intel advisory --ecosystem pip --package requests",
        ),
    ),
    ModuleGuide(
        name="cve",
        group="Passive OSINT, CVE & SBOM",
        network="Public CVE/OSV Feeds (Zero Target Contact)",
        summary=(
            "NVD 2.0 + CVE.org + GHSA + CISA KEV + FIRST EPSS research and recursive "
            "14-format lockfile & CycloneDX/SPDX SBOM auditing via OSV.dev."
        ),
        usage="s1shell cve <search|get|audit|cache> [options]",
        subcommands=(
            SubcommandGuide(
                "search",
                "s1shell cve search [--keyword STR | --cpe CPE | --from-fingerprint FILE]",
                "Search NVD 2.0 with CVSS/severity/date filters and KEV/EPSS enrichment.",
                (
                    's1shell cve search --keyword "nginx 1.18" --min-cvss 7.0 --enrich',
                    "s1shell cve search --from-fingerprint ./results/fingerprint.json --kev-only",
                ),
            ),
            SubcommandGuide(
                "get",
                "s1shell cve get <CVE-ID> [CVE-ID ...] [--enrich]",
                "Fetch one or more CVE IDs with SSVC priority, KEV, EPSS, & GHSA data.",
                ("s1shell cve get CVE-2021-44228 CVE-2024-3094 --enrich",),
            ),
            SubcommandGuide(
                "audit",
                "s1shell cve audit <lockfile|sbom|dir> [--recursive] [--enrich] [--fail-on SEV]",
                "Audit lockfiles (requirements.txt, package-lock, uv.lock, etc.) & SBOMs via OSV.",
                (
                    "s1shell cve audit requirements.txt --enrich",
                    "s1shell cve audit ./repo --recursive --fail-on HIGH --format sarif",
                ),
            ),
            SubcommandGuide(
                "cache",
                "s1shell cve cache clear",
                "Clear local SQLite CVE/OSV/intel cache entries.",
                ("s1shell cve cache clear",),
            ),
        ),
        key_flags=("--enrich", "--kev-only", "--recursive", "--fail-on", "--offline", "--refresh"),
        examples=(
            "s1shell cve get CVE-2021-44228 --enrich",
            's1shell cve search --keyword "openssl 3.0" --severity HIGH --enrich',
            "s1shell cve audit ./project --recursive --enrich --fail-on HIGH",
        ),
    ),
    ModuleGuide(
        name="ai",
        group="Defensive AI, Offline Codec, Reports & MCP",
        network="Built-in Offline / Local Ollama / Cloud LLM",
        summary=(
            "Defensive AI engine with built-in offline synthesizer, Ollama, Anthropic, "
            "OpenAI-compat & Gemini, 9+ skills, pipelines, NDA redaction, ReAct & chat."
        ),
        usage="s1shell ai <env|skills|analyze|investigate|chat> [options]",
        subcommands=(
            SubcommandGuide(
                "env",
                "s1shell ai env [--provider PROVIDER] [--model MODEL] [--set-key KEY]",
                (
                    "Inspect or persist AI provider "
                    "(builtin, ollama, anthropic, openai_compat, gemini)."
                ),
                (
                    "s1shell ai env",
                    "s1shell ai env --provider builtin",
                    "s1shell ai env --provider ollama --model llama3.1:8b",
                ),
            ),
            SubcommandGuide(
                "skills",
                "s1shell ai skills <list | show SKILL_ID>",
                "List or inspect bundled & custom (~/.s1shell/skills.d/*.yaml) AI skills.",
                ("s1shell ai skills list", "s1shell ai skills show attack-path-modeling"),
            ),
            SubcommandGuide(
                "analyze",
                "s1shell ai analyze --input FILE [--skill ID] [--pipeline NAME] [--redact]",
                "Run defensive AI triage, attack-path modeling, or structured JSON analysis.",
                (
                    (
                        "s1shell ai analyze --input ./results/target/assess.json "
                        "--skill attack-path-modeling --provider builtin"
                    ),
                    (
                        "s1shell ai analyze --input ./results/target/assess.json "
                        "--pipeline purple-team --redact --restore --format md"
                    ),
                ),
            ),
            SubcommandGuide(
                "investigate",
                's1shell ai investigate --input DIR --goal "..." [--max-steps 5]',
                "Run bounded (1-8 step) read-only ReAct investigation over saved artifacts.",
                ('s1shell ai investigate --input ./results/target --goal "Prioritize top risks"',),
            ),
            SubcommandGuide(
                "chat",
                "s1shell ai chat --input FILE [--skill ID]",
                "Interactive multi-turn defensive AI copilot (/skill, /verify, /save, /exit).",
                ("s1shell ai chat --input ./results/target/assess.json --redact --restore",),
            ),
        ),
        key_flags=(
            "--provider {builtin,ollama,anthropic,openai_compat,gemini}",
            "--skill ID",
            "--pipeline {deep-triage,purple-team,executive-pack}",
            "--structured",
            "--redact --restore",
            "--local-only",
        ),
        examples=(
            "s1shell ai skills list",
            (
                "s1shell ai analyze --input ./results/target/assess.json "
                "--skill attack-path-modeling --provider builtin"
            ),
            "s1shell ai chat --input ./results/target/assess.json --skill zero-trust-hardening",
        ),
    ),
    ModuleGuide(
        name="codec",
        group="Defensive AI, Offline Codec, Reports & MCP",
        network="Offline (Zero Network)",
        summary=(
            "CyberChef-style offline decoder (25 codecs + auto magic peeling), encoder, "
            "smart JWT/X.509/hash/epoch inspector, and multi-algorithm file/text hasher."
        ),
        usage="s1shell codec <decode|encode|inspect|hash> [INPUT | --file FILE]",
        subcommands=(
            SubcommandGuide(
                "decode",
                "s1shell codec decode [INPUT] [-e auto|base64|hex|url|jwt|saml|...] [--chain ...]",
                "Decode single, chained, or auto-peeled nested encodings offline.",
                (
                    's1shell codec decode "SGVsbG8gUzFzaGVsbA=="',
                    's1shell codec decode "aHR0cHM6Ly9leGFtcGxlLmNvbQ==" --raw',
                ),
            ),
            SubcommandGuide(
                "encode",
                "s1shell codec encode [INPUT] [-e CODEC | --chain c1,c2] [--raw]",
                "Encode text or files using single codec or ordered chain pipeline.",
                ('s1shell codec encode "hello" -e base64url --raw',),
            ),
            SubcommandGuide(
                "inspect",
                "s1shell codec inspect [INPUT | --file FILE]",
                "Smart inspector for JWT claims, X.509 PEM/DER certs, hashes, epochs & entropy.",
                ("s1shell codec inspect --file cert.pem",),
            ),
            SubcommandGuide(
                "hash",
                "s1shell codec hash [INPUT | --file FILE] [--algos md5,sha256,...]",
                "Compute MD5, SHA-1, SHA-256, SHA-384, SHA-512, BLAKE2b, CRC32 & entropy.",
                ("s1shell codec hash --file ./results/target/report.html",),
            ),
        ),
        key_flags=("-e / --encoding", "--chain", "--file FILE", "--raw", "--all-shifts"),
        examples=(
            's1shell codec decode "SGVsbG8gUzFzaGVsbA=="',
            's1shell codec encode "s1shell" --chain gzip,base64url --raw',
            "s1shell codec inspect --file cert.pem",
            "s1shell codec hash --file ./README.md",
        ),
    ),
    ModuleGuide(
        name="report",
        group="Defensive AI, Offline Codec, Reports & MCP",
        network="Offline (Zero Network)",
        summary=(
            "Compile profile, fingerprint, CVE, intel, and assess JSON artifacts into "
            "executive HTML, Markdown, JSON, or GitHub Code Scanning SARIF 2.1.0."
        ),
        usage="s1shell report build --input FILE [--input FILE ...] --format html|md|json|sarif",
        subcommands=(
            SubcommandGuide(
                "build",
                "s1shell report build --input FILE [--operator NAME] [--format html|md|json|sarif]",
                "Auto-detect artifact types and compile a unified assessment report.",
                (
                    (
                        "s1shell report build --input ./results/target/assess.json "
                        '--operator "Willy Gailo" --format html --out report.html'
                    ),
                ),
            ),
        ),
        key_flags=(
            "--input FILE",
            "--operator NAME",
            "--format {md,html,json,sarif}",
            "--out FILE",
        ),
        examples=(
            (
                "s1shell report build --input ./results/target/profile.json "
                "--input ./results/target/fingerprint.json --input ./results/target/cves.json "
                "--format html --out executive-report.html"
            ),
        ),
    ),
    ModuleGuide(
        name="mcp",
        group="Defensive AI, Offline Codec, Reports & MCP",
        network="Online Streamable HTTP / Local Stdio",
        summary=(
            "MCP 2025-03-26 server exposing 23 read-only tools (+3 opt-in scoped target "
            "tools), 4 Resources, & 9+ Prompts, plus client config generator & live ping."
        ),
        usage="s1shell mcp <serve|config|ping> [options]",
        subcommands=(
            SubcommandGuide(
                "serve",
                "s1shell mcp serve [--transport stdio|http] [--host IP] [--port PORT]",
                "Start local stdio or hardened online Streamable HTTP MCP server.",
                (
                    "s1shell mcp serve",
                    "s1shell mcp serve --transport http --port 8765 --generate-token",
                ),
            ),
            SubcommandGuide(
                "config",
                "s1shell mcp config [antigravity|claude|cursor|vscode|windsurf|http]",
                "Print ready-to-paste JSON config for AI IDEs and MCP clients.",
                (
                    "s1shell mcp config antigravity --transport http --url "
                    "http://127.0.0.1:8765/mcp",
                ),
            ),
            SubcommandGuide(
                "ping",
                "s1shell mcp ping [--url URL] [--token TOKEN]",
                "Verify /healthz, handshake, and exposed capabilities of a running HTTP MCP.",
                ("s1shell mcp ping --url http://127.0.0.1:8765/mcp",),
            ),
        ),
        key_flags=(
            "--transport {stdio,http}",
            "--host / --port",
            "--token / --generate-token",
            "--allow-origin URL",
            "--allow-scoped-targets --authorized",
        ),
        examples=(
            "s1shell mcp serve --transport http --host 127.0.0.1 --port 8765 --generate-token",
            "s1shell mcp config antigravity --transport stdio",
            "s1shell mcp ping --url http://127.0.0.1:8765/mcp",
        ),
    ),
    ModuleGuide(
        name="scope",
        group="Setup, Scope Governance & Diagnostics",
        network="Offline (DNS on `check` only)",
        summary=(
            "Fail-closed authorization scope manager supporting domains, *.wildcards, "
            "leading-dot TLDs (.com, .ph), IPs, CIDRs, URL prefixes, v3 .onion & exclusions."
        ),
        usage="s1shell scope <add|import|list|check|remove|expire> [options]",
        subcommands=(
            SubcommandGuide(
                "add",
                "s1shell scope add <target> --owner NAME --ref ID --expires YYYY-MM-DD",
                "Add an authorized allow rule (or --exclude deny rule).",
                (
                    (
                        's1shell scope add example.com --owner "Acme Corp" '
                        '--ref "SOW-2026-01" --expires 2026-12-31 --include-subdomains'
                    ),
                    (
                        's1shell scope add admin.example.com --owner "Acme Corp" '
                        '--ref "SOW-2026-01" --expires 2026-12-31 --exclude'
                    ),
                ),
            ),
            SubcommandGuide(
                "import",
                "s1shell scope import <file> --owner NAME --ref ID --expires YYYY-MM-DD",
                "Bulk-import targets from a newline file (`!` prefix = exclude, `--dry-run`).",
                (
                    (
                        's1shell scope import targets.txt --owner "Acme" '
                        '--ref "SOW-01" --expires 2026-12-31 --dry-run'
                    ),
                ),
            ),
            SubcommandGuide("list", "s1shell scope list", "List all configured scope rules."),
            SubcommandGuide(
                "check",
                "s1shell scope check <target>",
                "Verify if a URL, domain, IP, or .onion is currently allowed in scope.",
                ("s1shell scope check https://example.com",),
            ),
            SubcommandGuide(
                "remove",
                "s1shell scope remove <id|target>",
                "Delete a scope rule by entry ID or exact target string.",
                ("s1shell scope remove example.com",),
            ),
            SubcommandGuide(
                "expire",
                "s1shell scope expire [--prune]",
                "Show expired entries or remove them with --prune.",
                ("s1shell scope expire --prune",),
            ),
        ),
        key_flags=(
            "--owner",
            "--ref",
            "--expires YYYY-MM-DD",
            "--include-subdomains",
            "--exclude",
            "--replace",
            "--dry-run",
        ),
        examples=(
            "s1shell scope list",
            (
                's1shell scope add example.com --owner "Client" --ref "SOW-01" '
                "--expires 2026-12-31 --include-subdomains"
            ),
            "s1shell scope check https://example.com",
        ),
    ),
    ModuleGuide(
        name="doctor",
        group="Setup, Scope Governance & Diagnostics",
        network="Offline (Local Diagnostics)",
        summary=(
            "Check Python version, ~/.s1shell permissions, scope.yaml, audit.log SHA-256 "
            "integrity, cache.db, signatures, AI provider/skills, API keys & Tor readiness."
        ),
        usage="s1shell doctor [--format table|json|md]",
        key_flags=("--format {table,json,md}", "--out FILE", "--no-color"),
        examples=(
            "s1shell doctor",
            "s1shell doctor --format json",
        ),
    ),
    ModuleGuide(
        name="audit",
        group="Setup, Scope Governance & Diagnostics",
        network="Offline (Local Tamper-Evident Log)",
        summary=(
            "Inspect recent events and cryptographically verify the fcntl-locked "
            "SHA-256 hash chain in ~/.s1shell/audit.log."
        ),
        usage="s1shell audit <list|verify> [options]",
        subcommands=(
            SubcommandGuide(
                "list",
                "s1shell audit list [--limit N] [--category target|intel|scope] [--outcome ...]",
                "Display filtered recent audit log records.",
                ("s1shell audit list --limit 25", "s1shell audit list --category target"),
            ),
            SubcommandGuide(
                "verify",
                "s1shell audit verify",
                "Verify full SHA-256 hash chain integrity of audit.log offline.",
                ("s1shell audit verify",),
            ),
        ),
        key_flags=("--limit N", "--category", "--outcome", "--command", "--target"),
        examples=(
            "s1shell audit list --limit 20",
            "s1shell audit verify",
        ),
    ),
    ModuleGuide(
        name="tor",
        group="Setup, Scope Governance & Diagnostics",
        network="Offline (`status`) / Tor Egress (`check`)",
        summary=(
            "Verify local Tor SOCKS5h daemon & socksio readiness (`status`) or confirm "
            "live Tor exit egress via check.torproject.org (`check`, fail-closed)."
        ),
        usage="s1shell tor <status|check> [--tor-proxy socks5h://127.0.0.1:9050]",
        subcommands=(
            SubcommandGuide(
                "status",
                "s1shell tor status",
                "Offline check for local tor binary, socksio dependency, & loopback port.",
                ("s1shell tor status",),
            ),
            SubcommandGuide(
                "check",
                "s1shell tor check",
                "Live Tor exit verification over SOCKS5h with zero clearnet fallback.",
                ("s1shell tor check",),
            ),
        ),
        key_flags=("--tor-proxy URL", "--format {table,json,md}"),
        examples=(
            "s1shell tor status",
            "s1shell tor check",
            "s1shell intel ct example.com --tor",
        ),
    ),
    ModuleGuide(
        name="scan",
        group="Passive OSINT, CVE & SBOM",
        network="Offline (Zero Network)",
        summary=(
            "Offline local security scanner: redacted secret/credential leak detection "
            "(filesystem & git diffs), IaC/config auditing "
            "(Dockerfile/K8s/GHA/Compose/NGINX/SSHd), "
            "and CycloneDX 1.5 SBOM generation."
        ),
        usage="s1shell scan <secrets|config|sbom> [path] [options]",
        subcommands=(
            SubcommandGuide(
                name="secrets",
                usage=(
                    "s1shell scan secrets [path] [--git-staged | --git-diff REF] [--fail-on SEV] "
                    "[--format sarif]"
                ),
                summary=(
                    "Detect 27+ secret & credential patterns with redaction, entropy checks & git "
                    "diff support."
                ),
                examples=(
                    "s1shell scan secrets .",
                    "s1shell scan secrets . --git-staged --fail-on HIGH",
                    "s1shell scan secrets ./repo --format sarif --out secrets.sarif",
                ),
            ),
            SubcommandGuide(
                name="config",
                usage="s1shell scan config [path] [--fail-on SEV] [--format table|json|md|sarif]",
                summary=(
                    "Audit Dockerfiles, K8s YAML, GitHub Actions, Docker Compose, NGINX, SSHd & "
                    ".env."
                ),
                examples=(
                    "s1shell scan config .",
                    "s1shell scan config ./deploy --fail-on HIGH --format sarif --out iac.sarif",
                ),
            ),
            SubcommandGuide(
                name="sbom",
                usage="s1shell scan sbom [path] [--raw-bom] [--out sbom.cdx.json]",
                summary=(
                    "Generate a CycloneDX 1.5 JSON SBOM from local lockfiles, manifests & "
                    "Dockerfiles."
                ),
                examples=(
                    "s1shell scan sbom . --raw-bom --out sbom.cdx.json",
                    "s1shell cve audit sbom.cdx.json --enrich",
                ),
            ),
        ),
        key_flags=(
            "--git-staged",
            "--git-diff REF",
            "--no-gitignore",
            "--fail-on SEV",
            "--raw-bom",
        ),
        examples=(
            "s1shell scan secrets . --git-staged --fail-on HIGH",
            "s1shell scan config . --format sarif --out iac.sarif",
            "s1shell scan sbom . --raw-bom --out sbom.cdx.json",
        ),
    ),
    ModuleGuide(
        name="analyze",
        group="Defensive AI, Offline Codec, Reports & MCP",
        network="Offline (Optional Passive DNS for `email`)",
        summary=(
            "Deep security analyzers: CSP3 bypass-gadget evaluator, SPF/DMARC/DKIM key-strength "
            "auditor, offline raw HTTP header posture scorer, and FIRST CVSS v3.x/v4.0 calculator."
        ),
        usage="s1shell analyze <csp|email|headers|cvss> [args]",
        subcommands=(
            SubcommandGuide(
                name="csp",
                usage='s1shell analyze csp "<policy>" | --from-profile profile.json',
                summary=(
                    "Audit CSP3 directives, JSONP/CDN bypass hosts, nonces, duplicates & get "
                    "hardened rewrite."
                ),
                examples=(
                    "s1shell analyze csp \"default-src 'self'; script-src 'unsafe-inline' "
                    'https://cdn.jsdelivr.net"',
                    "s1shell analyze csp --from-profile ./results/target/assess.json",
                ),
            ),
            SubcommandGuide(
                name="email",
                usage=(
                    "s1shell analyze email <domain> [--spf REC] [--dmarc REC] [--dkim REC] "
                    "[--selector SEL]"
                ),
                summary=(
                    "Audit SPF lookup budget & IPv4 blast radius, DMARC alignment, and DKIM "
                    "RSA/Ed25519 key bits."
                ),
                examples=(
                    "s1shell analyze email example.com --selector google",
                    's1shell analyze email example.com --offline --spf "v=spf1 +all" --dmarc '
                    '"v=DMARC1; p=none"',
                ),
            ),
            SubcommandGuide(
                name="headers",
                usage=(
                    "s1shell analyze headers --file headers.txt [--url URL] [--preset "
                    "web|api|strict]"
                ),
                summary=(
                    "Run full security header, CSP3, cookie, CORS & stack fingerprint audit "
                    "offline."
                ),
                examples=(
                    "curl -sI https://example.com | s1shell analyze headers -",
                    "s1shell analyze headers --file captured-headers.txt --preset strict",
                ),
            ),
            SubcommandGuide(
                name="cvss",
                usage='s1shell analyze cvss "<CVSS:3.1/...>"',
                summary=(
                    "Decode & compute FIRST CVSS v3.0/v3.1 Base/Temporal/Environmental and v4.0 "
                    "vectors."
                ),
                examples=(
                    's1shell analyze cvss "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"',
                    "s1shell analyze cvss "
                    '"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C"',
                ),
            ),
        ),
        key_flags=(
            "--file FILE",
            "--from-profile FILE",
            "--spf",
            "--dmarc",
            "--dkim",
            "--selector",
            "--offline",
            "--preset",
        ),
        examples=(
            "s1shell analyze csp \"default-src 'self'; script-src https://unpkg.com\"",
            "s1shell analyze email example.com --selector default",
            's1shell analyze cvss "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"',
        ),
    ),
    ModuleGuide(
        name="completion",
        group="Setup, Scope Governance & Diagnostics",
        network="Offline (Zero Network)",
        summary="Generate shell tab-completion scripts for bash, zsh, or fish.",
        usage="s1shell completion <bash|zsh|fish>",
        key_flags=("--out FILE",),
        examples=(
            "s1shell completion bash > ~/.local/share/bash-completion/completions/s1shell",
            "s1shell completion zsh > ~/.zsh/completions/_s1shell",
            "s1shell completion fish > ~/.config/fish/completions/s1shell.fish",
        ),
    ),
    ModuleGuide(
        name="check",
        group="Setup, Scope Governance & Diagnostics",
        network="Offline (Local Diagnostics + Guide)",
        summary=(
            "Run full local readiness check (`doctor`) AND display the complete S1shell "
            "CLI usage guide, quickstart workflows, flags, and exit codes."
        ),
        usage="s1shell --check [--format table|md|json] [--out FILE]",
        key_flags=("--format {table,md,json}", "--out FILE", "--no-color"),
        examples=(
            "s1shell --check",
            "s1shell check --format md --out S1SHELL_CHECK.md",
            "s1shell --check --format json",
        ),
    ),
    ModuleGuide(
        name="help",
        group="Setup, Scope Governance & Diagnostics",
        network="Offline (Zero Network)",
        summary=(
            "Interactive CLI manual: browse all modules, inspect one module or subcommand "
            "in depth, or export the full guide (`--all --format md`)."
        ),
        usage="s1shell help [module] [subcommand] [--all] [--format table|md|json]",
        key_flags=("--all", "--format {table,md,json}", "--out FILE", "--no-color"),
        examples=(
            "s1shell help",
            "s1shell help assess",
            "s1shell help cve audit",
            "s1shell help --all --format md --out S1SHELL_GUIDE.md",
        ),
    ),
)

_MODULE_MAP: dict[str, ModuleGuide] = {guide.name: guide for guide in MODULE_GUIDES}

WORKFLOW_GUIDES: tuple[WorkflowGuide, ...] = (
    WorkflowGuide(
        title="1. End-to-End Authorized Target Assessment",
        description="Verify setup, authorize scope, run unified assessment, remediate & audit.",
        commands=(
            "s1shell --check",
            (
                's1shell scope add example.com --owner "Client" --ref "SOW-2026" '
                "--expires 2026-12-31 --include-subdomains"
            ),
            (
                "s1shell assess https://example.com --authorized --enrich-cve --intel "
                "--well-known --check-methods --out-dir ./results/example"
            ),
            "s1shell remediate ./results/example/assess.json --stack auto",
            "s1shell audit verify",
        ),
    ),
    WorkflowGuide(
        title="2. Zero-Target-Contact Passive OSINT & SBOM Audit",
        description="Gather CT subdomains, RDAP, threat intel, & audit project dependencies.",
        commands=(
            "s1shell intel ct example.com --export-candidates candidates.txt",
            "s1shell intel rdap example.com",
            "s1shell intel lookup example.com --sources vt,greynoise,urlscan,rdap",
            "s1shell cve audit ./project --recursive --enrich --fail-on HIGH",
        ),
    ),
    WorkflowGuide(
        title="3. Defensive AI Triage, Offline Codec & Posture Drift",
        description="Synthesize attack paths offline/locally, decode artifacts, & diff retests.",
        commands=(
            (
                "s1shell ai analyze --input ./results/example/assess.json "
                "--skill attack-path-modeling --provider builtin"
            ),
            's1shell codec decode "SGVsbG8gUzFzaGVsbA=="',
            (
                "s1shell diff ./results/base/assess.json ./results/retest/assess.json "
                "--fail-on-regression"
            ),
        ),
    ),
    WorkflowGuide(
        title="4. Online Streamable HTTP MCP & Zero-Leak Tor Routing",
        description="Expose S1shell tools over MCP or route passive/target traffic through Tor.",
        commands=(
            "s1shell mcp serve --transport http --host 127.0.0.1 --port 8765 --generate-token",
            "s1shell mcp config antigravity --transport http --url http://127.0.0.1:8765/mcp",
            "s1shell tor status && s1shell intel ct example.com --tor",
        ),
    ),
)


def get_module_guide(module_name: str) -> ModuleGuide | None:
    """Look up a module guide by name (case-insensitive)."""
    return _MODULE_MAP.get(module_name.strip().lower())


def build_parser_epilog(module_name: str) -> str:
    """Build a formatted argparse `epilog` with real CLI examples and developer credit."""
    guide = get_module_guide(module_name)
    if guide is None:
        return f"S1shell v{__version__} | {DEV_CREDIT}"
    lines: list[str] = []
    if guide.subcommands:
        lines.append("Subcommands:")
        for sc in guide.subcommands:
            lines.append(f"  {sc.name:<12} {sc.summary}")
        lines.append("")
    if guide.examples:
        lines.append("Examples:")
        for ex in guide.examples:
            lines.append(f"  $ {ex}")
        lines.append("")
    lines.append(f"More details: `s1shell help {guide.name}` | Full guide: `s1shell --check`")
    lines.append(f"S1shell v{__version__} | {DEV_CREDIT}")
    return "\n".join(lines)


def build_subcommand_epilog(module_name: str, subcommand_name: str) -> str:
    """Build a focused argparse `epilog` for a nested subcommand."""
    guide = get_module_guide(module_name)
    lines: list[str] = []
    if guide is not None:
        for sc in guide.subcommands:
            if sc.name == subcommand_name:
                if sc.examples:
                    lines.append("Examples:")
                    for ex in sc.examples:
                        lines.append(f"  $ {ex}")
                    lines.append("")
                break
    lines.append(
        f"More details: `s1shell help {module_name} {subcommand_name}` | "
        f"Full guide: `s1shell --check`"
    )
    lines.append(f"S1shell v{__version__} | {DEV_CREDIT}")
    return "\n".join(lines)


def _find_subparser(
    parser: argparse.ArgumentParser | None,
    module_name: str,
    subcommand_name: str | None = None,
) -> argparse.ArgumentParser | None:
    """Safely locate an argparse subparser for live flag introspection."""
    if parser is None:
        return None

    def _child(parent: argparse.ArgumentParser, name: str) -> argparse.ArgumentParser | None:
        for action in parent._actions:
            choices = getattr(action, "choices", None)
            if isinstance(choices, dict):
                candidate = choices.get(name)
                if isinstance(candidate, argparse.ArgumentParser):
                    return candidate
        return None

    mod_parser = _child(parser, module_name)
    if mod_parser is None or not subcommand_name:
        return mod_parser
    return _child(mod_parser, subcommand_name)


def _extract_parser_options(target_parser: argparse.ArgumentParser | None) -> list[tuple[str, str]]:
    """Extract live `(flag_or_arg, help_text)` rows from an argparse parser."""
    if target_parser is None:
        return []
    rows: list[tuple[str, str]] = []
    seen: set[str] = set()
    for action in target_parser._actions:
        if action.help == argparse.SUPPRESS:
            continue
        if isinstance(getattr(action, "choices", None), dict):
            continue
        if action.option_strings:
            label = ", ".join(action.option_strings)
            if action.metavar:
                label = f"{label} {action.metavar}"
            elif action.choices and not isinstance(action.choices, dict):
                joined = ",".join(str(c) for c in action.choices)
                label = f"{label} {{{joined}}}"
        else:
            label = str(action.metavar or action.dest)
        if label in seen:
            continue
        seen.add(label)
        rows.append((label, str(action.help or "")))
    return rows


def _banner_panel() -> Panel:
    title = Text()
    title.append("S1shell ", style="bold cyan")
    title.append(f"v{__version__}", style="bold green")
    title.append("  |  ", style="dim")
    title.append(DEV_CREDIT, style="bold yellow")

    body = Text()
    body.append(
        "Authorized Defensive Security Assessment, Passive OSINT, SBOM Audit, AI & MCP Toolkit\n",
        style="bold white",
    )
    body.append(
        "Fail-Closed Policy Gate: Scope -> Authorization (--authorized) -> "
        "IP Pinning / Tor SOCKS5h -> SHA-256 Audit Log\n",
        style="dim",
    )
    body.append("Quick Commands: ", style="bold cyan")
    body.append("s1shell --check", style="green")
    body.append("  ·  ", style="dim")
    body.append("s1shell help <module>", style="green")
    body.append("  ·  ", style="dim")
    body.append("s1shell help --all", style="green")
    body.append("  ·  ", style="dim")
    body.append("s1shell --version", style="green")
    return Panel(body, title=title, border_style="cyan", expand=False)


def _renderables_to_output(
    renderables: list[Any],
    *,
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    if out_file is not None:
        buf_console = Console(no_color=True, width=120)
        with buf_console.capture() as cap:
            for item in renderables:
                buf_console.print(item)
        write_or_print(cap.get(), out_file=out_file, stdout=stdout)
        return
    for item in renderables:
        console.print(item)


def _guide_json_payload(*, doctor_report: DoctorReport | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "tool": "s1shell",
        "version": __version__,
        "developer": __developer__,
        "credit": DEV_CREDIT,
        "modules": [
            {
                "name": g.name,
                "group": g.group,
                "network": g.network,
                "summary": g.summary,
                "usage": g.usage,
                "subcommands": [
                    {
                        "name": s.name,
                        "usage": s.usage,
                        "summary": s.summary,
                        "examples": list(s.examples),
                    }
                    for s in g.subcommands
                ],
                "key_flags": list(g.key_flags),
                "examples": list(g.examples),
            }
            for g in MODULE_GUIDES
        ],
        "workflows": [
            {
                "title": w.title,
                "description": w.description,
                "commands": list(w.commands),
            }
            for w in WORKFLOW_GUIDES
        ],
        "global_flags": [{"flag": f, "description": d} for f, d in GLOBAL_FLAGS],
        "exit_codes": [{"code": c, "meaning": m} for c, m in EXIT_CODES],
    }
    if doctor_report is not None:
        payload["doctor"] = doctor_report
    return payload


def _build_overview_markdown(*, include_all_details: bool = False) -> list[str]:
    lines: list[str] = [
        f"# S1shell v{__version__} — CLI Usage Guide ({DEV_CREDIT})",
        "",
        (
            "> Authorized Defensive Security Assessment, Passive OSINT, SBOM Audit, "
            "Defensive AI & Online MCP CLI Toolkit"
        ),
        "",
        "## Quickstart Workflows",
        "",
    ]
    for wf in WORKFLOW_GUIDES:
        lines.append(f"### {wf.title}")
        lines.append(wf.description)
        lines.append("")
        lines.append("```bash")
        lines.extend(wf.commands)
        lines.append("```")
        lines.append("")

    lines.append("## CLI Modules & Commands")
    lines.append("")
    for group in GROUP_ORDER:
        lines.append(f"### {group}")
        lines.append("")
        lines.append("| Module | Subcommands | Network | Description |")
        lines.append("|---|---|---|---|")
        for g in MODULE_GUIDES:
            if g.group != group:
                continue
            subs = ", ".join(f"`{s.name}`" for s in g.subcommands) or "*(direct)*"
            lines.append(f"| `s1shell {g.name}` | {subs} | {g.network} | {g.summary} |")
        lines.append("")

    if include_all_details:
        lines.append("## Complete Module Reference & Examples")
        lines.append("")
        for g in MODULE_GUIDES:
            lines.append(f"### `s1shell {g.name}` — {g.group}")
            lines.append(f"- **Usage:** `{g.usage}`")
            lines.append(f"- **Network:** {g.network}")
            lines.append(f"- **Description:** {g.summary}")
            if g.subcommands:
                lines.append("- **Subcommands:**")
                for sc in g.subcommands:
                    lines.append(f"  - `{sc.name}` (`{sc.usage}`): {sc.summary}")
            if g.key_flags:
                lines.append(f"- **Key Flags:** {', '.join(f'`{f}`' for f in g.key_flags)}")
            if g.examples:
                lines.append("")
                lines.append("```bash")
                lines.extend(g.examples)
                lines.append("```")
            lines.append("")

    lines.extend(
        [
            "## Global Flags",
            "",
            "| Flag | Description |",
            "|---|---|",
        ]
    )
    for flag, desc in GLOBAL_FLAGS:
        lines.append(f"| `{flag}` | {desc} |")

    lines.extend(
        [
            "",
            "## Exit Codes",
            "",
            "| Code | Meaning |",
            "|---|---|",
        ]
    )
    for code, meaning in EXIT_CODES:
        lines.append(f"| `{code}` | {meaning} |")

    lines.extend(["", "---", f"*{DEV_CREDIT} · S1shell v{__version__}*"])
    return lines


def _build_overview_renderables() -> list[Any]:
    renderables: list[Any] = [_banner_panel()]

    for group in GROUP_ORDER:
        tbl = Table(title=f"[bold cyan]{group}[/bold cyan]", expand=True)
        tbl.add_column("Module", style="bold cyan", no_wrap=True)
        tbl.add_column("Subcommands", style="green", ratio=2)
        tbl.add_column("Network", style="yellow", ratio=2)
        tbl.add_column("What It Does", ratio=4)
        for g in MODULE_GUIDES:
            if g.group != group:
                continue
            subs = " | ".join(s.name for s in g.subcommands) if g.subcommands else "(direct)"
            tbl.add_row(f"s1shell {g.name}", subs, g.network, g.summary)
        renderables.append(tbl)

    wf_tbl = Table(title="[bold green]Quickstart Workflows (Copy & Run)[/bold green]", expand=True)
    wf_tbl.add_column("Workflow", style="bold cyan", ratio=2)
    wf_tbl.add_column("Commands", style="white", ratio=5)
    for wf in WORKFLOW_GUIDES:
        cmd_block = "\n".join(f"$ {cmd}" for cmd in wf.commands)
        wf_tbl.add_row(f"{wf.title}\n[dim]{wf.description}[/dim]", cmd_block)
    renderables.append(wf_tbl)

    flags_tbl = Table(title="[bold]Common Global Flags (Before or After Subcommands)[/bold]")
    flags_tbl.add_column("Flag", style="cyan", no_wrap=True)
    flags_tbl.add_column("Description")
    for flag, desc in GLOBAL_FLAGS:
        flags_tbl.add_row(flag, desc)
    renderables.append(flags_tbl)

    exit_tbl = Table(title="[bold]POSIX Exit Codes[/bold]")
    exit_tbl.add_column("Code", style="bold yellow", justify="right", no_wrap=True)
    exit_tbl.add_column("Meaning")
    for code, meaning in EXIT_CODES:
        exit_tbl.add_row(code, meaning)
    renderables.append(exit_tbl)

    tip = Text()
    tip.append("Tip: ", style="bold cyan")
    tip.append("Run ")
    tip.append("s1shell help <module>", style="bold green")
    tip.append(" (e.g. `s1shell help assess` or `s1shell help cve audit`) for flags & examples, ")
    tip.append("s1shell help --all", style="bold green")
    tip.append(" for the full manual, or ")
    tip.append("s1shell --check", style="bold green")
    tip.append(f" for live diagnostics + guide.  [{DEV_CREDIT}]", style="dim")
    renderables.append(tip)
    return renderables


def render_cli_guide(
    *,
    fmt: str = "table",
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Render the S1shell CLI overview, module directory, workflows, flags, and exit codes."""
    norm = fmt.lower()
    if norm not in ("table", "md", "json"):
        raise ValidationError(f"Unsupported format '{fmt}' for `help`. Choose table, json, or md.")
    if norm == "json":
        write_or_print(dumps_json(_guide_json_payload()), out_file=out_file, stdout=stdout)
        return
    if norm == "md":
        write_or_print(
            "\n".join(_build_overview_markdown(include_all_details=False)),
            out_file=out_file,
            stdout=stdout,
        )
        return
    _renderables_to_output(
        _build_overview_renderables(), console=console, out_file=out_file, stdout=stdout
    )


def render_full_manual(
    *,
    fmt: str = "table",
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Render the complete S1shell CLI manual covering every module, subcommand, and example."""
    norm = fmt.lower()
    if norm not in ("table", "md", "json"):
        raise ValidationError(
            f"Unsupported format '{fmt}' for `help --all`. Choose table, json, or md."
        )
    if norm == "json":
        write_or_print(dumps_json(_guide_json_payload()), out_file=out_file, stdout=stdout)
        return
    if norm == "md":
        write_or_print(
            "\n".join(_build_overview_markdown(include_all_details=True)),
            out_file=out_file,
            stdout=stdout,
        )
        return

    renderables = _build_overview_renderables()
    detail_tbl = Table(
        title=f"[bold cyan]Complete Command & Example Reference ({DEV_CREDIT})[/bold cyan]",
        expand=True,
    )
    detail_tbl.add_column("Module / Usage", style="bold cyan")
    detail_tbl.add_column("Subcommands & Key Flags", style="green")
    detail_tbl.add_column("Examples")
    for g in MODULE_GUIDES:
        sub_lines = [f"• {s.name}: {s.summary}" for s in g.subcommands]
        if g.key_flags:
            sub_lines.append(f"Flags: {', '.join(g.key_flags)}")
        ex_block = "\n".join(f"$ {e}" for e in g.examples) or f"$ {g.usage}"
        detail_tbl.add_row(
            f"{g.name}\n[dim]{g.usage}[/dim]",
            "\n".join(sub_lines) or "—",
            ex_block,
        )
    renderables.append(detail_tbl)
    _renderables_to_output(renderables, console=console, out_file=out_file, stdout=stdout)


def render_module_guide(
    module_name: str,
    *,
    subcommand_name: str | None = None,
    parser: argparse.ArgumentParser | None = None,
    fmt: str = "table",
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Render detailed help, live argparse flags, and examples for one module or subcommand."""
    guide = get_module_guide(module_name)
    if guide is None:
        available = ", ".join(g.name for g in MODULE_GUIDES)
        raise ValidationError(f"Unknown module '{module_name}'. Available modules: {available}")

    matched_sub: SubcommandGuide | None = None
    if subcommand_name:
        norm_sub = subcommand_name.strip().lower()
        for sc in guide.subcommands:
            if sc.name == norm_sub:
                matched_sub = sc
                break
        if matched_sub is None:
            valid_subs = ", ".join(s.name for s in guide.subcommands) or "none"
            raise ValidationError(
                f"Unknown subcommand '{subcommand_name}' for `s1shell {guide.name}`. "
                f"Available: {valid_subs}"
            )

    target_parser = _find_subparser(parser, guide.name, matched_sub.name if matched_sub else None)
    live_options = _extract_parser_options(target_parser)

    norm = fmt.lower()
    if norm not in ("table", "md", "json"):
        raise ValidationError(f"Unsupported format '{fmt}' for `help`. Choose table, json, or md.")

    if norm == "json":
        payload: dict[str, Any] = {
            "tool": "s1shell",
            "version": __version__,
            "developer": __developer__,
            "credit": DEV_CREDIT,
            "module": guide.name,
            "subcommand": matched_sub.name if matched_sub else None,
            "group": guide.group,
            "network": guide.network,
            "summary": matched_sub.summary if matched_sub else guide.summary,
            "usage": matched_sub.usage if matched_sub else guide.usage,
            "subcommands": [
                {
                    "name": s.name,
                    "usage": s.usage,
                    "summary": s.summary,
                    "examples": list(s.examples),
                }
                for s in guide.subcommands
            ],
            "options": [{"option": opt, "help": hlp} for opt, hlp in live_options],
            "examples": list(
                matched_sub.examples if matched_sub and matched_sub.examples else guide.examples
            ),
        }
        write_or_print(dumps_json(payload), out_file=out_file, stdout=stdout)
        return

    heading = f"s1shell {guide.name} {matched_sub.name}" if matched_sub else f"s1shell {guide.name}"
    usage_str = matched_sub.usage if matched_sub else guide.usage
    summary_str = matched_sub.summary if matched_sub else guide.summary
    examples = matched_sub.examples if matched_sub and matched_sub.examples else guide.examples

    if norm == "md":
        lines = [
            f"# `{heading}` — S1shell v{__version__} ({DEV_CREDIT})",
            "",
            f"- **Category:** {guide.group}",
            f"- **Network:** {guide.network}",
            f"- **Usage:** `{usage_str}`",
            f"- **Summary:** {summary_str}",
        ]
        if not matched_sub and guide.subcommands:
            lines.extend(
                ["", "## Subcommands", "", "| Subcommand | Usage | Summary |", "|---|---|---|"]
            )
            for sc in guide.subcommands:
                lines.append(f"| `{sc.name}` | `{sc.usage}` | {sc.summary} |")
        if live_options:
            lines.extend(
                ["", "## Options & Arguments", "", "| Option | Description |", "|---|---|"]
            )
            for opt, hlp in live_options:
                lines.append(f"| `{opt}` | {hlp} |")
        if examples:
            lines.extend(["", "## Examples", "", "```bash", *examples, "```"])
        write_or_print("\n".join(lines), out_file=out_file, stdout=stdout)
        return

    panel_body = Text()
    panel_body.append(f"{summary_str}\n", style="bold white")
    panel_body.append("Usage: ", style="bold cyan")
    panel_body.append(f"{usage_str}\n", style="green")
    panel_body.append("Category: ", style="bold cyan")
    panel_body.append(f"{guide.group}  |  ", style="white")
    panel_body.append("Network: ", style="bold cyan")
    panel_body.append(f"{guide.network}", style="yellow")

    panel_title = (
        f"[bold cyan]{heading}[/bold cyan] [dim](S1shell v{__version__} · {DEV_CREDIT})[/dim]"
    )
    renderables: list[Any] = [
        Panel(
            panel_body,
            title=panel_title,
            border_style="cyan",
            expand=False,
        )
    ]

    if not matched_sub and guide.subcommands:
        sub_tbl = Table(title="Subcommands", expand=True)
        sub_tbl.add_column("Subcommand", style="bold green", no_wrap=True)
        sub_tbl.add_column("Usage", style="cyan", ratio=3)
        sub_tbl.add_column("Description", ratio=4)
        for sc in guide.subcommands:
            sub_tbl.add_row(sc.name, sc.usage, sc.summary)
        renderables.append(sub_tbl)

    if live_options:
        opt_tbl = Table(title="Options & Arguments", expand=True)
        opt_tbl.add_column("Option / Arg", style="cyan", ratio=2, overflow="fold")
        opt_tbl.add_column("Description", ratio=4)
        for opt, hlp in live_options:
            opt_tbl.add_row(opt, hlp)
        renderables.append(opt_tbl)

    if examples:
        ex_text = "\n".join(f"$ {ex}" for ex in examples)
        renderables.append(
            Panel(
                ex_text,
                title="[bold green]Copy-Paste Examples[/bold green]",
                border_style="green",
            )
        )

    _renderables_to_output(renderables, console=console, out_file=out_file, stdout=stdout)


def render_check_report(
    doctor_report: DoctorReport,
    *,
    fmt: str = "table",
    console: Console,
    out_file: Path | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Render `s1shell --check`: live readiness diagnostics + complete CLI usage guide."""
    norm = fmt.lower()
    if norm not in ("table", "md", "json"):
        raise ValidationError(
            f"Unsupported format '{fmt}' for `--check`. Choose table, json, or md."
        )
    if norm == "json":
        write_or_print(
            dumps_json(_guide_json_payload(doctor_report=doctor_report)),
            out_file=out_file,
            stdout=stdout,
        )
        return
    if norm == "md":
        lines = [
            f"# S1shell Check & CLI Guide (`v{__version__}` · {DEV_CREDIT})",
            "",
            f"## Local Readiness Check (`healthy={doctor_report.healthy}`)",
            "",
            f"- **Home Dir:** `{doctor_report.home_dir}`",
            f"- **Developer:** {doctor_report.developer}",
            "",
            "| Check | Status | Detail |",
            "|---|---|---|",
        ]
        for chk in doctor_report.checks:
            lines.append(f"| `{chk.name}` | {chk.status.upper()} | {chk.detail} |")
        lines.append("")
        lines.extend(_build_overview_markdown(include_all_details=False))
        write_or_print("\n".join(lines), out_file=out_file, stdout=stdout)
        return

    renderables: list[Any] = [_banner_panel()]

    doc_tbl = Table(
        title=(
            f"[bold cyan]Local Readiness Check[/bold cyan] "
            f"(home={doctor_report.home_dir}, healthy={doctor_report.healthy}, {DEV_CREDIT})"
        ),
        expand=True,
    )
    doc_tbl.add_column("Check", style="cyan", no_wrap=True)
    doc_tbl.add_column("Status", no_wrap=True)
    doc_tbl.add_column("Detail")
    for chk in doctor_report.checks:
        st_upper = chk.status.upper()
        style = (
            "bold green"
            if chk.status == "ok"
            else ("bold yellow" if chk.status == "warn" else "bold red")
        )
        doc_tbl.add_row(chk.name, f"[{style}]{st_upper}[/{style}]", chk.detail)
    renderables.append(doc_tbl)

    # Append all usage overview tables (skipping the duplicate banner panel at index 0)
    renderables.extend(_build_overview_renderables()[1:])
    _renderables_to_output(renderables, console=console, out_file=out_file, stdout=stdout)
