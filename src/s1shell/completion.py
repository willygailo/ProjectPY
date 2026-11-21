"""Shell completion script generator for bash, zsh, and fish."""

from __future__ import annotations

from s1shell.errors import ValidationError

_MODULES = (
    "scope cve intel codec scan analyze profile fingerprint report audit doctor completion ai "
    "assess diff remediate mcp tor help check"
)
_COMMON_FLAGS = (
    "--format --out --verbose --no-color --authorized --scope-file --home "
    "--tor --tor-targets --tor-proxy --help"
)
_MCP_CLIENTS = "antigravity claude cursor vscode windsurf http"
_MCP_FLAGS = (
    "--transport --host --port --token --generate-token --allow-origin "
    f"--allow-scoped-targets --url {_COMMON_FLAGS}"
)
_OUTCOMES = "success blocked_out_of_scope blocked_unauthorized error"
_SCOPE_FLAGS = (
    "--owner --ref --expires --include-subdomains --exclude --notes "
    f"--replace --prune --dry-run {_COMMON_FLAGS}"
)
_CVE_FLAGS = (
    "--keyword --cpe --from-fingerprint --min-cvss --severity --fail-on "
    "--published-after --published-before --limit --enrich --kev-only "
    f"--recursive --refresh --offline clear {_COMMON_FLAGS}"
)
_PROFILE_FLAGS = f"--tls-versions --dns-security --well-known --check-methods {_COMMON_FLAGS}"
_REPORT_FLAGS = f"--input --profile --fingerprint --cve --operator {_COMMON_FLAGS}"
_AUDIT_FLAGS = f"--limit --category --outcome --command --target {_COMMON_FLAGS}"
_AI_SKILLS = (
    "attack-path-modeling ptes-ops-chain pentest-report-writer threat-intel-correlator "
    "sbom-supply-chain zero-trust-hardening compliance-mapper "
    "detection-engineering retest-diff-brief token-crypto-auditor"
)
_AI_FLAGS = (
    "--provider --base-url --set-key --model --env-file --input --prompt "
    "--mode --skill --pipeline --structured --redact --restore --raw-context "
    "--local-only --fallback --cache --refresh --goal --max-steps "
    f"--max-tokens {_COMMON_FLAGS}"
)
_ASSESS_FLAGS = (
    "--targets-file --delay --no-tls-versions --no-dns-security --well-known "
    "--check-methods --preset --ignore-finding --no-remediate --intel "
    "--skip-cve --enrich-cve --min-cvss --cve-limit --offline --ai --ai-provider "
    "--ai-mode --ai-skill --ai-pipeline --redact --restore --local-only "
    f"--fail-on --min-score --operator --out-dir {_COMMON_FLAGS}"
)
_INTEL_FLAGS = (
    "--set-nvd-key --set-github-key --set-vt-key --set-greynoise-key --set-urlscan-key "
    "--env-file --pinned-ip --sources --cve --ecosystem --package --limit "
    f"--export-candidates --refresh --offline {_COMMON_FLAGS}"
)
_STACKS = "auto nginx apache caddy express cloudflare traefik generic"
_SCAN_FLAGS = (
    f"--git-staged --git-diff --no-gitignore --fail-on --no-recursive --raw-bom {_COMMON_FLAGS}"
)
_ANALYZE_FLAGS = (
    "--file --from-profile --spf --dmarc --dkim --selector --offline --url --preset "
    f"{_COMMON_FLAGS}"
)
_REMEDIATE_FLAGS = f"--stack {_COMMON_FLAGS}"
_CODEC_FLAGS = (
    f"--encoding -e --chain --file --shift --all-shifts --max-depth --raw --algos {_COMMON_FLAGS}"
)
_AI_PROVIDERS = "anthropic ollama openai_compat gemini builtin"
_ROOT_COMPLETIONS = f"{_MODULES} --check --help-all --version -V --help -h"
_FILE_FLAGS = (
    "--out|--scope-file|--from-profile|--from-fingerprint|--input|"
    "--profile|--fingerprint|--cve|--env-file|--targets-file|--export-candidates|--file"
)

_BASH_COMPLETION = f"""# bash completion for s1shell
_s1shell_completions() {{
    local cur prev
    cur="${{COMP_WORDS[COMP_CWORD]}}"
    prev="${{COMP_WORDS[COMP_CWORD-1]}}"

    case "${{prev}}" in
        --format)
            COMPREPLY=( $(compgen -W "table json md html sarif" -- "${{cur}}") )
            return 0
            ;;
        --severity|--fail-on)
            COMPREPLY=( $(compgen -W "LOW MEDIUM HIGH CRITICAL" -- "${{cur}}") )
            return 0
            ;;
        --preset)
            COMPREPLY=( $(compgen -W "web api strict" -- "${{cur}}") )
            return 0
            ;;
        --stack)
            COMPREPLY=( $(compgen -W "{_STACKS}" -- "${{cur}}") )
            return 0
            ;;
        --provider|--ai-provider)
            COMPREPLY=( $(compgen -W "{_AI_PROVIDERS}" -- "${{cur}}") )
            return 0
            ;;
        --mode|--ai-mode)
            COMPREPLY=( $(compgen -W "triage executive remediate" -- "${{cur}}") )
            return 0
            ;;
        --pipeline|--ai-pipeline)
            COMPREPLY=( $(compgen -W "deep-triage purple-team executive-pack" -- "${{cur}}") )
            return 0
            ;;
        --skill|--ai-skill)
            COMPREPLY=( $(compgen -W "{_AI_SKILLS}" -- "${{cur}}") )
            return 0
            ;;
        --category)
            COMPREPLY=( $(compgen -W "target intel scope" -- "${{cur}}") )
            return 0
            ;;
        --outcome)
            COMPREPLY=( $(compgen -W "{_OUTCOMES}" -- "${{cur}}") )
            return 0
            ;;
        {_FILE_FLAGS})
            COMPREPLY=( $(compgen -f -- "${{cur}}") )
            return 0
            ;;
    esac

    if [[ ${{COMP_CWORD}} -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "{_ROOT_COMPLETIONS}" -- "${{cur}}") )
        return 0
    fi

    local mod="${{COMP_WORDS[1]}}"
    case "${{mod}}" in
        scope)
            if [[ ${{COMP_CWORD}} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "add import list check remove expire" -- "${{cur}}") )
            else
                COMPREPLY=( $(compgen -W "{_SCOPE_FLAGS}" -- "${{cur}}") )
            fi
            ;;
        cve)
            if [[ ${{COMP_CWORD}} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "search get audit cache" -- "${{cur}}") )
            else
                COMPREPLY=( $(compgen -W "{_CVE_FLAGS}" -- "${{cur}}") )
            fi
            ;;
        profile)
            COMPREPLY=( $(compgen -W "{_PROFILE_FLAGS}" -- "${{cur}}") )
            ;;
        fingerprint)
            COMPREPLY=( $(compgen -W "--from-profile {_COMMON_FLAGS}" -- "${{cur}}") )
            ;;
        report)
            if [[ ${{COMP_CWORD}} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "build" -- "${{cur}}") )
            else
                COMPREPLY=( $(compgen -W "{_REPORT_FLAGS}" -- "${{cur}}") )
            fi
            ;;
        audit)
            if [[ ${{COMP_CWORD}} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "list verify" -- "${{cur}}") )
            else
                COMPREPLY=( $(compgen -W "{_AUDIT_FLAGS}" -- "${{cur}}") )
            fi
            ;;
        completion)
            COMPREPLY=( $(compgen -W "bash zsh fish" -- "${{cur}}") )
            ;;
        ai)
            if [[ ${{COMP_CWORD}} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "env analyze skills investigate chat" -- "${{cur}}") )
            else
                COMPREPLY=( $(compgen -W "{_AI_FLAGS}" -- "${{cur}}") )
            fi
            ;;
        assess)
            COMPREPLY=( $(compgen -W "{_ASSESS_FLAGS}" -- "${{cur}}") )
            ;;
        diff)
            COMPREPLY=( $(compgen -W "--fail-on-regression {_COMMON_FLAGS}" -- "${{cur}}") )
            ;;
        remediate)
            COMPREPLY=( $(compgen -W "{_REMEDIATE_FLAGS}" -- "${{cur}}") )
            ;;
        intel)
            if [[ ${{COMP_CWORD}} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "env lookup advisory ct rdap" -- "${{cur}}") )
            else
                COMPREPLY=( $(compgen -W "{_INTEL_FLAGS}" -- "${{cur}}") )
            fi
            ;;
        codec)
            if [[ ${{COMP_CWORD}} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "decode encode inspect hash" -- "${{cur}}") )
            else
                COMPREPLY=( $(compgen -W "{_CODEC_FLAGS}" -- "${{cur}}") )
            fi
            ;;
        scan)
            if [[ ${{COMP_CWORD}} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "secrets config sbom" -- "${{cur}}") )
            else
                COMPREPLY=( $(compgen -W "{_SCAN_FLAGS}" -- "${{cur}}") )
            fi
            ;;
        analyze)
            if [[ ${{COMP_CWORD}} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "csp email headers cvss" -- "${{cur}}") )
            else
                COMPREPLY=( $(compgen -W "{_ANALYZE_FLAGS}" -- "${{cur}}") )
            fi
            ;;
        mcp)
            if [[ ${{COMP_CWORD}} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "serve config ping" -- "${{cur}}") )
            elif [[ ${{COMP_CWORD}} -eq 3 && "${{COMP_WORDS[2]}}" == "config" ]]; then
                COMPREPLY=( $(compgen -W "{_MCP_CLIENTS}" -- "${{cur}}") )
            else
                COMPREPLY=( $(compgen -W "{_MCP_FLAGS}" -- "${{cur}}") )
            fi
            ;;
        tor)
            if [[ ${{COMP_CWORD}} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "status check" -- "${{cur}}") )
            else
                COMPREPLY=( $(compgen -W "{_COMMON_FLAGS}" -- "${{cur}}") )
            fi
            ;;
        help)
            if [[ ${{COMP_CWORD}} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "{_MODULES} --all" -- "${{cur}}") )
            else
                COMPREPLY=( $(compgen -W "--all {_COMMON_FLAGS}" -- "${{cur}}") )
            fi
            ;;
        *)
            COMPREPLY=( $(compgen -W "{_COMMON_FLAGS}" -- "${{cur}}") )
            ;;
    esac
}}

complete -F _s1shell_completions s1shell
"""

_ZSH_COMPLETION = """#compdef s1shell

_s1shell() {
    local -a modules
    modules=(
        'scope:Manage authorized target scope, exclusions, and bulk imports'
        'cve:Research CVEs via NVD, CVE.org, OSV.dev, CISA KEV, and FIRST EPSS'
        'intel:Passive threat intel (VirusTotal, GreyNoise, urlscan.io, GitHub GHSA)'
        'codec:Offline decoder, encoder, smart token/cert/hash inspector, and checksums'
        'scan:Offline secret scanner, IaC/config auditor, and CycloneDX 1.5 SBOM generator'
        'analyze:Deep CSP3, Email Auth (SPF/DMARC/DKIM), offline HTTP headers, and CVSS analyzer'
        'profile:Read-only DNS/TLS/HTTP/HTML profiling'
        'fingerprint:Passive software, CDN, WAF, and JS library identification'
        'report:Compile CVE, profile, fingerprint, and assess reports'
        'audit:Inspect and verify tamper-evident audit log'
        'doctor:Verify local environment and permissions'
        'completion:Generate shell completion scripts'
        'ai:Manage AI providers (.env) and run defensive analysis'
        'assess:All-in-one authorized target or batch assessment pipeline'
        'diff:Compare baseline vs current assessment artifacts'
        'remediate:Generate offline deterministic hardening config snippets'
        'mcp:Run online Streamable HTTP or local stdio read-only MCP server'
        'tor:Check local Tor SOCKS5h readiness or verify Tor exit egress'
        'help:Show full CLI usage guide or detailed help for one module'
        'check:Run local readiness check (doctor) and full CLI usage guide'
    )

    _arguments -C \\
        '--check[Run local readiness check and show full CLI usage guide]' \\
        '--help-all[Show complete CLI manual for every module and subcommand]' \\
        '(-V --version)'{-V,--version}'[Show s1shell version and developer credit]' \\
        '--format[Output format]:format:(table json md html sarif)' \\
        '--out[Output file]:file:_files' \\
        '--verbose[Enable verbose diagnostics]' \\
        '--no-color[Disable ANSI terminal colors]' \\
        '--authorized[Confirm operator authorization]' \\
        '--scope-file[Override scope.yaml]:file:_files' \\
        '--home[Override state directory]:dir:_directories' \\
        '1:module:->module' \\
        '*::arg:->args'

    case "$state" in
        module)
            _describe 'module' modules
            ;;
        args)
            case "$words[1]" in
                scope)
                    local -a subcmds
                    subcmds=(
                        'add:Add scope or exclusion entry'
                        'import:Bulk-import scope entries from file'
                        'list:List entries'
                        'check:Check target'
                        'remove:Remove entry'
                        'expire:Show/prune expired'
                    )
                    _describe 'scope command' subcmds
                    ;;
                cve)
                    local -a subcmds
                    subcmds=(
                        'search:Search NVD'
                        'get:Fetch one or more CVE IDs'
                        'audit:Audit lockfile or CycloneDX SBOM via OSV.dev'
                        'cache:Manage local CVE cache'
                    )
                    _describe 'cve command' subcmds
                    ;;
                report)
                    local -a subcmds
                    subcmds=('build:Build combined report')
                    _describe 'report command' subcmds
                    ;;
                audit)
                    local -a subcmds
                    subcmds=(
                        'list:List audit log events'
                        'verify:Verify SHA-256 hash chain integrity'
                    )
                    _describe 'audit command' subcmds
                    ;;
                completion)
                    _values 'shell' bash zsh fish
                    ;;
                ai)
                    local -a subcmds
                    subcmds=(
                        'env:Show or update AI .env settings'
                        'analyze:Run defensive AI analysis with skills and pipelines'
                        'skills:List or inspect bundled and custom AI skills'
                        'investigate:Run bounded read-only ReAct AI investigation'
                        'chat:Interactive multi-turn defensive AI copilot'
                    )
                    _describe 'ai command' subcmds
                    ;;
                mcp)
                    local -a subcmds
                    subcmds=(
                        'serve:Start online Streamable HTTP or local stdio MCP server'
                        'config:Print ready-to-paste MCP client JSON configuration'
                        'ping:Test connectivity and capabilities of an online HTTP MCP server'
                    )
                    _describe 'mcp command' subcmds
                    ;;
                tor)
                    local -a subcmds
                    subcmds=(
                        'status:Offline local Tor binary and SOCKS5h port readiness check'
                        'check:Verify live Tor exit egress via check.torproject.org'
                    )
                    _describe 'tor command' subcmds
                    ;;
                intel)
                    local -a subcmds
                    subcmds=(
                        'env:Show or update intel API keys in .env'
                        'lookup:Passive VT/GreyNoise/urlscan/RDAP lookup'
                        'advisory:Query GitHub Security Advisories (GHSA)'
                        'ct:Passive Certificate Transparency log lookup via crt.sh'
                        'rdap:RFC 7480-7484 RDAP domain or IP registration lookup'
                    )
                    _describe 'intel command' subcmds
                    ;;
                codec)
                    local -a subcmds
                    subcmds=(
                        'decode:Decode Base64/Hex/URL/HTML/Unicode/SAML/JWT/Gzip/Auto'
                        'encode:Encode text or files using single or chained codecs'
                        'inspect:Smart offline JWT/X.509/hash/timestamp/auto-decode inspector'
                        'hash:Compute MD5/SHA-1/SHA-256/SHA-512/BLAKE2b/CRC32 and entropy'
                    )
                    _describe 'codec command' subcmds
                    ;;
                scan)
                    local -a subcmds
                    subcmds=(
                        'secrets:Scan local files, repos, or git diffs for exposed secrets'
                        'config:Audit Dockerfiles, K8s, GitHub Actions, Compose, NGINX, SSHd & .env'
                        'sbom:Generate CycloneDX 1.5 JSON SBOM from lockfiles & manifests'
                    )
                    _describe 'scan command' subcmds
                    ;;
                analyze)
                    local -a subcmds
                    subcmds=(
                        'csp:Evaluate CSP3 directives, bypass hosts & hardened policy'
                        'email:Audit SPF blast radius, DMARC policy & DKIM key strength'
                        'headers:Audit raw HTTP response headers offline'
                        'cvss:Decode and compute FIRST CVSS v3.0/v3.1/v4.0 vectors'
                    )
                    _describe 'analyze command' subcmds
                    ;;
            esac
            ;;
    esac
}

_s1shell "$@"
"""

_FISH_COMPLETION = """# fish completion for s1shell
complete -c s1shell -f
complete -c s1shell -n "__fish_use_subcommand" -a "scope" -d "Manage authorized target scope"
complete -c s1shell -n "__fish_use_subcommand" -a "cve" -d "CVE & SBOM intelligence (NVD/OSV)"
complete -c s1shell -n "__fish_use_subcommand" -a "intel" -d "Passive VT/GreyNoise/urlscan/GHSA"
complete -c s1shell -n "__fish_use_subcommand" -a "codec" -d "Offline decode/encode/inspect/hash"
complete -c s1shell -n "__fish_use_subcommand" -a "scan" -d "Offline secrets, IaC & SBOM"
complete -c s1shell -n "__fish_use_subcommand" -a "analyze" -d "CSP3, Email, Headers & CVSS"
complete -c s1shell -n "__fish_use_subcommand" -a "profile" -d "Read-only target profiling"
complete -c s1shell -n "__fish_use_subcommand" -a "fingerprint" -d "Passive stack matching"
complete -c s1shell -n "__fish_use_subcommand" -a "report" -d "Compile assessment reports"
complete -c s1shell -n "__fish_use_subcommand" -a "audit" -d "Inspect and verify audit log"
complete -c s1shell -n "__fish_use_subcommand" -a "doctor" -d "Run local diagnostics"
complete -c s1shell -n "__fish_use_subcommand" -a "completion" -d "Generate shell completion"
complete -c s1shell -n "__fish_use_subcommand" -a "ai" -d "AI providers and defensive analysis"
complete -c s1shell -n "__fish_use_subcommand" -a "assess" -d "Single or batch target assessment"
complete -c s1shell -n "__fish_use_subcommand" -a "diff" -d "Compare baseline vs current assess"
complete -c s1shell -n "__fish_use_subcommand" -a "remediate" -d "Offline hardening config playbook"
complete -c s1shell -n "__fish_use_subcommand" -a "mcp" -d "Online HTTP or local stdio MCP server"
complete -c s1shell -n "__fish_use_subcommand" -a "tor" -d "Tor SOCKS5h readiness and exit check"
complete -c s1shell -n "__fish_use_subcommand" -a "help" -d "Full CLI usage guide and module manual"
complete -c s1shell -n "__fish_use_subcommand" -a "check" -d "Local diagnostics + full CLI guide"

complete -c s1shell -l check -d "Run local readiness check + show full CLI usage guide"
complete -c s1shell -l help-all -d "Show complete manual for all modules and subcommands"
complete -c s1shell -s V -l version -d "Show s1shell version and developer credit"

complete -c s1shell -n "__fish_seen_subcommand_from scope" -a "add import list check remove expire"
complete -c s1shell -n "__fish_seen_subcommand_from cve" -a "search get audit cache"
complete -c s1shell -n "__fish_seen_subcommand_from report" -a "build"
complete -c s1shell -n "__fish_seen_subcommand_from audit" -a "list verify"
complete -c s1shell -n "__fish_seen_subcommand_from completion" -a "bash zsh fish"
complete -c s1shell -n "__fish_seen_subcommand_from ai" -a "env analyze skills investigate chat"
complete -c s1shell -n "__fish_seen_subcommand_from mcp" -a "serve config ping"
complete -c s1shell -n "__fish_seen_subcommand_from tor" -a "status check"
complete -c s1shell -n "__fish_seen_subcommand_from intel" -a "env lookup advisory ct rdap"
complete -c s1shell -n "__fish_seen_subcommand_from codec" -a "decode encode inspect hash"
complete -c s1shell -n "__fish_seen_subcommand_from scan" -a "secrets config sbom"
complete -c s1shell -n "__fish_seen_subcommand_from analyze" -a "csp email headers cvss"

complete -c s1shell -l format -x -a "table json md html sarif"
complete -c s1shell -l preset -x -a "web api strict"
complete -c s1shell -l stack -x -a "auto nginx apache caddy express cloudflare traefik generic"
complete -c s1shell -l out -r
complete -c s1shell -l scope-file -r
complete -c s1shell -l home -r
complete -c s1shell -l authorized -d "Confirm operator authorization"
complete -c s1shell -l no-color -d "Disable ANSI colors"
complete -c s1shell -l verbose -d "Enable verbose diagnostics"
"""


def generate_completion(shell: str) -> str:
    """Return a shell completion script for bash, zsh, or fish."""
    norm = shell.strip().lower()
    if norm == "bash":
        return _BASH_COMPLETION
    if norm == "zsh":
        return _ZSH_COMPLETION
    if norm == "fish":
        return _FISH_COMPLETION
    raise ValidationError(f"Unsupported shell '{shell}'. Choose bash, zsh, or fish.")
