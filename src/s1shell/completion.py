"""Shell completion script generator for bash, zsh, and fish."""

from __future__ import annotations

from s1shell.errors import ValidationError

_MODULES = "scope cve profile fingerprint report audit doctor completion ai assess diff mcp"
_COMMON_FLAGS = "--format --out --verbose --no-color --authorized --scope-file --home --help"
_OUTCOMES = "success blocked_out_of_scope blocked_unauthorized error"
_SCOPE_FLAGS = (
    f"--owner --ref --expires --include-subdomains --exclude --notes --replace --prune {_COMMON_FLAGS}"
)
_CVE_FLAGS = (
    "--keyword --cpe --from-fingerprint --min-cvss --severity "
    f"--published-after --published-before --limit --enrich --kev-only --refresh --offline clear {_COMMON_FLAGS}"
)
_REPORT_FLAGS = f"--input --profile --fingerprint --cve --operator {_COMMON_FLAGS}"
_AUDIT_FLAGS = f"--limit --category --outcome --command --target {_COMMON_FLAGS}"
_AI_FLAGS = (
    "--provider --base-url --set-key --model --env-file --input --prompt "
    f"--mode --redact --max-tokens {_COMMON_FLAGS}"
)
_ASSESS_FLAGS = (
    "--targets-file --delay --no-tls-versions --no-dns-security --well-known "
    "--skip-cve --enrich-cve --min-cvss --cve-limit --offline --ai --ai-provider "
    f"--ai-mode --redact --fail-on --min-score --operator --out-dir {_COMMON_FLAGS}"
)
_FILE_FLAGS = (
    "--out|--scope-file|--from-profile|--from-fingerprint|--input|"
    "--profile|--fingerprint|--cve|--env-file|--targets-file"
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
        --provider|--ai-provider)
            COMPREPLY=( $(compgen -W "anthropic ollama openai_compat gemini" -- "${{cur}}") )
            return 0
            ;;
        --mode|--ai-mode)
            COMPREPLY=( $(compgen -W "triage executive remediate" -- "${{cur}}") )
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
        COMPREPLY=( $(compgen -W "{_MODULES} --version --help" -- "${{cur}}") )
        return 0
    fi

    local mod="${{COMP_WORDS[1]}}"
    case "${{mod}}" in
        scope)
            if [[ ${{COMP_CWORD}} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "add list check remove expire" -- "${{cur}}") )
            else
                COMPREPLY=( $(compgen -W "{_SCOPE_FLAGS}" -- "${{cur}}") )
            fi
            ;;
        cve)
            if [[ ${{COMP_CWORD}} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "search get cache" -- "${{cur}}") )
            else
                COMPREPLY=( $(compgen -W "{_CVE_FLAGS}" -- "${{cur}}") )
            fi
            ;;
        profile)
            COMPREPLY=( $(compgen -W "--tls-versions --dns-security --well-known {_COMMON_FLAGS}" -- "${{cur}}") )
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
                COMPREPLY=( $(compgen -W "env analyze" -- "${{cur}}") )
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
        mcp)
            if [[ ${{COMP_CWORD}} -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "serve" -- "${{cur}}") )
            else
                COMPREPLY=( $(compgen -W "{_COMMON_FLAGS}" -- "${{cur}}") )
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
        'scope:Manage authorized target scope and exclusions'
        'cve:Research CVEs via NVD, CVE.org, CISA KEV, and FIRST EPSS'
        'profile:Read-only DNS/TLS/HTTP/HTML profiling'
        'fingerprint:Passive software, CDN, and WAF identification'
        'report:Compile CVE, profile, fingerprint, and assess reports'
        'audit:Inspect and verify tamper-evident audit log'
        'doctor:Verify local environment and permissions'
        'completion:Generate shell completion scripts'
        'ai:Manage AI providers (.env) and run defensive analysis'
        'assess:All-in-one authorized target or batch assessment pipeline'
        'diff:Compare baseline vs current assessment artifacts'
        'mcp:Run read-only offline/intel MCP stdio server'
    )

    _arguments -C \\
        '--version[Show s1shell version]' \\
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
                        'get:Fetch CVE ID'
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
                        'analyze:Run defensive AI artifact analysis'
                    )
                    _describe 'ai command' subcmds
                    ;;
                mcp)
                    local -a subcmds
                    subcmds=('serve:Start read-only offline MCP server')
                    _describe 'mcp command' subcmds
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
complete -c s1shell -n "__fish_use_subcommand" -a "cve" -d "Research CVEs via NVD, CVE.org, KEV, EPSS"
complete -c s1shell -n "__fish_use_subcommand" -a "profile" -d "Read-only DNS/TLS/HTTP/HTML profiling"
complete -c s1shell -n "__fish_use_subcommand" -a "fingerprint" -d "Passive stack matching"
complete -c s1shell -n "__fish_use_subcommand" -a "report" -d "Compile assessment reports"
complete -c s1shell -n "__fish_use_subcommand" -a "audit" -d "Inspect and verify audit log"
complete -c s1shell -n "__fish_use_subcommand" -a "doctor" -d "Run local diagnostics"
complete -c s1shell -n "__fish_use_subcommand" -a "completion" -d "Generate shell completion"
complete -c s1shell -n "__fish_use_subcommand" -a "ai" -d "AI providers and defensive analysis"
complete -c s1shell -n "__fish_use_subcommand" -a "assess" -d "All-in-one or batch assessment pipeline"
complete -c s1shell -n "__fish_use_subcommand" -a "diff" -d "Compare baseline vs current assessment"
complete -c s1shell -n "__fish_use_subcommand" -a "mcp" -d "Read-only offline MCP stdio server"

complete -c s1shell -n "__fish_seen_subcommand_from scope" -a "add list check remove expire"
complete -c s1shell -n "__fish_seen_subcommand_from cve" -a "search get cache"
complete -c s1shell -n "__fish_seen_subcommand_from report" -a "build"
complete -c s1shell -n "__fish_seen_subcommand_from audit" -a "list verify"
complete -c s1shell -n "__fish_seen_subcommand_from completion" -a "bash zsh fish"
complete -c s1shell -n "__fish_seen_subcommand_from ai" -a "env analyze"
complete -c s1shell -n "__fish_seen_subcommand_from mcp" -a "serve"

complete -c s1shell -l format -x -a "table json md html sarif"
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
