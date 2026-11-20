# S1shell

**S1shell** is an open-source, defensive CLI toolkit built for Kali Linux and standard Linux environments to support **authorized security assessments**, **CVE research**, **scoped target profiling**, **passive technology verification**, and **auditable reporting**.

---

## Authorized-Use Notice

S1shell is strictly intended for use on systems you **own** or have **explicit written authorization** to evaluate.

Every target-touching operation enforces a fail-closed policy gate:
1. **Scope First (`exit 2`)**: No packet is sent unless the target and its resolved IP addresses match an active, unexpired entry in `~/.s1shell/scope.yaml` (and domain entries cannot silently resolve to un-scoped loopback, private, or cloud metadata IPs).
2. **Explicit Authorization (`exit 3`)**: Target commands require `--authorized` or interactive TTY confirmation. Non-interactive runs without `--authorized` fail immediately.
3. **Audit Logging**: Every network attempt (allowed, blocked, or failed) appends a structured JSONL record to `~/.s1shell/audit.log`.

---

## What S1shell Does Not Do

By design, S1shell **never** implements or accepts plugins for:
- Exploitation, exploit payloads, or vulnerability PoC execution
- Payload generation or active vulnerability probing/fuzzing (SQLi/XSS/SSRF/LFI strings)
- WAF bypass, firewall evasion, request smuggling, or browser User-Agent spoofing
- Rate-limit evasion, proxy rotation, or IP rotation
- Brute force, password spraying, credential testing, or directory/subdomain enumeration
- Port scanning, host discovery, denial-of-service testing, or target state modification

---

## Installation

### Kali Linux

```bash
./scripts/install-kali.sh
# Or editable development setup:
./scripts/install-kali.sh --dev
```

### Standard Python (3.10+) with `pipx`

```bash
pipx install .
```

### Development / Offline Testing

```bash
make setup
source .venv/bin/activate
make check
```

Or run the checks directly:

```bash
ruff check src tests
ruff format --check src tests
mypy src
pytest --cov=s1shell --cov-report=term-missing
```

---

## How to Use S1shell (Step-by-Step Quickstart)

Every S1shell workflow follows a safe, reproducible pipeline: **check environment -> define scope -> profile target -> fingerprint -> research CVEs -> (optional) AI triage -> build report -> inspect audit log**.

If running directly from source without `pipx install .`, prefix commands with `PYTHONPATH=src python3 -m s1shell` instead of `s1shell`.

### All-in-One Pentester Assessment (`s1shell assess`)

Once your target is in scope, you can run the entire workflow (**profile + TLS version check + passive fingerprint + CVE correlation + automated posture score/grade + report bundle**) in one command:

```bash
s1shell assess https://app.example.com --authorized --operator "Jane Doe" --out-dir ./assessment-out
```

Or run step-by-step manually:

### Step 1: Verify Your Local Environment

```bash
s1shell doctor
```

Checks Python version (`>= 3.10`), `~/.s1shell` directory and file permissions, `scope.yaml`, `audit.log`, `cache.db`, bundled fingerprint signatures, `NVD_API_KEY`, and `ANTHROPIC_API_KEY`.

Optional: install shell tab-completion (`bash`, `zsh`, or `fish`):

```bash
s1shell completion bash > ~/.local/share/bash-completion/completions/s1shell
```

### Step 2: Configure Optional API Keys (`.env`)

S1shell works out of the box without API keys, or you can configure:
- **`NVD_API_KEY`** (raises NVD CVE lookup rate limit from 5 req/30s to 50 req/30s)
- **`ANTHROPIC_API_KEY`** (enables defensive triage via `s1shell ai analyze`)

Copy [.env.example](.env.example) to `.env` or manage credentials via `s1shell ai env`:

```bash
# View current .env configuration (API keys are masked)
s1shell ai env

# Save your standard Anthropic inference key and model into ~/.s1shell/.env (0600 permissions)
s1shell ai env --set-key "sk-ant-api03-..." --model "claude-sonnet-4-20250514"
```

### Step 3: Add & Verify an Authorized Target Scope

Target-touching commands (`profile`, live `fingerprint`) **fail closed** unless the target matches an active, unexpired entry in `scope.yaml`:

```bash
s1shell scope add example.com \
  --include-subdomains \
  --owner "ACME IT" \
  --ref "SOW-2026-014" \
  --expires 2026-12-31

# Confirm DNS resolution and scope match before touching the target
s1shell scope check https://app.example.com
```

### Step 4: Profile the Authorized Target (Read-Only)

Runs DNS lookups (`A`, `AAAA`, `CNAME`), a single TLS handshake, and a single non-redirecting `GET` request to inspect protocol version (`HTTP/1.1` / `HTTP/2` / `Alt-Svc`), security headers, banners, and `Set-Cookie` flags:

```bash
s1shell profile https://app.example.com --authorized --format json --out profile.json
```

> Without `--authorized`, interactive TTY confirmation is requested; non-interactive shells exit with code `3`.

### Step 5: Fingerprint the Stack Offline

Reuse `profile.json` with **zero additional network requests** to match servers, CDNs, WAFs, and frameworks against bundled signatures:

```bash
s1shell fingerprint --from-profile profile.json --format json --out fp.json
```

### Step 6: Research Matching CVEs (Zero Target Contact)

Query NVD & CVE.org (cached locally in `~/.s1shell/cache.db`) directly from your detected stack or by keyword/CPE:

```bash
s1shell cve search --from-fingerprint fp.json --min-cvss 7.0 --format json --out cves.json
```

### Step 7: Optional Defensive AI Triage

Summarize findings and prioritize defensive hardening steps using the saved JSON artifacts (zero target contact):

```bash
s1shell ai analyze \
  --input profile.json \
  --input fp.json \
  --input cves.json \
  --prompt "Prioritize remediation steps for missing headers and high-severity CVEs." \
  --format md \
  --out ai_triage.md
```

### Step 8: Compile the Final Assessment Report

Combine `profile`, `fingerprint`, and `cve` JSON artifacts into Markdown, JSON, or a self-contained HTML report (autoescaped Jinja2, zero external scripts/CDNs):

```bash
s1shell report build \
  --profile profile.json \
  --fingerprint fp.json \
  --cve cves.json \
  --operator "Jane Doe" \
  --format html \
  --out report.html
```

### Step 9: Review the Audit Trail

```bash
s1shell audit list --limit 50
```

---

## Module-by-Module Usage Guide

### 1. `scope` — Target Authorization Governance

```bash
# Add domain, wildcard (*.example.com), IPv4/IPv6, CIDR, or URL prefix
s1shell scope add example.com --include-subdomains --owner "ACME IT" --ref "SOW-2026-014" --expires 2026-12-31
s1shell scope add 203.0.113.0/24 --owner "ACME NetOps" --ref "SOW-2026-014" --expires 2026-12-31 --notes "DMZ range"

# List configured entries, check a target, prune expired entries, or remove by ID/target
s1shell scope list
s1shell scope check https://app.example.com
s1shell scope expire --prune
s1shell scope remove example.com
```

### 2. `cve` — Public Vulnerability Research

```bash
# Search NVD by keyword or CPE 2.3 string with CVSS/severity/date filters
s1shell cve search --keyword "nginx 1.18" --min-cvss 7.0
s1shell cve search --cpe "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*" --severity HIGH --format json --out cves.json
s1shell cve search --from-fingerprint fp.json --published-after 2023-01-01 --limit 15

# Look up a specific CVE (NVD + CVE.org enrichment), offline cache mode, or clear cache
s1shell cve get CVE-2021-23017
s1shell cve get CVE-2021-23017 --offline
s1shell cve cache clear
```

### 3. `profile` — Read-Only DNS/TLS/HTTP Profiling

```bash
# Standard single-handshake + single-GET profile
s1shell profile https://app.example.com --authorized --format md

# Also perform bounded TLS 1.0–1.3 checks to flag deprecated TLS versions
s1shell profile https://app.example.com --authorized --tls-versions --format json --out profile.json
```

### 4. `fingerprint` — Passive Technology & CDN/WAF Identification

```bash
# Offline mode (recommended after profiling; zero target traffic)
s1shell fingerprint --from-profile profile.json --format json --out fp.json

# Live guarded single-GET inspection
s1shell fingerprint https://app.example.com --authorized --format table
```

### 5. `ai` — `.env` Management & Defensive Triage

```bash
# Check configured key (masked), key type, active model, and .env source
s1shell ai env

# Write key/model to ~/.s1shell/.env (or pass --env-file .env for project-local .env)
s1shell ai env --set-key "sk-ant-api03-..." --model "claude-sonnet-4-20250514" --env-file .env

# Analyze saved S1shell JSON artifacts or ask a defensive hardening question
s1shell ai analyze --input profile.json --input cves.json --format md
s1shell ai analyze --prompt "Explain recommended HSTS and CSP directives for an API gateway."
```

> Note: Anthropic `/v1/messages` inference requires a standard API key (`sk-ant-api*`); Anthropic Admin keys (`sk-ant-admin*`) are flagged by `s1shell doctor` and `s1shell ai env`.

### 6. `report` — Assessment Report Compiler

```bash
# Auto-detect artifact types with repeatable --input, or pass typed flags
s1shell report build \
  --input profile.json \
  --input fp.json \
  --input cves.json \
  --operator "Jane Doe" \
  --format html \
  --out report.html
```

### 7. `audit` — Audit Log Viewer

```bash
s1shell audit list --limit 50
s1shell audit list --category target --outcome blocked_out_of_scope --format md
s1shell audit list --command "ai analyze" --target api.anthropic.com
```

### 8. `doctor` & `completion`

```bash
s1shell doctor --format json
s1shell completion zsh > ~/.zsh/completions/_s1shell
s1shell completion fish > ~/.config/fish/completions/s1shell.fish
```

### 9. `assess` — All-in-One Pentester Assessment Pipeline

```bash
# Full assessment with posture grade, findings table, and complete report bundle
s1shell assess https://app.example.com --authorized --operator "Jane Doe" --out-dir ./assessment-out

# Fast offline/no-CVE posture check or direct HTML report output
s1shell assess https://app.example.com --authorized --skip-cve --format html --out report.html

# Include optional defensive AI executive summary (requires sk-ant-api* key)
s1shell assess https://app.example.com --authorized --ai --format md
```

---

## Command & Flag Reference

### Modules & Commands

| Command | Network Contact | Purpose |
|---|---|---|
| `s1shell assess <target>` | Single target + NVD (unless `--skip-cve`) | All-in-one profile, fingerprint, CVE, posture score, & report bundle |
| `s1shell scope add \| list \| check \| remove \| expire` | DNS on `check` only | Manage authorized targets & expiry in `scope.yaml` |
| `s1shell cve search \| get \| cache clear` | Public NVD & CVE.org | Search/lookup CVEs & manage SQLite cache (`--offline` supported) |
| `s1shell profile <target>` | Single target (1 GET + TLS) | Inspect DNS, ALPN/HTTP, TLS cert, security headers, cookies |
| `s1shell fingerprint [<target> \| --from-profile FILE]` | None (`--from-profile`) or 1 GET | Passive vendor/CDN/WAF matching with evidence |
| `s1shell ai env \| analyze` | Anthropic API on `analyze` | Manage `.env` credentials (`0600`) & defensive artifact triage |
| `s1shell report build` | None (offline) | Compile `profile`, `fingerprint`, and `cve` JSON into HTML/MD/JSON |
| `s1shell audit list` | None (offline) | View & filter `~/.s1shell/audit.log` JSONL records |
| `s1shell doctor` | None (offline) | Check Python, file modes (`0700`/`0600`), scope, cache, and API keys |
| `s1shell completion {bash,zsh,fish}` | None (offline) | Output shell completion script |

### Common Flags (Supported Before or After Subcommands)

| Flag | Description |
|---|---|
| `--format {table,json,md,html}` | Output format (`html` is supported by `report build` and `assess`) |
| `--out FILE` | Write output to `FILE` instead of stdout |
| `--authorized` | Non-interactive authorization confirmation for target-touching commands |
| `--scope-file FILE` | Override path to `scope.yaml` |
| `--home DIR` | Override state directory (default `~/.s1shell` or `$S1SHELL_HOME`) |
| `--no-color` | Disable ANSI colors in terminal tables |
| `--verbose` | Print full tracebacks to stderr on unexpected errors |
| `--version` | Show installed `s1shell` version |

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Validation, network, or runtime error |
| `2` | Target out of scope, expired, or unsafe IP resolution |
| `3` | Operator authorization not confirmed |

## Documentation

- [Architecture](docs/architecture.md)
- [Artifact & Log Schemas](docs/schemas.md)
- [Contributing Guide](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security Policy](SECURITY.md)
