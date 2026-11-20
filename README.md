# S1shell

[![Version](https://img.shields.io/badge/version-0.3.0-blue.svg)](CHANGELOG.md)
[![Python](https://img.shields.io/badge/python-3.10%2B-3776ab.svg)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Quality](https://img.shields.io/badge/quality-ruff%20%7C%20strict%20mypy%20%7C%2076%20offline%20tests-brightgreen.svg)](.github/workflows/ci.yml)

**S1shell** is an open-source, defensive security assessment CLI toolkit built for Kali Linux and standard Linux environments. It unifies **scoped read-only target profiling**, **passive technology & JS library fingerprinting**, **CVE / KEV / EPSS & SBOM auditing**, **multi-feed passive threat intelligence**, **deterministic hardening playbooks**, **posture drift diffing**, **multi-provider defensive AI triage**, **SARIF / HTML / Markdown reporting**, and a **read-only offline MCP server** behind a fail-closed authorization gate.

### Key Capabilities

- **Fail-Closed Scope & Governance**: Allow/deny (`--exclude`) scope rules, bulk scope import (`scope import --dry-run`), DNS rebinding & private/metadata IP guards, IP-pinned HTTP/TLS connections, and a SHA-256 hash-chained `audit.log` (`audit verify`).
- **Deep Read-Only Profiling**: DNS hygiene (`A`/`AAAA`/`CNAME`/`MX`/`NS`/`CAA`/`SPF` 10-lookup check/`DMARC`/`MTA-STS`/`TLS-RPT`/`DNSSEC`/dangling CNAME + zone-apex fallback), TLS 1.0–1.3 matrix + cipher/key/sig/SPKI pin hash, directive-level CSP/CORS/HSTS/cache/debug-header/cookie analysis, zero-extra-packet passive HTML inspection, and opt-in `OPTIONS` method & `security.txt`/`robots.txt` review.
- **81 Passive Fingerprints + Client Library CPEs**: Identifies web servers, CDNs, WAFs, DevOps platforms, frameworks, and client-side JS libraries (`jQuery`, `Bootstrap`, `Lodash`, `Moment.js`, `DOMPurify`, `Handlebars`, `Axios`, `Swagger UI`) with automatic CPE 2.3 correlation and custom `~/.s1shell/signatures.d/*.yaml` support.
- **CVE, KEV, EPSS, GHSA & SBOM Auditing**: NVD 2.0 + CVE.org + GitHub Security Advisories + CISA KEV + FIRST EPSS with SSVC-style `P0-IMMEDIATE`..`P3-MONITOR` priority tiers, plus zero-target-contact **OSV.dev** lockfile & CycloneDX SBOM scanning (`requirements.txt`, `package-lock.json`, `go.mod`, `Cargo.lock`, `*.cdx.json`).
- **5-Feed Passive Threat Intelligence (`s1shell intel`)**: Cached, zero-target-contact lookups across **VirusTotal v3**, **GreyNoise Community** (noise vs benign RIOT), **urlscan.io Search API** (passive historical index only), **GitHub Advisories (GHSA)**, and **NVD**, with `0600` masked `.env` management.
- **Deterministic Playbooks, Presets, Drift Diffs & SARIF**: Assessment presets (`web`, `api`, `strict`), transparent finding waivers (`--ignore-finding`), OWASP Top 10:2021 / ASVS / CWE / NIST 800-53 mapping, offline config snippets (`nginx`, `apache`, `caddy`, `express`, `dns`, `security.txt`), `diff --fail-on-regression`, and CI policy gates (`exit 4`).
- **Multi-Provider Defensive AI & Read-Only MCP**: Supports **Anthropic**, local air-gapped **Ollama**, **OpenAI-compatible**, and **Google Gemini** with prompt-injection tagging (`<untrusted_telemetry>`) and reversible NDA-safe redaction (`--redact`), plus a 12-tool read-only JSON-RPC 2.0 stdio MCP server (`mcp serve`).

```mermaid
flowchart LR
    CLI["s1shell CLI / Read-Only MCP"] --> GATE["Policy Gate (Scope -> Auth -> IP Pin -> SHA-256 Audit)"]
    CLI --> INTEL["Zero-Target-Contact Intel (SQLite TTL Cache)"]
    CLI --> OFFLINE["Offline Analysis & Reporting"]

    GATE --> TARGET["profile / fingerprint / assess [--targets-file]"]
    INTEL --> FEEDS["NVD / CVE.org / OSV.dev / KEV / EPSS / VT / GreyNoise / urlscan / GHSA"]
    OFFLINE --> OUT["remediate / diff / report build (HTML, MD, JSON, SARIF 2.1.0)"]
```

---

## Authorized-Use Notice

S1shell is strictly intended for use on systems you **own** or have **explicit written authorization** to evaluate.

Every target-touching operation enforces a fail-closed policy gate:
1. **Scope First (`exit 2`)**: No packet is sent unless the target and its resolved IP addresses match an active, unexpired allow entry (and no `--exclude` rule) in `~/.s1shell/scope.yaml`, and domain entries cannot silently resolve to un-scoped loopback, private, or cloud metadata IPs.
2. **Explicit Authorization (`exit 3`)**: Target commands require `--authorized` or interactive TTY confirmation. Non-interactive runs without `--authorized` fail immediately.
3. **Tamper-Evident Audit Logging**: Every network attempt appends a SHA-256 hash-chained JSONL record to `~/.s1shell/audit.log`, verifiable offline via `s1shell audit verify`.

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

## Installation & Shell Completion

### Clone Repository

```bash
git clone https://github.com/willygailo/ProjectPY.git
cd ProjectPY
```

### Kali Linux

```bash
./scripts/install-kali.sh
# Or editable development setup:
./scripts/install-kali.sh --dev
```

### Standard Python (3.10+) with `pipx`

```bash
pipx install .
# Upgrade existing local install after pulling updates:
pipx install --force .
```

### Development & Offline Verification

```bash
make setup
source .venv/bin/activate
make check
```

> Running directly from source without `pipx`? Replace `s1shell` with `PYTHONPATH=src python3 -m s1shell`.

### Shell Tab-Completion (`bash`, `zsh`, `fish`)

```bash
# Bash
mkdir -p ~/.local/share/bash-completion/completions
s1shell completion bash > ~/.local/share/bash-completion/completions/s1shell

# Zsh
mkdir -p ~/.zsh/completions
s1shell completion zsh > ~/.zsh/completions/_s1shell

# Fish
mkdir -p ~/.config/fish/completions
s1shell completion fish > ~/.config/fish/completions/s1shell.fish
```

---

## Quickstart: 10-Step Advanced Assessment Workflow

### 1. Verify Environment & Audit Chain Integrity

```bash
s1shell doctor
s1shell audit verify
```

### 2. Configure Threat Intel & AI Keys (`.env`, `0600`)

All API keys are optional (S1shell works out of the box with unauthenticated NVD/OSV/CVE.org). Store keys securely in `~/.s1shell/.env` or project-local `.env` (`chmod 600`, gitignored; always masked in output):

```bash
# Configure passive threat intelligence feeds
s1shell intel env \
  --set-nvd-key "YOUR_NVD_KEY" \
  --set-github-key "YOUR_GITHUB_TOKEN" \
  --set-vt-key "YOUR_VT_KEY" \
  --set-greynoise-key "YOUR_GREYNOISE_KEY" \
  --set-urlscan-key "YOUR_URLSCAN_KEY"

# Inspect masked key status
s1shell intel env

# Configure local air-gapped Ollama (zero cloud telemetry) or Anthropic/OpenAI/Gemini
s1shell ai env --provider ollama --model "llama3.1:8b"
```

### 3. Onboard Authorized Scope & Exclusions

```bash
# Add single domain/CIDR allow rules and deny-first exclusions
s1shell scope add example.com --include-subdomains --owner "ACME IT" --ref "SOW-2026-014" --expires 2026-12-31
s1shell scope add billing.example.com --exclude --owner "ACME IT" --ref "SOW-2026-014" --expires 2026-12-31

# Bulk import targets from a file (prefix `!` on any line to mark an exclusion)
s1shell scope import targets.txt --owner "ACME IT" --ref "SOW-2026-014" --expires 2026-12-31 --dry-run
s1shell scope import targets.txt --owner "ACME IT" --ref "SOW-2026-014" --expires 2026-12-31

# Verify DNS resolution and scope authorization before touching a target
s1shell scope check https://app.example.com
```

### 4. All-in-One Target or Batch Assessment (`s1shell assess`)

Runs **profile -> passive fingerprint -> CPE-verified CVE + KEV/EPSS -> optional passive threat intel -> preset posture scoring (CWE/ASVS/OWASP/NIST) -> deterministic hardening playbook -> JSON/SARIF/MD/HTML bundle**:

```bash
# Full web assessment with KEV/EPSS, passive VT/GreyNoise/urlscan intel, well-known, & OPTIONS check
s1shell assess https://app.example.com --authorized \
  --enrich-cve --intel --well-known --check-methods \
  --operator "Jane Doe" --out-dir ./assessment-out

# API-focused preset (suppresses browser HTML/clickjacking noise) with CI policy gates (exit 4)
s1shell assess https://api.example.com --authorized \
  --preset api --check-methods --ignore-finding DNS-005 \
  --fail-on HIGH --min-score 80 --format sarif --out api.sarif

# Sequential guarded batch assessment (concurrency=1, scope-gated per target, HTML dashboard)
s1shell assess --targets-file in_scope_urls.txt --authorized \
  --delay 0.5 --enrich-cve --intel --fail-on CRITICAL --out-dir ./batch-out
```

### 5. Deterministic Offline Hardening Playbook (`s1shell remediate`)

Generate copy-pasteable defensive configurations (`nginx`, `apache`, `caddy`, `express`, `dns`, `security.txt`, `generic`) directly from a saved `assess.json` with **zero AI / zero network**:

```bash
s1shell remediate ./assessment-out/assess.json --stack auto --format md --out hardening.md
```

### 6. Posture Drift Diffing (`s1shell diff`)

Compare baseline vs current `assess.json` artifacts in re-tests or CI pipelines:

```bash
s1shell diff ./baseline/assess.json ./assessment-out/assess.json --fail-on-regression
```

### 7. Lockfile & CycloneDX SBOM Auditing (`s1shell cve audit`)

Zero-target-contact vulnerability scanning for `requirements.txt`, `package-lock.json`, `go.mod`, `Cargo.lock`, and CycloneDX JSON SBOMs via **OSV.dev + CISA KEV + FIRST EPSS**:

```bash
s1shell cve audit requirements.txt --enrich --fail-on HIGH
s1shell cve audit package-lock.json --enrich --kev-only
s1shell cve audit sbom.cdx.json --enrich --format sarif --out sbom.sarif
```

### 8. Passive Threat Intelligence & GitHub Advisories (`s1shell intel`)

Zero-target-contact reputation, scanner/RIOT classification, passive historical scan search, and GHSA lookups (all cached locally in `~/.s1shell/cache.db`):

```bash
# Passive VirusTotal + GreyNoise + urlscan.io Search lookup
s1shell intel lookup example.com --pinned-ip 93.184.216.34
s1shell intel lookup 93.184.216.34 --sources vt,greynoise --offline

# Query GitHub Security Advisories (GHSA)
s1shell intel advisory --cve CVE-2023-45803
s1shell intel advisory --ecosystem pip --package requests
```

### 9. Multi-CVE Research & SSVC Prioritization (`s1shell cve`)

```bash
# Search NVD with KEV/EPSS enrichment & P0-IMMEDIATE..P3-MONITOR priority tiers
s1shell cve search --keyword "nginx 1.18" --min-cvss 7.0 --enrich
s1shell cve search --from-fingerprint ./assessment-out/fingerprint.json --kev-only

# Look up one or multiple specific CVE IDs (with NVD + CVE.org + GHSA + KEV/EPSS)
s1shell cve get CVE-2021-23017 CVE-2023-44487 --enrich
```

### 10. Multi-Provider Defensive AI Triage (`s1shell ai`)

```bash
# Redact client hostnames, IPs, emails, scope IDs & cookies before cloud inference
s1shell ai analyze \
  --input ./assessment-out/assess.json \
  --mode remediate \
  --redact \
  --format md \
  --out ai_remediation.md
```

---

## Standalone Modules, Extensibility, CI/CD & MCP

### Standalone `profile`, `fingerprint`, `report`, & `audit`

```bash
# Deep read-only single-target profile
s1shell profile https://app.example.com --authorized \
  --tls-versions --dns-security --well-known --check-methods \
  --format json --out profile.json

# Offline fingerprinting (zero network traffic)
s1shell fingerprint --from-profile profile.json --format json --out fp.json

# Compile multiple saved JSON artifacts into a self-contained autoescaped HTML report
s1shell report build \
  --input profile.json --input fp.json --input cves.json --input intel.json \
  --operator "Jane Doe" --format html --out report.html

# Inspect and filter tamper-evident audit logs
s1shell audit list --category target --outcome blocked_out_of_scope --limit 50
s1shell audit verify
```

### Custom Passive Fingerprint Signatures (`~/.s1shell/signatures.d/`)

Drop any `*.yaml` file into `~/.s1shell/signatures.d/` to extend S1shell's 81 bundled passive rules without modifying source code:

```yaml
signatures:
  - vendor: "Internal Corp"
    product: "Custom Edge Gateway"
    category: "waf"
    confidence: "high"
    headers:
      - name: "x-corp-edge"
        pattern: "^edge/([\\d.]+)"
```

### CI/CD & GitHub Code Scanning (SARIF 2.1.0)

```yaml
- name: Run S1shell Dependency & Authorized Target Gate
  run: |
    s1shell cve audit requirements.txt --enrich --format sarif --out deps.sarif --fail-on HIGH
    s1shell assess https://staging.example.com --authorized \
      --preset api --fail-on HIGH --min-score 80 --format sarif --out target.sarif

- name: Upload SARIF to GitHub Security Tab
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: target.sarif
```

### Read-Only Offline MCP Server (`s1shell mcp serve`)

Exposes **12 strictly read-only offline/intel tools** over JSON-RPC 2.0 stdio (`s1shell_doctor`, `s1shell_scope_list`, `s1shell_fingerprint_from_profile`, `s1shell_cve_search`, `s1shell_cve_get`, `s1shell_cve_audit`, `s1shell_assess_diff`, `s1shell_remediate`, `s1shell_intel_lookup`, `s1shell_intel_advisory`, `s1shell_audit_list`, `s1shell_audit_verify`) with zero target-touching capability.

Example MCP client configuration:

```json
{
  "mcpServers": {
    "s1shell": {
      "command": "s1shell",
      "args": ["mcp", "serve"]
    }
  }
}
```

---

## Environment Variables & API Feeds

Variables resolve in order: **process environment > project `./.env` > `~/.s1shell/.env`** (see [.env.example](.env.example)). Files written by `s1shell intel env` and `s1shell ai env` are enforced as `0600` and gitignored.

| Variable | Module | Purpose |
|---|---|---|
| `NVD_API_KEY` | `cve`, `assess` | Raises NVD 2.0 quota from 5 req/30s to 50 req/30s |
| `GITHUB_TOKEN` | `intel`, `cve` | Authenticates GitHub Security Advisories (GHSA) lookups & CVE enrichment |
| `VIRUSTOTAL_API_KEY` | `intel`, `assess --intel` | Passive VirusTotal v3 domain/IP reputation |
| `GREYNOISE_API_KEY` | `intel`, `assess --intel` | Passive GreyNoise Community IP scanner & benign RIOT lookup |
| `URLSCAN_API_KEY` | `intel`, `assess --intel` | Passive urlscan.io historical Search API index lookup |
| `S1SHELL_AI_PROVIDER` | `ai`, `assess --ai` | `anthropic` (default), `ollama`, `openai_compat`, or `gemini` |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `GEMINI_API_KEY` | `ai` | Cloud LLM inference credentials (not needed for local `ollama`) |
| `S1SHELL_HOME` | All | Override state directory (default `~/.s1shell`) |

---

## Command & Flag Reference

### Modules & Commands

| Command | Network Contact | Purpose |
|---|---|---|
| `s1shell assess <target \| --targets-file>` | Scoped target + NVD/KEV/EPSS (+ optional VT/GN/urlscan with `--intel`) | Unified profile, fingerprint, CVE, intel, posture, playbook, & report bundle |
| `s1shell scope add \| import \| list \| check \| remove \| expire` | DNS on `check` only | Manage authorized allow/exclude rules & bulk imports in `scope.yaml` |
| `s1shell cve search \| get \| audit \| cache clear` | Public NVD / CVE.org / OSV.dev / GHSA / KEV / EPSS | CVE lookup, SSVC priority triage, & lockfile/SBOM auditing |
| `s1shell intel env \| lookup \| advisory` | Public VT / GreyNoise / urlscan Search / GitHub GHSA | Zero-target-contact passive threat intel & `.env` key manager |
| `s1shell profile <target>` | Single target (1 GET + TLS + opt-in checks) | DNS hygiene, TLS/SPKI/ciphers, headers, cookies, cache, HTML, `OPTIONS` |
| `s1shell fingerprint [<target> \| --from-profile FILE]` | None (`--from-profile`) or 1 GET | Passive server/CDN/WAF/JS-library identification with CPE 2.3 |
| `s1shell remediate <assess.json>` | None (offline) | Deterministic stack-tailored hardening config generator |
| `s1shell diff <base.json> <curr.json>` | None (offline) | Security posture drift detection & CI regression gate |
| `s1shell report build` | None (offline) | Compile artifacts into JSON, Markdown, SARIF 2.1.0, or HTML |
| `s1shell ai env \| analyze` | Configured AI endpoint (or local Ollama) | Manage `.env` credentials & redacted defensive AI analysis |
| `s1shell audit list \| verify` | None (offline) | Inspect & verify SHA-256 hash chain integrity of `audit.log` |
| `s1shell mcp serve` | Offline / public intel only | Stdio JSON-RPC 2.0 MCP server exposing 12 strictly read-only tools |
| `s1shell doctor` / `s1shell completion {bash,zsh,fish}` | None (offline) | Local environment diagnostics & shell tab-completion |

### Common Global Flags (Accepted Before or After Subcommands)

| Flag | Description |
|---|---|
| `--format {table,json,md,html,sarif}` | Output format (`html` on `report build` / `assess`; `sarif` on `report build` / `assess` / `cve audit`) |
| `--out FILE` | Write output to `FILE` instead of stdout |
| `--authorized` | Non-interactive authorization confirmation for target-touching commands |
| `--scope-file FILE` | Override path to `scope.yaml` |
| `--home DIR` | Override state directory (default `~/.s1shell` or `$S1SHELL_HOME`) |
| `--no-color` | Disable ANSI colors in terminal tables |
| `--verbose` | Print full tracebacks to stderr on unexpected errors |
| `--version` | Show installed `s1shell` version |

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Validation, network, or runtime error |
| `2` | Target out of scope, excluded, expired, or unsafe IP resolution |
| `3` | Operator authorization not confirmed |
| `4` | CI policy gate threshold breached (`--fail-on`, `--min-score`, `--fail-on-regression`) |

---

## Documentation

- [Architecture](docs/architecture.md)
- [Artifact & Log Schemas](docs/schemas.md)
- [Changelog](CHANGELOG.md)
- [Contributing Guide](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security Policy](SECURITY.md)
