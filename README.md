# S1shell

**S1shell** is an open-source, defensive CLI toolkit built for Kali Linux and standard Linux environments to support **authorized security assessments**, **CVE & SBOM/dependency research**, **scoped read-only target profiling**, **passive technology verification**, **deterministic hardening playbooks**, **posture drift diffing**, and **auditable SARIF/HTML/Markdown reporting**.

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

---

## Quickstart for Advanced Authorized Assessments

### 1. Verify Environment & Audit Integrity

```bash
s1shell doctor
s1shell audit verify
```

### 2. Onboard Scope (Single Target or Bulk Import with Exclusions)

```bash
# Single target or exclusion
s1shell scope add example.com --include-subdomains --owner "ACME IT" --ref "SOW-2026-014" --expires 2026-12-31
s1shell scope add billing.example.com --exclude --owner "ACME IT" --ref "SOW-2026-014" --expires 2026-12-31

# Bulk import targets from a file (prefix `!` on any line to mark an exclusion)
s1shell scope import targets.txt --owner "ACME IT" --ref "SOW-2026-014" --expires 2026-12-31 --dry-run
s1shell scope import targets.txt --owner "ACME IT" --ref "SOW-2026-014" --expires 2026-12-31
```

### 3. All-in-One Target or Batch Assessment (`s1shell assess`)

Runs **read-only profile (DNS hygiene, TLS/X.509/SPKI/ciphers, headers, cookies, cache, passive HTML, optional `OPTIONS` methods & well-known) -> passive fingerprint (servers, CDNs, WAFs, JS libraries) -> CPE-verified CVE + KEV/EPSS correlation -> preset posture scoring (CWE/ASVS/OWASP/NIST) -> deterministic hardening playbook -> HTML/MD/SARIF/JSON bundle**:

```bash
# Full web assessment with KEV/EPSS enrichment, well-known, OPTIONS method check, and full report bundle
s1shell assess https://app.example.com --authorized \
  --enrich-cve --well-known --check-methods \
  --operator "Jane Doe" --out-dir ./assessment-out

# API-focused assessment preset with CI policy gates (exit 4 on breach)
s1shell assess https://api.example.com --authorized \
  --preset api --check-methods --fail-on HIGH --min-score 80 --format sarif --out api.sarif

# Sequential guarded batch assessment (concurrency=1, scope-gated per target, HTML dashboard)
s1shell assess --targets-file in_scope_urls.txt --authorized \
  --delay 0.5 --enrich-cve --fail-on CRITICAL --out-dir ./batch-out
```

### 4. Offline Deterministic Remediation Playbook (`s1shell remediate`)

Generate copy-pasteable hardening configs (`nginx`, `apache`, `caddy`, `express`, `dns`, `security.txt`) directly from a saved `assess.json` with **zero AI / zero network**:

```bash
s1shell remediate ./assessment-out/assess.json --stack auto --format md --out hardening.md
```

### 5. Posture Drift Diffing (`s1shell diff`)

Compare baseline vs current `assess.json` snapshots in CI or re-test engagements:

```bash
s1shell diff ./baseline/assess.json ./assessment-out/assess.json --fail-on-regression
```

### 6. Lockfile & CycloneDX SBOM Auditing (`s1shell cve audit`)

Zero-target-contact vulnerability scanning for `requirements.txt`, `package-lock.json`, `go.mod`, `Cargo.lock`, and CycloneDX JSON SBOMs via OSV.dev + CISA KEV + FIRST EPSS:

```bash
s1shell cve audit requirements.txt --enrich --fail-on HIGH
s1shell cve audit sbom.cdx.json --enrich --format sarif --out sbom.sarif
```

### 7. Multi-CVE Research & KEV/EPSS Prioritization (`s1shell cve`)

```bash
# Search NVD with KEV/EPSS enrichment & SSVC-style P0-P3 priority tiers
s1shell cve search --keyword "nginx 1.18" --min-cvss 7.0 --enrich
s1shell cve search --from-fingerprint ./assessment-out/fingerprint.json --kev-only

# Look up one or multiple specific CVE IDs
s1shell cve get CVE-2021-23017 CVE-2023-44487 --enrich
```

### 8. Multi-Provider Defensive AI Triage (`s1shell ai`)

Supports **Anthropic**, local air-gapped **Ollama**, **OpenAI-compatible**, and **Google Gemini** endpoints with prompt-injection isolation (`<untrusted_telemetry>`) and reversible NDA-safe redaction (`--redact`):

```bash
# Configure local air-gapped Ollama (zero cloud telemetry)
s1shell ai env --provider ollama --model "llama3.1:8b"

# Or configure cloud inference with automatic redaction
s1shell ai analyze --input ./assessment-out/assess.json --mode remediate --redact --format md
```

### 9. Read-Only Offline MCP Server (`s1shell mcp serve`)

Expose S1shell's offline/intel tools (`doctor`, `scope_list`, `fingerprint_from_profile`, `cve_search`, `cve_get`, `cve_audit`, `assess_diff`, `remediate`, `audit_list`, `audit_verify`) over JSON-RPC 2.0 stdio to MCP-compatible AI assistants without ever granting target-contact permissions:

```bash
s1shell mcp serve
```

---

## Command & Flag Reference

| Command | Network Contact | Purpose |
|---|---|---|
| `s1shell assess <target \| --targets-file>` | Scoped target + NVD/KEV/EPSS | Unified profile, fingerprint, CVE, posture, playbook, & report bundle |
| `s1shell scope add \| import \| list \| check \| remove \| expire` | DNS on `check` only | Manage authorized allow/exclude rules & bulk imports in `scope.yaml` |
| `s1shell cve search \| get \| audit \| cache clear` | Public NVD / CVE.org / OSV.dev / KEV / EPSS | CVE lookup, SSVC priority triage, & lockfile/SBOM auditing |
| `s1shell profile <target>` | Single target (1 GET + TLS + opt-in checks) | DNS hygiene, TLS/SPKI/ciphers, headers, cookies, cache, HTML, `OPTIONS` |
| `s1shell fingerprint [<target> \| --from-profile FILE]` | None (`--from-profile`) or 1 GET | Passive server/CDN/WAF/JS-library identification with CPE 2.3 |
| `s1shell remediate <assess.json>` | None (offline) | Deterministic stack-tailored hardening config generator |
| `s1shell diff <base.json> <curr.json>` | None (offline) | Security posture drift detection & CI regression gate |
| `s1shell report build` | None (offline) | Compile artifacts into JSON, Markdown, SARIF 2.1.0, or HTML |
| `s1shell ai env \| analyze` | Configured AI endpoint (or local Ollama) | Manage `.env` credentials & redacted defensive AI analysis |
| `s1shell audit list \| verify` | None (offline) | Inspect & verify SHA-256 hash chain integrity of `audit.log` |
| `s1shell mcp serve` | Offline / public intel only | Stdio JSON-RPC 2.0 MCP server for strictly read-only tools |
| `s1shell doctor` / `s1shell completion {bash,zsh,fish}` | None (offline) | Local environment diagnostics & shell tab-completion |

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Validation, network, or runtime error |
| `2` | Target out of scope, excluded, expired, or unsafe IP resolution |
| `3` | Operator authorization not confirmed |
| `4` | CI policy gate threshold breached (`--fail-on`, `--min-score`, `--fail-on-regression`) |

## Documentation

- [Architecture](docs/architecture.md)
- [Artifact & Log Schemas](docs/schemas.md)
- [Changelog](CHANGELOG.md)
- [Contributing Guide](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
