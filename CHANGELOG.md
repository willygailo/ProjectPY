# Changelog

All notable changes to S1shell will be documented in this file.

## [0.3.0] - 2026-11-20

### Added — Passive Multi-Feed Threat Intelligence (`s1shell intel`)
- **New `s1shell intel` Module (Zero Target Contact)**:
  - `s1shell intel env`: Inspect masked status and securely persist `NVD_API_KEY`, `GITHUB_TOKEN`, `VIRUSTOTAL_API_KEY`, `GREYNOISE_API_KEY`, and `URLSCAN_API_KEY` into a `0600` `.env` file.
  - `s1shell intel lookup <domain-or-ip>`: Passive domain/IP reputation via **VirusTotal v3**, IP scanner/benign RIOT context via **GreyNoise Community**, and strictly passive historical footprint via **urlscan.io Search API** — cached in SQLite (`--offline` supported) with graceful degradation.
  - `s1shell intel advisory`: Query the **GitHub Security Advisories (GHSA)** REST API by CVE ID or ecosystem+package.
- **GHSA Enrichment on `cve get --enrich`**: Automatically attaches matching GHSA IDs, advisory URLs, and first-patched versions when `GITHUB_TOKEN` is configured.
- **Assessment Threat Intel Correlation (`s1shell assess --intel`)**: Enriches scoped assessments with VirusTotal, GreyNoise, and urlscan.io passive telemetry, adds `INTEL-VT-MAL`, `INTEL-GN-MAL`, and `INTEL-GN-RIOT` findings to posture scoring, saves `intel.json`, and renders a dedicated autoescaped **Passive Threat Intelligence** card in HTML and Markdown reports.
- **Diagnostics, Reports & MCP**: Updated `s1shell doctor` to report masked status for all 5 intel feeds, added `intel_report` support in `s1shell report build`, and exposed `s1shell_intel_lookup` and `s1shell_intel_advisory` in `s1shell mcp serve`.

## [0.2.0] - 2026-11-20

### Added — Advanced Pentester & AppSec Suite
- **Dependency & CycloneDX SBOM Auditing (`s1shell cve audit <file>`)**: Zero-target-contact vulnerability scanning for `requirements.txt`, `package-lock.json`, `go.mod`, `Cargo.lock`, and CycloneDX JSON SBOMs via public OSV.dev batch API with SQLite caching, CISA KEV/EPSS enrichment, SARIF 2.1.0 output, and `--fail-on` CI gates.
- **SSVC-Style CVE Risk Priority & Multi-CVE Lookup**: Automatic `P0-IMMEDIATE` / `P1-URGENT` / `P2-SCHEDULED` / `P3-MONITOR` priority tiering combining KEV + EPSS + CVSS, plus batch `s1shell cve get CVE-1 CVE-2 ...`.
- **Deterministic Offline Hardening Playbook (`s1shell remediate <assess.json>`)**: Generates stack-tailored defensive configuration snippets (`nginx`, `apache`, `caddy`, `express`, `dns`, `security.txt`, `generic`) directly from findings with zero AI/network required; also embedded in `assess` bundles and reports.
- **Assessment Presets, Waivers & Compliance Mapping**: Added `--preset {web,api,strict}` and repeatable `--ignore-finding ID` waivers to `s1shell assess`, plus OWASP Top 10:2021 (`owasp`) and NIST SP 800-53 (`nist`) tags alongside CWE & OWASP ASVS across JSON, Markdown, HTML, and SARIF 2.1.0 outputs.
- **Bulk Scope Import & Exclusions (`s1shell scope import <file>`)**: Bulk-import newline-delimited target lists with inline `!exclude` rules and `--dry-run` validation, complementing deny-first `--exclude` scope governance.
- **Deeper Read-Only Target Profiling**:
  - Opt-in `--check-methods` (`OPTIONS` Allow inspection flagging `TRACE`/`TRACK`/`PUT`/`DELETE`/`WebDAV`).
  - X.509 SHA-256 certificate fingerprints, RFC 7469 SPKI SHA-256 pin hashes, serial numbers, OCSP Must-Staple, and EC curve strength checks.
  - Passive DNS `MX`, `NS`, `_mta-sts`, `_smtp._tls` (TLS-RPT), zone-apex fallback for subdomains, SPF RFC 7208 10-lookup counting, and DMARC policy parsing.
  - Sensitive response `Cache-Control` analysis, framework debug-header exposure detection (`X-Debug-Token`, `X-Laravel-Debug`, etc.), HTTPS-to-HTTP downgrade redirect detection, cookie scope/lifetime checks, and passive HTML `method="GET"` password form / `target="_blank"` `noopener` / third-party origin inventory.
- **Passive Client-Side Library CPE Correlation & Expanded Signatures**: Wired passively observed HTML JS libraries (`jQuery`, `Bootstrap`, `Lodash`, `Moment.js`, `DOMPurify`, `Handlebars`, `Axios`, `Swagger UI`) directly into `signatures.yaml` with CPE 2.3 identifiers, plus 15+ enterprise WAF/gateway/DevOps signatures (Citrix NetScaler, FortiWeb, ModSecurity, PAN-OS, Jira, Confluence, Keycloak, SonarQube, Kibana, MinIO, Squid, SvelteKit, Astro, Joomla, Magento).
- **Consolidated Batch HTML Dashboard & CI Gates**: `s1shell assess --targets-file` now generates a self-contained autoescaped `batch_report.html` dashboard, supports `--format html`, and enforces `--fail-on` severity gates alongside `--min-score`.
- **Expanded Read-Only MCP Server (`s1shell mcp serve`)**: Added `s1shell_remediate` and `s1shell_cve_audit` tools to the stdlib JSON-RPC 2.0 offline/intel MCP server.

### Fixed
- Fixed strict `mypy` type errors in `cve/service.py` and `assess/service.py` and resolved all Ruff lint/formatting issues across `src/` and `tests/`.
- Updated shell completions (`bash`, `zsh`, `fish`) and documentation to match all v0.2.0 modules and flags.

## [0.1.0] - 2026-11-18

### Added
- Scope governance (`scope add/list/check/remove/expire`) with DNS verification and private-IP escape guards.
- Append-only JSONL audit logging (`~/.s1shell/audit.log`) and `audit list` command.
- Policy gate (`guard.py`) enforcing scope -> authorization -> audit -> execution ordering.
- `cve` module with NVD REST API 2.0 and CVE.org clients, SQLite TTL cache, and token-bucket rate limiting.
- `profile` module for read-only DNS, single-handshake TLS/X.509, ALPN HTTP/2, `Alt-Svc` HTTP/3, security headers, banner disclosure, and cookie flags.
- `fingerprint` module with declarative `signatures.yaml` passive matching (standalone guarded mode and `--from-profile` offline mode).
- `report` module compiling `cve`, `profile`, and `fingerprint` outputs into JSON, Markdown, and autoescaped self-contained HTML.
- Kali Linux installer script (`scripts/install-kali.sh`) and offline `pytest` suite.
