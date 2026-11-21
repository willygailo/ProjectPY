# Changelog

All notable changes to S1shell will be documented in this file.

## [Unreleased]

### Added — Offline Local Security Scanner (`s1shell scan`), Deep Policy/Crypto Analyzers (`s1shell analyze`) & Expanded Hardening
- **Local Secret, IaC/Config & SBOM Scanner (`s1shell scan`, `src/s1shell/scan/`)**:
  - `s1shell scan secrets [path] [--git-staged | --git-diff REF] [--fail-on SEV] [--format sarif]`: 27+ redacted credential detectors (AWS, GCP, Azure, GitHub, GitLab, Anthropic, OpenAI, Hugging Face, Stripe, Slack, Discord, Telegram, SendGrid, Mailgun, Twilio, npm, PyPI, Docker Hub, Vault, Shopify, PEM keys, DB URIs, JWTs, high-entropy generic assignments) with `.gitignore`/binary filtering, placeholder rejection, inline `# s1shell:ignore` suppression tracking, and line/column-accurate SARIF 2.1.0 output.
  - `s1shell scan config [path] [--fail-on SEV] [--format sarif]`: Deterministic IaC & service security auditor for Dockerfiles, Kubernetes manifests, GitHub Actions workflows (incl. `pull_request_target` Pwn Request & expression injection), Docker Compose, NGINX, `.env`, and `sshd_config`.
  - `s1shell scan sbom [path] [--raw-bom]`: Generates spec-compliant **CycloneDX 1.5 JSON SBOMs** from lockfiles, `pyproject.toml`, `package.json`, and Dockerfile base images, directly consumable by `s1shell cve audit`.
- **Deep Security Policy, Email Auth, Offline Header & CVSS Analyzers (`s1shell analyze`, `src/s1shell/analyze/`)**:
  - `s1shell analyze csp`: CSP3 static evaluator with 28-domain JSONP/script-gadget bypass DB, duplicate/typo directive detection, nonce entropy checks, grading, and hardened CSP rewrites.
  - `s1shell analyze email`: Offline or live-DNS SPF (IPv4 CIDR blast radius & lookup budget), DMARC (policy/subdomain/pct/alignment/reporting), and cryptographic DKIM public-key DER bit-length auditor.
  - `s1shell analyze headers`: 100%-offline raw HTTP header (`curl -i`, Burp, DevTools, or `profile.json`) security posture, CSP3, stack fingerprint, EOL, and remediation auditor.
  - `s1shell analyze cvss`: Upgraded `cve/cvss.py` with full FIRST CVSS v3.0/v3.1 Base, Temporal, Environmental, and Exploitability/Impact sub-score calculations plus CVSS v4.0 vector validation/decoding.
- **Anthropic User-Scoped Key (`sk-ant-usr*`) & Workspace Support (`config.py`, `ai/client.py`, `ai/service.py`, `doctor.py`)**:
  - Added `ANTHROPIC_WORKSPACE_ID` (`s1shell ai env --workspace-id wrkspc_...`), automatic `anthropic-workspace-id` header forwarding in `AnthropicClient`, `user` key classification in `doctor` / `ai env`, and `sk-ant-usr*` leak detection in `scan secrets`.
- **Expanded Remediation Playbooks, Offline EOL DB, MCP Tools & Automated Test Suite**:
  - Added `cloudflare` and `traefik` remediation stacks, fixed Caddy `HDR-HSTS-WEAK`/`HDR-CSP-UNSAFE` coverage, and added CORS/SRI/OIDC/JWKS/LEAK remediation snippets in `assess/remediate.py`.
  - Expanded offline `fingerprint/eol.yaml` with 14 additional production technologies (PostgreSQL, MySQL, Redis, Envoy, Traefik, Varnish, Django, Rails, Laravel, Next.js, OpenSSH, Grafana, Jenkins).
  - Exposed 7 new read-only MCP tools (`30` default / `33` opt-in scoped tools) and 5 new ReAct investigator tools (`14` total), updated `help_guide.py` and shell completions, and added an offline `pytest` test suite in `tests/`.

## [0.5.0] - 2026-11-20

### Added — Advanced Defensive AI Tactics, Skills Library, Pipelines & Read-Only Investigator (`s1shell ai`)
- **Prompt-Injection Guardrails & Signal-First Distillation (`ai/guardrails.py`, `ai/distill.py`)**:
  - Wrapped untrusted telemetry in nonce-tagged `<untrusted_telemetry id="t_...">` delimiters with tag-breakout neutralization and heuristic prompt-injection detectors surfaced in `injection_warnings` and audit logs.
  - Added artifact-aware distillation compacting oversized `assess`, `profile`, `cve`, `intel`, `dependency_audit`, and `ct` reports while preserving findings, CVEs, KEV/EPSS priority, and EOL signals (`--no-compact` available).
  - Added reversible NDA redaction (`--redact --restore`), air-gap `--local-only` loopback endpoint enforcement, SQLite LLM response caching (`--cache` / `--refresh`), and HTTP `429`/`502`/`503`/`504` retry/backoff with `--fallback <provider>` failover.
- **Declarative Defensive AI Skills Library (`ai/skills.yaml`, `ai/skills.py`)**:
  - Shipped **9 built-in defensive skills** (`attack-path-modeling`, `pentest-report-writer`, `threat-intel-correlator`, `sbom-supply-chain`, `zero-trust-hardening`, `compliance-mapper`, `detection-engineering`, `retest-diff-brief`, `token-crypto-auditor`) plus custom `~/.s1shell/skills.d/*.yaml` overrides, inspectable via `s1shell ai skills list|show` and `s1shell doctor`.
  - Added `--skill <id>` and `--structured` validated JSON output (with single automatic repair pass) across `ai analyze` and `assess --ai-triage --ai-skill ...`.
- **Multi-Stage Pipelines & Deterministic Anti-Hallucination Grounding (`ai/pipelines.py`, `ai/verify.py`)**:
  - Added `--pipeline {deep-triage,purple-team,executive-pack}` chaining specialized Analyst -> Architect -> Critic / Blue-Team stages (`--ai-pipeline` also supported on `assess`).
  - Added offline regex grounding verifier (`grounding_score`, `verified_refs`, `ungrounded_refs`) checking every cited Finding and CVE ID against input artifacts.
- **Read-Only Agentic Investigator & Interactive Copilot (`ai/investigate.py`, `s1shell ai investigate|chat`)**:
  - Added `s1shell ai investigate --goal "..." --input ... --max-steps N` executing a bounded (1–8 steps) ReAct loop strictly allowlisted to **9 offline/passive read-only S1shell tools** (zero target-touching capability) with full audit logging and grounding verification.
  - Added interactive multi-turn `s1shell ai chat` supporting `/skill`, `/skills`, `/verify`, `/save`, and `/exit`.
- **Online Streamable HTTP & Local Stdio MCP Server (`mcp_server.py`, `s1shell mcp serve|config|ping`)**:
  - Upgraded `s1shell mcp serve` to support both **Online Streamable HTTP (`--transport http`, MCP `2025-03-26`, `POST /mcp`, `GET /healthz`, `DELETE /mcp`)** and local `stdio` with zero extra dependencies (`http.server.ThreadingHTTPServer`).
  - Added fail-closed online security guards: loopback default (`127.0.0.1:8765`), mandatory Bearer auth (`--token` / `--generate-token` / `S1SHELL_MCP_TOKEN`) when binding non-loopback hosts, constant-time `secrets.compare_digest` verification, `Origin` DNS-rebinding protection (`--allow-origin`), and 2 MiB request body cap.
  - Added `s1shell_ai_analyze` (`22` default online/offline read-only tools), native **MCP Resources** (`s1shell://doctor`, `s1shell://scope`, `s1shell://skills`, `s1shell://audit/recent`), native **MCP Prompts** (all 9+ defensive AI skills), and opt-in fail-closed **`--allow-scoped-targets --authorized`** mode (`+3` guarded read-only tools: `s1shell_profile`, `s1shell_fingerprint`, `s1shell_assess`).
  - Added `s1shell mcp config {antigravity,claude,cursor,vscode,windsurf,http}` and `s1shell mcp ping` CLI utilities.
- **Defensive Tor (`socks5h://`) Routing, Zero-DNS-Leak DoH & v3 `.onion` Auditing (`tor.py`, `s1shell tor status|check`, `--tor`, `--tor-targets`)**:
  - Added fail-closed `--tor` Analyst OPSEC routing (`socks5h://127.0.0.1:9050` / `9150`) across all passive OSINT, CVE, SBOM, Threat-Intel, and Cloud AI feeds (`S1SHELL_TOR=1`), automatically bypassing Tor for local loopback Ollama/MCP endpoints and rejecting DNS-leaking `socks5://` schemes or remote proxies.
  - Added opt-in `--tor --tor-targets --authorized` zero-leak routing for authorized public target URLs/domains using a pure-Python RFC 1928 SOCKS5h tunnel (`ATYP 0x03`) for full TLS/X.509/ALPN handshakes, Tor-tunneled DNS-over-HTTPS (`TorDoHResolver`) for scope anti-SSRF validation and DNS hygiene, and `socks5h://` single-GET HTTP/well-known/`OPTIONS` fetches — enabling **Direct vs Tor perspective diffs** (`s1shell diff`) while strictly forbidding private/CGNAT targets, silent clearnet fallback, and IP rotation (`NEWNYM`).
  - Added strict RFC 7686 **Tor v3 `.onion`** scope support (`type: "onion"`, 56-char base32; rejects deprecated v2 `.onion`, zero local DNS queries), `s1shell tor status|check`, `tor_proxy` check in `s1shell doctor`, and `s1shell_tor_status` in `s1shell mcp serve` (`23` default / `26` scoped tools).
- **Leading-Dot / Wildcard TLD Scope Rules & Project `scope.yaml` Auto-Discovery (`scope.py`, `config.py`, `scope.yaml.example`)**:
  - Added leading-dot TLD & domain syntax (`.com`, `.ph`, `.com.ph`, `.gov.ph`, `.edu.ph`, `.org`, `.net`, `.io`, etc.) alongside `*.domain` in `s1shell scope add|import`, automatically normalizing to `include_subdomains: true`.
  - Added automatic project `./scope.yaml` fallback discovery when `~/.s1shell/scope.yaml` is not present yet, plus a tracked `scope.yaml.example` template with 35 pre-configured Philippine (`.ph`, `.com.ph`, `.gov.ph`, `.edu.ph`, `.org.ph`, `.net.ph`), global, and regional TLD entries.
- **Passive Target Identity, Contacts (Email / Gmail / Phone), Keys / Client-IDs & Surface Entity Output (`profile/html_check.py`, `intel/clients.py`, `output.py`, `report.html.j2`)**:
  - Added zero-extra-packet extraction of target **Emails & `[Gmail]` contacts**, **Phone/Contact numbers** (`tel:`, `JSON-LD`, international/PH numbers), **Exposed Keys & Client/App IDs** (GA4/UA, GTM, Google Ads/AdSense, Firebase `apiKey`/`projectId`/`appId`, Meta Pixel/App ID, Stripe publishable/live keys, reCAPTCHA/Turnstile `sitekey`, OAuth `client_id`, Sentry DSN, Mapbox tokens, Supabase URLs, AWS/GCP/GitHub/Slack/Discord/Telegram/Twilio/SendGrid/Mailgun/OpenAI tokens, and passive JWT claims), **Names/Organizations** (`meta` + Schema.org `JSON-LD`), **Form Endpoints & High-Interest Input Parameters** (`redirect_uri*`, `url*`, `file*`, `id*`, `token*`, `admin*`), **Internal RFC1918 IPs / `.internal` Hostnames & Developer HTML Comments**, **Social links**, and **Cloud storage buckets / API paths**.
  - Added `HTML-009` (High-interest form/URL parameters exposed) and `HTML-010` (Internal IP/hostname or developer comment exposed) findings to `assess/scorer.py`, expanded cloud/SaaS CNAME takeover suffixes to 33 providers in `profile/dns_check.py`, and highlighted high-interest pentest subdomains (`admin`, `api`, `dev`, `staging`, `vpn`, `portal`, `auth`, `sso`, `jenkins`, `gitlab`, `grafana`, etc.) in `s1shell intel ct`.
  - Enhanced RDAP parsing (`parse_rdap_payload`) to extract public vCard contact emails, phone numbers (`tel`), and entity names/handles/roles.
  - Added a dedicated **`Target Identity, Contacts (Email / Gmail / Phone) & Surface Entities`** table to `s1shell profile` and `s1shell assess` (`table`, `md`, `json`, and `html` reports).

### Fixed
- **Subdomain & URL-to-Apex Fallback on `intel rdap`, `intel ct`, & `intel lookup` (`intel/clients.py`)**: Added `_domain_lookup_candidates()` (with 2-label ccSLD awareness for `.com.ph`, `.gov.ph`, `.edu.ph`, `.org.ph`, `.net.ph`, `.co.uk`, etc.) so passing a full URL or subdomain (e.g. `s1shell intel rdap https://m.gsmarena.com` or `portal.acme.com.ph`) automatically falls back to the registrable apex domain (`gsmarena.com` / `acme.com.ph`) instead of failing with HTTP 404.
- **HTTPS IP-Literal TLS Handshake (`profile/tls_check.py`)**: Fixed `ValueError: check_hostname requires server_hostname` when profiling HTTPS IP targets (e.g. `https://1.1.1.1` or `https://127.0.0.1`) by passing the IP literal as `server_hostname` during verified TLS handshakes so Python's `ssl` validates IP SANs cleanly.
- **Scope Table Rendering (`output.py`)**: Prevented Rich 80-column table truncation on `s1shell scope list` when long v3 `.onion` or URL-prefix entries are present (`min_width=16, overflow="fold"`).

## [0.4.2] - 2026-11-20

### Security & Reliability Hardening
- **Scope Guard SSRF & Exclusion Hardening (`scope.py`)**: Hardened `is_special_ip()` to block non-global ranges including RFC 6598 CGNAT (`100.64.0.0/10`, covering Tailscale and cloud metadata endpoints like `100.100.100.200`), NAT64 (`64:ff9b::/96`), and embedded IPv4-mapped IPv6 addresses (`::ffff:0:0/96`), and unwrapped embedded IPv4 addresses during both direct-IP and DNS-resolved `--exclude` matching.
- **Race-Free, `O(1)` Hash-Chained Audit Log (`audit.py`)**: Replaced full-file read + unlocked append with exclusive POSIX `fcntl.flock` locking, atomic `0600` creation, and backward EOF tail-seeking so concurrent CLI/MCP writes preserve SHA-256 hash chain integrity.
- **Atomic `0600` Credential & Scope Writes (`config.py`, `scope.py`, `ai/service.py`, `intel/service.py`)**: Added `atomic_write_private()` using `os.open(..., 0o600)` on a temp file + `os.replace()` to eliminate the `0644 -> 0600` permission window and partial-write corruption on `scope.yaml` and `.env`.
- **Hardened Cloud AI Telemetry Redactor (`ai/redact.py`)**: Added IPv6 address redaction, sensitive header scrubbing (`Cookie`, `Authorization`, `Proxy-Authorization`, `X-Api-Key`, `X-Auth-Token`, `X-CSRF-Token`), sensitive URL query parameter redaction, and inline Bearer/JWT redaction.

### Fixed & Improved
- **MCP Server Sync & Read-Only Tools (`mcp_server.py`)**: Synced `s1shell_cve_audit` schema (`recursive` flag and all 14 lockfile/SBOM formats), added batch `cve_ids` support to `s1shell_cve_get`, updated `s1shell_intel_lookup`/`s1shell_remediate` descriptions, and added `s1shell_codec_hash` and `s1shell_scope_check` (`19` strictly read-only tools total).
- **Intel Client Resilience (`intel/clients.py`)**: Added bounded retry/backoff on HTTP `429`/`502`/`503`/`504` (honoring `Retry-After`) across VirusTotal, GreyNoise, urlscan.io, GitHub Advisories, `crt.sh`, and RDAP clients.
- **Batch `--no-remediate` & Dependency Upgrade Selection**: Forwarded `--no-remediate` in `assess --targets-file` batch mode, fixed `build_upgrade_commands()` to choose the highest semantic fixed version across multiple CVEs via `compare_versions()`, and aligned `pyproject.toml` repository URLs.

## [0.4.1] - 2026-11-20

### Added — Offline Codec, Multi-Layer Auto-Decoder & Smart Artifact Inspector (`s1shell codec`)
- **`s1shell codec decode`**: Offline decoder supporting `auto` (magic recursive peeling up to 12 layers with full trace), `base64`/`base64url`/`base32`/`base58`/`base85`/`ascii85`, `hex` (`0x`, spaces, colons, `\x`), `url`, `html`, `unicode`, `quoted-printable`, `rot13`, `caesar` (`--shift`, `--all-shifts` 1–25), `binary`, `octal`, `decimal`, `morse`, `punycode` (IDNA), `gzip`/`zlib`/`deflate` (with 8 MiB anti-zip-bomb cap), `saml` (URL/Base64/Deflate -> pretty XML), `jwt`, ordered `--chain` pipelines, stdin/`--file`/inline input, and `--raw` output.
- **`s1shell codec encode`**: Single or chained encoding across 25 codecs including `hex-escaped`, `url-all`, `gzip-b64`, and `zlib-b64`.
- **`s1shell codec inspect`**: Smart offline artifact analyzer identifying JWTs (with UTC timestamps & hygiene warnings), X.509 PEM/DER certificates (with SPKI pin & validity), cryptographic hash formats (`MD5`/`SHA-1`/`SHA-256`/`SHA-512`/`NTLM`/`bcrypt`/`Argon2`/`scrypt`/`PBKDF2`/`UUID`), Unix epoch timestamps, Shannon entropy, and nested encodings.
- **`s1shell codec hash`**: Computes `MD5`, `SHA-1`, `SHA-256`, `SHA-384`, `SHA-512`, `BLAKE2b`, `CRC32`, and Shannon entropy for inline text, stdin, or local files.
- **MCP & Shell Completions**: Added `s1shell_codec_decode`, `s1shell_codec_encode`, and `s1shell_codec_inspect` to `s1shell mcp serve` (`17` read-only MCP tools total) and updated Bash/Zsh/Fish completions.

## [0.4.0] - 2026-11-20

### Added — Deep Passive OSINT, Crypto/Email/Identity Profiling, & Supply-Chain v2
- **Passive OSINT Depth (`s1shell intel ct` & `s1shell intel rdap` — Zero API Key / Zero Target Contact)**:
  - `s1shell intel ct <domain> [--export-candidates FILE]`: Queries public Certificate Transparency logs (`crt.sh`), deduplicates passive SAN subdomains and wildcard SANs, summarizes active/expired certs and CA issuers, caches in SQLite, and optionally writes a candidate target list for authorization review before `scope import`.
  - `s1shell intel rdap <domain|ip>`: Queries RFC 7480–7484 RDAP registration data (registrar, organization, transfer lock status, DNSSEC delegation, domain age & expiry countdown, IP CIDR allocation, abuse contact) — also integrated into `intel lookup --sources ...,rdap` and `assess --intel` (`INTEL-RDAP-EXPIRING`, `INTEL-RDAP-UNLOCKED`, `INTEL-ORIGIN-DRIFT`).
  - Exposed `s1shell_intel_ct` and `s1shell_intel_rdap` on the read-only stdio MCP server (14 tools total).
- **Deep Read-Only Target Profiling (`profile` & `fingerprint` v2)**:
  - **Full X.509 Chain & CAA-vs-Issuer Alignment**: Parses full presented TLS certificate chains (detecting missing intermediates, expiring/expired intermediates, SHA-1 intermediates, and chain order mismatches -> `TLS-CHAIN`) and cross-checks leaf cert issuers against DNS `CAA` records (`TLS-CAA-MISMATCH`).
  - **Recursive RFC 7208 SPF Expansion, BIMI, DANE/TLSA & Expanded PSL**: Bounded recursive SPF `include:`/`redirect=` expansion catching cumulative >10 DNS lookups, >2 void lookups, loops, `+all`, and overly broad IPv4 CIDRs (`DNS-SPF-RECURSIVE`, `DNS-SPF-PERMISSIVE`), plus passive BIMI (`default._bimi`), DANE/TLSA (`_443._tcp`), and ~70 multi-part ccTLD Public Suffix entries (e.g. `gov.ph`, `edu.ph`, `co.id`, `com.my`).
  - **RFC Well-Known OIDC, JWKS & Mobile Trust Audit**: Opt-in `--well-known` now also reviews `/.well-known/openid-configuration` (`OIDC-001`), `/.well-known/jwks.json` (`JWKS-PRIV` critical private-key leak check & `JWKS-WEAK`), `assetlinks.json`, and `apple-app-site-association`.
  - **Zero-Extra-Packet Passive Exposure & JWT Inspector + CSP v2**: Detects and **redacts** accidentally exposed credentials/API keys/PEM headers/DB URIs (`LEAK-SECRET`), passively audits JWT headers/claims in HTML/cookies/headers (`LEAK-JWT`), flags exposed JS source maps (`LEAK-SOURCEMAP`) and framework stack traces (`LEAK-TRACE`), and checks wildcard `blob:`/`https:` script-src CSP directives.
  - **Offline End-of-Life (EOL) Software Database (`eol.yaml`)**: Flags unmaintained/EOL versions of NGINX, Apache, PHP, Python, Node.js, OpenSSL, jQuery, Bootstrap, AngularJS, WordPress, Drupal, Tomcat, IIS, Lodash, Moment.js, and HAProxy (`EOL-001`, CWE-1104) with zero network traffic.
- **Supply-Chain & SBOM Auditing v2 (`s1shell cve audit`)**:
  - Added pure-Python **FIRST CVSS v3.0/v3.1 Base Score Calculator** (`cve/cvss.py`) fixing numeric severity extraction from OSV CVSS vector strings.
  - Added parsers for `uv.lock`, `poetry.lock`, `Pipfile.lock`, `yarn.lock`, `pnpm-lock.yaml`, `composer.lock`, `Gemfile.lock`, `pom.xml`, and **SPDX 2.3 JSON SBOMs**.
  - Added `--recursive` directory scanning (`s1shell cve audit ./repo --recursive`), per-file SARIF 2.1.0 locations, `unpatched_count`, and deterministic ecosystem-specific `upgrade_commands`.

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
