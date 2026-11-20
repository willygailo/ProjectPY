# S1shell Architecture (`v0.5.0` — 16 Modules)

## Overview

S1shell separates **public vulnerability, SBOM & passive threat intelligence** (`cve`, `intel`), **target-touching read-only assessment** (`profile`, live `fingerprint`, `assess`), **defensive AI tactics & read-only ReAct investigation** (`ai`), **offline codec, remediation & drift analysis** (`codec`, `remediate`, `diff`, `report`), **online Streamable HTTP & local stdio MCP** (`mcp`), **zero-leak Tor SOCKS5h routing** (`tor`), and **local governance diagnostics** (`scope`, `audit`, `doctor`, `completion`) behind a mandatory fail-closed policy gate.

```text
  CLI (`cli.py` + `output.py`) & Online Streamable HTTP / Stdio MCP (`mcp_server.py`)
     │
     ├── 1. Target Commands (`profile`, live `fingerprint`, `assess [--targets-file]`)
     │      │
     │      ▼
     │   Policy Gate (`guard.py`)
     │      ├─ a. Parse & normalize target (`scope.py`: domain, IP, CIDR, URL prefix, v3 `.onion`)
     │      ├─ b. Check deny-first `--exclude` -> active allow + DNS/DoH-over-Tor anti-SSRF -> Exit 2
     │      ├─ c. Confirm `--authorized` or interactive TTY prompt -> Exit 3
     │      ├─ d. Execute bounded single-GET / OPTIONS + TLS (`target_fetch.py` / `http.py` / `tor.py`)
     │      └─ e. Append file-locked (`fcntl.flock`) O(1) SHA-256 hash-chained record (`audit.py`)
     │
     ├── 2. Passive Intel & Supply-Chain (`cve`, `intel`) — Zero Target Contact
     │      └─ SQLite TTL Cache (`cve/cache.py`) + HTTP 429/502/503/504 Retry-After Backoff
     │         (NVD 2.0 · CVE.org · OSV.dev 14 formats · KEV · EPSS · VT · GreyNoise · urlscan · GHSA · crt.sh · RDAP)
     │         (Optional `--tor` routes all public feeds via local `socks5h://127.0.0.1:9050`)
     │
     ├── 3. Defensive AI Engine (`ai/skills.py`, `ai/pipelines.py`, `ai/investigate.py`, `ai/verify.py`)
     │      ├─ 9 Bundled Skills (`skills.yaml`) + custom `~/.s1shell/skills.d/*.yaml`
     │      ├─ Signal-First Distiller (`distill.py`) + Nonce-Tagged `<untrusted_telemetry>` Guardrails
     │      ├─ Reversible NDA Redactor (`redact.py`: `--redact --restore`) + Citation Grounding Verifier
     │      ├─ Multi-Stage Pipelines (`deep-triage`, `purple-team`, `executive-pack`) & `--structured` JSON
     │      └─ Bounded Read-Only ReAct Investigator (`ai investigate`) & Interactive Copilot (`ai chat`)
     │         (Local Ollama `--local-only` auto-bypasses Tor; Anthropic, OpenAI-compat, Gemini)
     │
     ├── 4. Offline Codec, Playbooks & Reporting (`codec`, `remediate`, `diff`, `report`)
     │      └─ 25-Codec CyberChef-style Decoder/Inspector (`codec`), Stack Playbooks, Drift Gate (`exit 4`),
     │         Autoescaped Self-Contained HTML, Markdown, JSON, & SARIF 2.1.0
     │
     └── 5. Online Streamable HTTP & Stdio MCP (`mcp serve|config|ping`) + Diagnostics (`doctor`, `tor`)
            └─ MCP `2025-03-26`: 23 default tools (+3 opt-in scoped target tools = 26),
               4 live Resources, 9+ native Prompts, Bearer auth (`secrets.compare_digest`), & Origin guard
```

## DNS Rebinding, Redirect, Exclusion, SSRF & Tor Zero-Leak Safeguards

1. **Deny-First Exclusions & Structural Match Before DNS**: Active `--exclude` scope rules override broader allow rules (including `.com`, `.ph`, `.com.ph` leading-dot/wildcard TLD rules) before any DNS resolution occurs. Multiple allow matches resolve deterministically by specificity (`url_prefix` > `ip` > exact `domain`/`onion` > wildcard `domain`/`onion` > `cidr`).
2. **Special/Private/CGNAT/NAT64 IP Guard**: When a hostname resolves to loopback, RFC 1918 private, RFC 6598 CGNAT (`100.64.0.0/10`), NAT64 (`64:ff9b::/96`), IPv4-mapped IPv6 (`::ffff:0:0/96`), link-local (`169.254.169.254`), multicast, or reserved IPs (or an excluded IP), access is denied with exit code `2` unless an active `ip` or `cidr` allow entry explicitly covers that IP. Under `--tor --tor-targets`, private/special IPs are **always** forbidden.
3. **Direct IP Pinning vs Zero-Leak Tor (`socks5h://`)**:
   - **Direct Mode (Default):** `PinnedSyncBackend` pins TCP connections to the exact IP validated by `scope.py` while keeping the hostname for HTTP `Host`, TLS SNI, and X.509 verification (`trust_env=False`).
   - **Tor Target Mode (`--tor --tor-targets` or v3 `.onion`):** Resolves scope IPs and DNS hygiene via **DNS-over-HTTPS (DoH) tunneled over Tor `socks5h://`** (`TorDoHResolver`), tunnels TLS handshakes through a pure-Python RFC 1928 SOCKS5h (`ATYP 0x03`) stream (`open_socks5h_socket`), and routes single-GET HTTP via `socks5h://` — **fail-closed (`NetworkError`) with zero clearnet fallback and zero IP rotation (`NEWNYM`)**.
4. **No Automatic Redirects & Sequential Concurrency (`concurrency=1`)**: `follow_redirects=False` and `max_redirects=0` ensure `3xx` responses never pivot requests out of scope.

## Tamper-Evident Audit Chain, Prompt-Injection Isolation & Online MCP Security

- Every record written to `~/.s1shell/audit.log` uses exclusive `fcntl.flock` locking, atomic `0600` creation, and backward `O(1)` tail-seeking with `prev_hash -> entry_hash` (SHA-256), verifiable offline via `s1shell audit verify`.
- All `.env` and `scope.yaml` writes use `atomic_write_private()` (`0600` temp file + `os.replace()`).
- AI analysis wraps untrusted target data inside nonce-tagged `<untrusted_telemetry id="t_...">` blocks with tag-breakout neutralization, prompt-injection pattern warnings, reversible NDA redaction (`--redact --restore`), and deterministic Finding/CVE citation grounding checks.
- Online Streamable HTTP MCP (`s1shell mcp serve --transport http`) defaults to `127.0.0.1:8765`, requires Bearer token auth on non-loopback binds, validates `Origin` headers against DNS rebinding, and enforces a 2 MiB body cap.
