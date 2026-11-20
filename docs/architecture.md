# S1shell Architecture

## Overview

S1shell separates **public vulnerability & SBOM intelligence** (`cve search`, `cve get`, `cve audit`), **target-touching read-only assessment** (`profile`, live `fingerprint`, `assess`), **local governance diagnostics** (`doctor`, `audit list/verify`, `scope`), **offline remediation & drift analysis** (`remediate`, `diff`, `report build`), and **agent integration** (`mcp serve`) behind a mandatory fail-closed policy gate.

```text
  CLI (`cli.py` + `output.py`) & Read-Only Stdio MCP (`mcp_server.py`)
     │
     ├── Target Commands (`profile`, live `fingerprint`, `assess [--targets-file]`)
     │      │
     │      ▼
     │   Policy Gate (`guard.py`)
     │      ├─ 1. Parse & normalize target (`scope.py`)
     │      ├─ 2. Check active exclusions -> most-specific active allow + verify DNS -> Exit 2
     │      ├─ 3. Confirm `--authorized` or TTY prompt -> Exit 3
     │      ├─ 4. Execute bounded GET/OPTIONS + TLS via pinned IP (`target_fetch.py` / `http.py`)
     │      └─ 5. Append SHA-256 hash-chained JSONL record (`audit.py`)
     │
     ├── Intel Commands (`cve search/get`, `cve audit <lockfile|sbom>`) — Zero Target Contact
     │      └─ SQLite TTL Cache (`cve/cache.py`) -> Rate-Limited NVD/CVE.org/OSV.dev + KEV/EPSS
     │
     ├── Offline Analysis & Playbooks (`fingerprint --from-profile`, `remediate`, `diff`, `report`)
     │      └─ Schema-Validated Loader -> Passive Matcher / Deterministic Hardening / SARIF / HTML
     │
     └── Governance & Diagnostics (`scope add/import/check`, `audit verify`, `doctor`, `completion`)
            └─ Local-only checks (0700/0600 permissions, hash-chain verification, signatures.d)
```

## DNS Rebinding, Redirect, Exclusion, and SSRF Safeguards

1. **Deny-First Exclusions & Structural Match Before DNS**: Active `--exclude` scope rules override broader allow rules before any DNS resolution occurs. Multiple allow matches resolve deterministically by specificity (`url_prefix` > `ip` > exact `domain` > wildcard `domain` > `cidr`).
2. **Special/Private IP Guard**: When a `domain` or hostname `url_prefix` resolves to loopback, RFC1918 private, link-local (`169.254.169.254`), multicast, or reserved IPs (or an excluded IP), access is denied with exit code `2` unless an active `ip` or `cidr` allow entry explicitly covers that IP.
3. **IP Pinning (`http.py`)**: `PinnedSyncBackend` overrides TCP connection destination to the exact IP validated by `scope.py` while keeping the original hostname for HTTP `Host`, TLS SNI, and X.509 hostname verification. `trust_env=False` prevents proxy environment variables from bypassing pinning.
4. **No Automatic Redirects**: `follow_redirects=False` and `max_redirects=0` ensure `3xx` responses never pivot requests out of scope; `Location` is recorded passively (including flagging HTTPS-to-HTTP downgrade redirects).
5. **Sequential Concurrency (`concurrency=1`)**: Even in `--targets-file` batch mode, S1shell runs strictly sequentially with a configurable `--delay`, enforcing scope and authorization independently per target.

## Tamper-Evident Audit Chain & Report Security

- Every record written to `~/.s1shell/audit.log` includes `prev_hash` and `entry_hash` (SHA-256 over canonical JSON fields), verifiable offline via `s1shell audit verify` and `s1shell doctor`.
- Self-contained HTML reports (`report.html.j2` and `batch_report.html.j2`) use inline CSS only, zero external scripts/CDNs, and `jinja2.Environment(..., autoescape=True)` to prevent untrusted target telemetry from injecting HTML/JS.
- AI triage wraps all external telemetry in `<untrusted_telemetry>` prompt-injection isolation tags and supports reversible client-side redaction (`--redact`) as well as local air-gapped Ollama inference.
