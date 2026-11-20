# S1shell Architecture

## Overview

S1shell separates **public vulnerability intelligence** (`cve`), **target-touching assessment** (`profile`, live `fingerprint`), **local governance diagnostics** (`doctor`, `audit`), and **offline compilation** (`report`, `--from-profile`, `cve search --from-fingerprint`) behind a mandatory policy gate.

```text
  CLI (`cli.py` + `output.py`)
     │
     ├── Target Commands (`profile`, live `fingerprint`)
     │      │
     │      ▼
     │   Policy Gate (`guard.py`)
     │      ├─ 1. Parse & normalize target (`scope.py`)
     │      ├─ 2. Match most-specific active scope + verify DNS -> Exit 2 on failure
     │      ├─ 3. Confirm `--authorized` or TTY prompt -> Exit 3 on failure
     │      ├─ 4. Execute bounded snapshot via pinned IP (`target_fetch.py` / `http.py` / `tls_check.py`)
     │      └─ 5. Append JSONL record (`audit.py`)
     │
     ├── Intel Commands (`cve search [--from-fingerprint]`, `cve get`)
     │      └─ SQLite TTL Cache (`cve/cache.py`) -> Rate-Limited NVD/CVE.org (`cve/`)
     │
     ├── Diagnostics & Ergonomics (`doctor`, `completion`, `audit list`)
     │      └─ Local-only checks (Python, permissions, scope.yaml, audit.log, cache.db, signatures.yaml)
     │
     └── Offline Analysis (`fingerprint --from-profile`, `report build`)
            └─ Schema-Validated JSON Artifact Loader -> Passive Matcher / Jinja2 Autoescaped Renderer
```

## DNS Rebinding, Redirect, and SSRF Safeguards

1. **Structural match before DNS**: If a target does not match an active entry in `scope.yaml`, no DNS lookup or target packet is emitted. Multiple active matches resolve deterministically by specificity (`url_prefix` > `ip` > exact `domain` > wildcard `domain` > `cidr`).
2. **Special/private IP guard**: When a `domain` or hostname `url_prefix` resolves to loopback, RFC1918 private, link-local (`169.254.169.254`), multicast, or reserved IPs, access is denied with exit code `2` unless an active `ip` or `cidr` scope entry explicitly covers that IP.
3. **IP Pinning (`http.py`)**: `PinnedSyncBackend` overrides TCP connection destination to the exact IP validated by `scope.py` while keeping the original hostname for HTTP `Host`, TLS SNI, and X.509 hostname verification. `trust_env=False` prevents proxy environment variables from bypassing pinning.
4. **No Automatic Redirects**: `follow_redirects=False` and `max_redirects=0` ensure `3xx` responses never pivot requests out of scope; `Location` is recorded passively.

## Report Security

- Self-contained HTML reports (`report/templates/report.html.j2`) use inline CSS only and zero external scripts/stylesheets.
- `jinja2.Environment(..., autoescape=True)` prevents untrusted target HTTP headers or banners from injecting executable HTML/JS into generated reports.
