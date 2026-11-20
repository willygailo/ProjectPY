# Security Policy & Responsible Use

## Authorized-Use Requirement

S1shell is designed strictly for **authorized defensive security assessments**,
vulnerability triage, configuration verification, and educational research on
systems you own or have explicit written authorization to assess.

By design, S1shell enforces:

1. **Scope-first gating (`exit 2`)**: Target-facing modules refuse to transmit
   packets unless the target and its resolved IP addresses match an unexpired
   allow entry (and no deny-first `--exclude` rule) in `~/.s1shell/scope.yaml`
   (or project `./scope.yaml`), blocking un-scoped private, loopback, CGNAT
   (`100.64.0.0/10`), NAT64 (`64:ff9b::/96`), and cloud metadata IPs.
2. **Explicit authorization confirmation (`exit 3`)**: Target commands require
   `--authorized` or interactive TTY confirmation.
3. **Read-only passive profiling**: Only single standard HTTP GET/HEAD/OPTIONS
   requests and standard TLS handshakes are performed. No exploit payloads,
   fuzzing, brute forcing, evasion, or state-changing requests exist.
4. **Zero-leak Tor (`socks5h://`) & Online MCP Guards**:
   - `--tor` / `--tor-targets` enforce `socks5h://` (no local DNS leak),
     DoH-over-Tor DNS/scope validation, SOCKS5h-tunneled TLS handshakes, and
     fail-closed behavior with zero clearnet fallback and zero IP rotation.
   - `s1shell mcp serve --transport http` defaults to `127.0.0.1:8765`, requires
     Bearer authentication (`secrets.compare_digest`) on non-loopback binds, and
     enforces `Origin` header validation against DNS-rebinding attacks.
5. **Tamper-evident audit logging**: Every network attempt (allowed or blocked)
   is appended to `~/.s1shell/audit.log` (`0600`) with an `O(1)` file-locked
   SHA-256 hash chain verifiable via `s1shell audit verify`.

## Prohibited Uses & Non-Goals

Feature requests or pull requests introducing exploitation, payload generation,
WAF/firewall evasion, rate-limit bypassing, IP/circuit rotation, credential
testing, scanning out of scope, or denial-of-service behavior will not be
accepted.

## Reporting Vulnerabilities in S1shell

If you discover a security vulnerability in S1shell itself (such as a scope
bypass, DNS rebinding gap, prompt-injection breakout, or report XSS issue):

- **Do not** open a public GitHub issue with exploit details against live users.
- Report privately via your repository's Security Advisories tab or contact the
  maintainers directly with reproduction steps and affected version.
- We aim to acknowledge reports within 72 hours and release a patch promptly.
