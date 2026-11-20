# Security Policy & Responsible Use

## Authorized-Use Requirement

S1shell is designed strictly for **authorized defensive security assessments**,
vulnerability triage, configuration verification, and educational research on
systems you own or have explicit written authorization to assess.

By design, S1shell enforces:

1. **Scope-first gating**: Target-facing modules refuse to transmit packets
   unless the target and its resolved IP addresses match an unexpired entry in
   `~/.s1shell/scope.yaml`.
2. **Explicit authorization confirmation**: Target commands require
   `--authorized` or interactive confirmation.
3. **Read-only passive profiling**: Only single standard HTTP GET/HEAD/OPTIONS
   requests and standard TLS handshakes are performed. No exploit payloads,
   fuzzing, brute forcing, evasion, or state-changing requests exist.
4. **Audit logging**: Every network attempt (allowed or blocked) is appended to
   `~/.s1shell/audit.log`.

## Prohibited Uses & Non-Goals

Feature requests or pull requests introducing exploitation, payload generation,
WAF/firewall evasion, rate-limit bypassing, credential testing, scanning out of
scope, or denial-of-service behavior will not be accepted.

## Reporting Vulnerabilities in S1shell

If you discover a security vulnerability in S1shell itself (such as a scope
bypass, DNS rebinding gap, path traversal, or report XSS issue):

- **Do not** open a public GitHub issue with exploit details against live users.
- Report privately via your repository's Security Advisories tab or contact the
  maintainers directly with reproduction steps and affected version.
- We aim to acknowledge reports within 72 hours and release a patch promptly.
