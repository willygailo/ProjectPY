# Changelog

All notable changes to S1shell will be documented in this file.

## [Unreleased]

### Fixed
- Fixed `PinnedSyncBackend.connect_tcp` compatibility with `httpcore` (`super().connect_tcp(...)` instead of nonexistent `httpcore.SyncStream`) so live pinned HTTP/HTTPS target connections succeed.
- Fixed offline test isolation in `test_profile_against_local_http_server_exercises_pinned_transport` and added live pinned HTTPS/SNI verification tests.
- Fixed Ruff `E501` line-length violations and strict `mypy` type issues across `cli.py`, `header_check.py`, `tls_check.py`, `cve/service.py`, and `http.py`.
- Fixed NVD search pagination truncation when client-side `--min-cvss` or `--severity` filters are active, and ensured SQLite cache connections close deterministically.
- Fixed `ScopeManager.remove` case sensitivity on URL prefix entries and added specificity-ordered matching plus duplicate active entry prevention (`--replace`).

### Added
- `s1shell doctor` local diagnostic command verifying Python version, `~/.s1shell` permissions, `scope.yaml`, `audit.log`, `cache.db`, passive signatures, and `NVD_API_KEY` status.
- `s1shell completion <bash|zsh|fish>` shell completion generator.
- `s1shell cve search --from-fingerprint <fp.json>` for zero-target-contact CVE triage of passively identified technologies.
- `s1shell audit list` filtering (`--category`, `--outcome`, `--command`, `--target`) and Markdown rendering (`--format md`).
- Expanded passive signature catalog (`signatures.yaml`) with version extraction and `cookie_patterns` matching.
- Executive summary, Set-Cookie attributes table, TLS SANs/versions, COOP/CORP/CSP checks, and Markdown table escaping in `profile` output and `report` templates.
- Open-source tooling: `Makefile`, `.pre-commit-config.yaml`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, GitHub issue/PR templates, Dependabot, release workflow, and wheel smoke tests in CI.

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
