# Contributing to S1shell

Thank you for contributing to S1shell. Before opening a pull request or issue, please read [SECURITY.md](SECURITY.md) and the project's defensive design rules.

## Responsible-Use Boundaries

S1shell is strictly an **authorized defensive toolkit**. Pull requests introducing any of the following will not be accepted:

- Exploit payloads, vulnerability PoC execution, or active probing/fuzzing (SQLi/XSS/SSRF/LFI strings)
- WAF/firewall evasion, request smuggling, or User-Agent spoofing
- Rate-limit evasion, proxy rotation, brute force, or directory/subdomain enumeration
- State-modifying target requests (`POST`/`PUT`/`PATCH`/`DELETE`) or bypassing `guard.py`

## Local Development Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Or using `make`:

```bash
make setup
source .venv/bin/activate
make check
```

## Verification Standards

1. **100% Offline Tests**: All tests under `tests/` must run completely offline. Mock external HTTP/DNS/NVD/CVE.org calls and use ephemeral `127.0.0.1` servers where socket verification is required.
2. **Lint & Format**: `ruff check src tests` and `ruff format --check src tests` must pass cleanly.
3. **Strict Typing**: `mypy src` runs with `strict = true` targeting Python `>=3.10`.
4. **Canonical Schemas**: Keep JSON output changes additive under `schema_version: "1.0"`, and update [docs/schemas.md](docs/schemas.md) when adding fields.

## Adding Passive Fingerprint Signatures

1. Add entries only to [src/s1shell/fingerprint/signatures.yaml](src/s1shell/fingerprint/signatures.yaml) using headers, `Set-Cookie` names/patterns, or TLS issuer patterns observable in a single normal HTTP `GET` response.
2. Include an optional regex capture group when the header carries a clean version string (e.g. `(?i)\\bnginx(?:/([\\d.]+))?`).
3. Add offline unit tests in [tests/fingerprint/test_matcher.py](tests/fingerprint/test_matcher.py) and verify no existing signatures regress.
