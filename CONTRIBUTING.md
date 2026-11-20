# Contributing to S1shell

Thank you for contributing to S1shell. Before opening a pull request or issue, please read [SECURITY.md](SECURITY.md) and the project's defensive design rules.

## Responsible-Use Boundaries

S1shell is strictly an **authorized defensive toolkit**. Pull requests introducing any of the following will not be accepted:

- Exploit payloads, vulnerability PoC execution, or active probing/fuzzing (SQLi/XSS/SSRF/LFI strings)
- WAF/firewall evasion, request smuggling, or User-Agent spoofing
- Rate-limit evasion, proxy/IP rotation (including Tor `NEWNYM` / ControlPort rotation), brute force, or directory/subdomain enumeration
- State-modifying target requests (`POST`/`PUT`/`PATCH`/`DELETE`) or bypassing `guard.py`

## Local Development Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
make check
```

## Verification Standards

1. **Lint & Format**: `ruff check src` and `ruff format --check src` must pass cleanly.
2. **Strict Typing**: `mypy src` runs with `strict = true` targeting Python `>=3.10`.
3. **100% Offline Verification**: Any automated test or smoke check must run completely offline using `httpx.MockTransport` or ephemeral `127.0.0.1` loopback servers.
4. **Canonical Schemas**: Keep JSON output changes additive under `schema_version: "1.0"`, and update [docs/schemas.md](docs/schemas.md) when adding fields.

## Extending Passive Signatures & Defensive AI Skills

- **Passive Fingerprint Signatures**: Add rules to [src/s1shell/fingerprint/signatures.yaml](src/s1shell/fingerprint/signatures.yaml) (or user-local `~/.s1shell/signatures.d/*.yaml`) using headers, `Set-Cookie` patterns, CNAMEs, TLS issuers, or passive HTML hints observable in a single normal HTTP `GET` response.
- **Defensive AI Skills**: Add declarative skills to [src/s1shell/ai/skills.yaml](src/s1shell/ai/skills.yaml) (or user-local `~/.s1shell/skills.d/*.yaml`) and verify with `s1shell ai skills list` and `s1shell doctor`.
