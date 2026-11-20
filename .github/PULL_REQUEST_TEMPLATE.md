## Summary

<!-- Describe what this change does and why. -->

## Related Issue

<!-- Fixes #... -->

## Responsible-Use & Safety Checklist

- [ ] Change complies with [SECURITY.md](SECURITY.md) (no exploit payloads, active fuzzing, WAF bypass, brute force, or out-of-scope scanning).
- [ ] Target-touching paths remain gated behind `guard.py` (`Scope -> Authorization -> Audit`).
- [ ] All tests run 100% offline (`pytest` uses mocks or ephemeral localhost servers only).
- [ ] `ruff check src tests`, `ruff format --check src tests`, and `mypy src` pass locally.
- [ ] Documentation (`README.md`, `docs/schemas.md`, `CHANGELOG.md`) updated if CLI flags or JSON schemas changed.
