"""Shared offline fixtures for S1shell unit and integration tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from s1shell.audit import AuditLogger
from s1shell.config import RuntimeConfig
from s1shell.scope import ScopeManager


@pytest.fixture()
def tmp_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> RuntimeConfig:
    """Provide an isolated RuntimeConfig backed by a temporary directory."""
    home = tmp_path / ".s1shell"
    monkeypatch.setenv("S1SHELL_HOME", str(home))
    return RuntimeConfig.from_env(home_override=home)


@pytest.fixture()
def scope_manager(tmp_config: RuntimeConfig) -> ScopeManager:
    """Return a ScopeManager using a deterministic offline DNS resolver."""

    def fake_resolver(host: str) -> list[str]:
        mapping = {
            "example.com": ["93.184.216.34"],
            "app.example.com": ["93.184.216.34"],
            "api.example.com": ["2606:2800:220:1:248:1893:25c8:1946"],
            "evil.example.com": ["127.0.0.1"],
            "metadata.example.com": ["169.254.169.254"],
            "internal.example.com": ["10.0.0.5"],
        }
        return mapping.get(host, ["93.184.216.34"])

    return ScopeManager(tmp_config.scope_file, resolver=fake_resolver)


@pytest.fixture()
def audit_logger(tmp_config: RuntimeConfig) -> AuditLogger:
    """Return an AuditLogger backed by the temporary home directory."""
    return AuditLogger(tmp_config.audit_log)
