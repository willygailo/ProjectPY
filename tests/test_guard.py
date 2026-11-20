"""Unit tests for the policy gate enforcing scope, authorization, and zero-packet guarantees."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from s1shell.audit import AuditLogger
from s1shell.errors import OutOfScopeError, UnauthorizedError
from s1shell.guard import TargetContext, authorize_and_run
from s1shell.scope import ScopeManager


class FakeTTYInput(io.StringIO):
    """StringIO simulating an interactive TTY stdin."""

    def isatty(self) -> bool:
        return True


def test_guard_blocks_out_of_scope_with_zero_action_calls(
    scope_manager: ScopeManager, audit_logger: AuditLogger
) -> None:
    called = False

    def action(_ctx: TargetContext) -> str:
        nonlocal called
        called = True
        return "should-not-run"

    with pytest.raises(OutOfScopeError):
        authorize_and_run(
            "https://unscoped.example.org",
            command="profile",
            scope_manager=scope_manager,
            audit_logger=audit_logger,
            authorized_flag=True,
            action=action,
        )

    assert called is False
    events = audit_logger.read_recent()
    assert len(events) == 1
    assert events[0].outcome == "blocked_out_of_scope"
    assert events[0].exit_code == 2


def test_guard_blocks_non_tty_without_authorized_flag(
    scope_manager: ScopeManager, audit_logger: AuditLogger
) -> None:
    scope_manager.add("example.com", owner="ACME", auth_ref="SOW-1", expires="2099-12-31")
    called = False

    def action(_ctx: TargetContext) -> str:
        nonlocal called
        called = True
        return "should-not-run"

    with pytest.raises(UnauthorizedError):
        authorize_and_run(
            "https://example.com",
            command="profile",
            scope_manager=scope_manager,
            audit_logger=audit_logger,
            authorized_flag=False,
            action=action,
            stdin=io.StringIO(""),  # Non-TTY
            stderr=io.StringIO(),
        )

    assert called is False
    events = audit_logger.read_recent()
    assert len(events) == 1
    assert events[0].outcome == "blocked_unauthorized"
    assert events[0].exit_code == 3


def test_guard_interactive_tty_prompt_accept_and_decline(
    scope_manager: ScopeManager, audit_logger: AuditLogger
) -> None:
    scope_manager.add("example.com", owner="ACME", auth_ref="SOW-1", expires="2099-12-31")

    err_buf = io.StringIO()
    with pytest.raises(UnauthorizedError):
        authorize_and_run(
            "https://example.com",
            command="profile",
            scope_manager=scope_manager,
            audit_logger=audit_logger,
            authorized_flag=False,
            action=lambda _ctx: "nope",
            stdin=FakeTTYInput("n\n"),
            stderr=err_buf,
        )

    result = authorize_and_run(
        "https://example.com",
        command="profile",
        scope_manager=scope_manager,
        audit_logger=audit_logger,
        authorized_flag=False,
        action=lambda ctx: f"ran:{ctx.authorized_via}:{ctx.scope_result.pinned_ip}",
        stdin=FakeTTYInput("yes\n"),
        stderr=err_buf,
    )
    assert result == "ran:interactive:93.184.216.34"
    events = audit_logger.read_recent()
    assert [e.outcome for e in events] == ["blocked_unauthorized", "success"]


def test_guard_checks_scope_before_authorization_prompt(tmp_path: Path) -> None:
    mgr = ScopeManager(tmp_path / "scope.yaml", resolver=lambda _h: ["93.184.216.34"])
    audit = AuditLogger(tmp_path / "audit.log")
    err_buf = io.StringIO()

    with pytest.raises(OutOfScopeError):
        authorize_and_run(
            "https://not-in-scope.example",
            command="profile",
            scope_manager=mgr,
            audit_logger=audit,
            authorized_flag=False,
            action=lambda _ctx: "never",
            stdin=FakeTTYInput("y\n"),
            stderr=err_buf,
        )

    # User must never even be prompted for an out-of-scope target
    assert err_buf.getvalue() == ""
