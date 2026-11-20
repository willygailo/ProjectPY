"""Central policy gate enforcing Scope -> Authorization -> Audit -> Execution."""

from __future__ import annotations

import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TextIO, TypeVar

from s1shell.audit import AuditEvent, AuditLogger
from s1shell.errors import ExitCode, OutOfScopeError, S1ShellError, UnauthorizedError
from s1shell.scope import ParsedTarget, ScopeCheckResult, ScopeManager

T = TypeVar("T")


@dataclass(frozen=True)
class TargetContext:
    """Verified execution context passed to target-touching actions."""

    parsed_target: ParsedTarget
    scope_result: ScopeCheckResult
    authorized_via: str  # flag | interactive


def confirm_authorization(
    scope_result: ScopeCheckResult,
    *,
    authorized_flag: bool,
    stdin: TextIO | None = None,
    stderr: TextIO | None = None,
) -> str:
    """Confirm operator authorization via `--authorized` or interactive TTY prompt."""
    if authorized_flag:
        return "flag"

    in_stream = stdin if stdin is not None else sys.stdin
    err_stream = stderr if stderr is not None else sys.stderr

    is_tty = hasattr(in_stream, "isatty") and in_stream.isatty()
    if not is_tty:
        raise UnauthorizedError(
            "Target command requires authorization confirmation. "
            "Pass --authorized in non-interactive mode."
        )

    entry = scope_result.matched_entry
    owner = entry.owner if entry else "unknown"
    auth_ref = entry.auth_ref if entry else "none"
    err_stream.write(
        f"Authorization required to inspect '{scope_result.parsed_target.raw}' "
        f"(owner={owner}, ref={auth_ref}). Proceed? [y/N]: "
    )
    err_stream.flush()
    try:
        answer = in_stream.readline().strip().lower()
    except OSError as exc:
        raise UnauthorizedError(f"Authorization confirmation failed: {exc}") from exc

    if answer not in {"y", "yes"}:
        raise UnauthorizedError("Operator declined authorization confirmation.")
    return "interactive"


def authorize_and_run(
    raw_target: str,
    *,
    command: str,
    scope_manager: ScopeManager,
    audit_logger: AuditLogger,
    authorized_flag: bool,
    action: Callable[[TargetContext], T],
    stdin: TextIO | None = None,
    stderr: TextIO | None = None,
) -> T:
    """Enforce mandatory Scope -> Auth -> Audit -> Action sequence for target commands."""
    started = time.monotonic()

    def elapsed_ms() -> int:
        return int((time.monotonic() - started) * 1000)

    try:
        scope_result = scope_manager.check_target(raw_target)
    except OutOfScopeError as exc:
        audit_logger.log(
            AuditEvent.create(
                category="target",
                command=command,
                target=raw_target,
                authorized_via="none",
                outcome="blocked_out_of_scope",
                exit_code=int(ExitCode.OUT_OF_SCOPE),
                duration_ms=elapsed_ms(),
                error=str(exc),
            )
        )
        raise

    if not scope_result.in_scope or scope_result.matched_entry is None:
        audit_logger.log(
            AuditEvent.create(
                category="target",
                command=command,
                target=raw_target,
                resolved_ips=scope_result.resolved_ips,
                scope_id=(scope_result.matched_entry.id if scope_result.matched_entry else None),
                auth_ref=(
                    scope_result.matched_entry.auth_ref if scope_result.matched_entry else None
                ),
                authorized_via="none",
                outcome="blocked_out_of_scope",
                exit_code=int(ExitCode.OUT_OF_SCOPE),
                duration_ms=elapsed_ms(),
                error=scope_result.reason,
            )
        )
        raise OutOfScopeError(scope_result.reason)

    matched = scope_result.matched_entry

    try:
        authorized_via = confirm_authorization(
            scope_result,
            authorized_flag=authorized_flag,
            stdin=stdin,
            stderr=stderr,
        )
    except UnauthorizedError as exc:
        audit_logger.log(
            AuditEvent.create(
                category="target",
                command=command,
                target=raw_target,
                resolved_ips=scope_result.resolved_ips,
                scope_id=matched.id,
                auth_ref=matched.auth_ref,
                authorized_via="none",
                outcome="blocked_unauthorized",
                exit_code=int(ExitCode.UNAUTHORIZED),
                duration_ms=elapsed_ms(),
                error=str(exc),
            )
        )
        raise

    ctx = TargetContext(
        parsed_target=scope_result.parsed_target,
        scope_result=scope_result,
        authorized_via=authorized_via,
    )

    try:
        result = action(ctx)
    except S1ShellError as exc:
        audit_logger.log(
            AuditEvent.create(
                category="target",
                command=command,
                target=raw_target,
                resolved_ips=scope_result.resolved_ips,
                scope_id=matched.id,
                auth_ref=matched.auth_ref,
                authorized_via=authorized_via,
                outcome="error",
                exit_code=int(exc.exit_code),
                duration_ms=elapsed_ms(),
                error=str(exc),
            )
        )
        raise
    except Exception as exc:
        audit_logger.log(
            AuditEvent.create(
                category="target",
                command=command,
                target=raw_target,
                resolved_ips=scope_result.resolved_ips,
                scope_id=matched.id,
                auth_ref=matched.auth_ref,
                authorized_via=authorized_via,
                outcome="error",
                exit_code=int(ExitCode.ERROR),
                duration_ms=elapsed_ms(),
                error=str(exc),
            )
        )
        raise

    audit_logger.log(
        AuditEvent.create(
            category="target",
            command=command,
            target=raw_target,
            resolved_ips=scope_result.resolved_ips,
            scope_id=matched.id,
            auth_ref=matched.auth_ref,
            authorized_via=authorized_via,
            outcome="success",
            exit_code=int(ExitCode.SUCCESS),
            duration_ms=elapsed_ms(),
        )
    )
    return result
