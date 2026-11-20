"""Typed exceptions and standardized CLI exit codes for S1shell."""

from enum import IntEnum


class ExitCode(IntEnum):
    """Standard process exit codes enforced across the CLI."""

    SUCCESS = 0
    ERROR = 1
    OUT_OF_SCOPE = 2
    UNAUTHORIZED = 3
    POLICY_FAILED = 4


class S1ShellError(Exception):
    """Base error mapped to a deterministic CLI exit code."""

    exit_code: ExitCode = ExitCode.ERROR

    def __init__(self, message: str, exit_code: ExitCode | None = None) -> None:
        super().__init__(message)
        if exit_code is not None:
            self.exit_code = exit_code


class ValidationError(S1ShellError):
    """Raised when user inputs, YAML files, or artifact schemas are invalid."""

    exit_code = ExitCode.ERROR


class NetworkError(S1ShellError):
    """Raised when an external API or target connection fails."""

    exit_code = ExitCode.ERROR


class OutOfScopeError(S1ShellError):
    """Raised when a target is outside scope, expired, or resolves unsafely."""

    exit_code = ExitCode.OUT_OF_SCOPE


class UnauthorizedError(S1ShellError):
    """Raised when operator authorization confirmation is missing or declined."""

    exit_code = ExitCode.UNAUTHORIZED


class PolicyGateError(S1ShellError):
    """Raised when an assessment fails an operator-configured CI posture threshold."""

    exit_code = ExitCode.POLICY_FAILED
