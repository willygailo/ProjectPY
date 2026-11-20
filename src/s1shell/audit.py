"""Append-only tamper-evident JSON Lines audit logger for network and scope-gate events."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from s1shell import __version__
from s1shell.config import chmod_private_file, ensure_private_dir
from s1shell.errors import ValidationError
from s1shell.models import SCHEMA_VERSION, utc_now_iso

GENESIS_HASH = "GENESIS"


def _compute_entry_hash(payload: dict[str, Any], prev_hash: str) -> str:
    """Compute canonical SHA-256 hash over audit payload fields and previous link hash."""
    canonical_body = {
        "timestamp_utc": payload["timestamp_utc"],
        "category": payload["category"],
        "command": payload["command"],
        "target": payload["target"],
        "resolved_ips": payload.get("resolved_ips", []),
        "scope_id": payload.get("scope_id"),
        "auth_ref": payload.get("auth_ref"),
        "authorized_via": payload.get("authorized_via", "n/a"),
        "outcome": payload["outcome"],
        "exit_code": int(payload["exit_code"]),
        "duration_ms": int(payload.get("duration_ms", 0)),
        "error": payload.get("error"),
        "prev_hash": prev_hash,
    }
    encoded = json.dumps(canonical_body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class AuditEvent:
    """Single immutable audit record written to ~/.s1shell/audit.log."""

    timestamp_utc: str
    category: str  # target | intel | scope
    command: str
    target: str
    resolved_ips: list[str]
    scope_id: str | None
    auth_ref: str | None
    authorized_via: str  # flag | interactive | none | n/a
    outcome: str  # success | blocked_out_of_scope | blocked_unauthorized | error
    exit_code: int
    duration_ms: int
    error: str | None = None
    prev_hash: str | None = None
    entry_hash: str | None = None

    @classmethod
    def create(
        cls,
        *,
        category: str,
        command: str,
        target: str,
        resolved_ips: list[str] | None = None,
        scope_id: str | None = None,
        auth_ref: str | None = None,
        authorized_via: str = "n/a",
        outcome: str,
        exit_code: int,
        duration_ms: int = 0,
        error: str | None = None,
    ) -> AuditEvent:
        """Factory filling in current UTC timestamp."""
        return cls(
            timestamp_utc=utc_now_iso(),
            category=category,
            command=command,
            target=target,
            resolved_ips=list(resolved_ips or []),
            scope_id=scope_id,
            auth_ref=auth_ref,
            authorized_via=authorized_via,
            outcome=outcome,
            exit_code=exit_code,
            duration_ms=duration_ms,
            error=error,
        )

    def _core_dict(self) -> dict[str, Any]:
        return {
            "timestamp_utc": self.timestamp_utc,
            "category": self.category,
            "command": self.command,
            "target": self.target,
            "resolved_ips": self.resolved_ips,
            "scope_id": self.scope_id,
            "auth_ref": self.auth_ref,
            "authorized_via": self.authorized_via,
            "outcome": self.outcome,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "error": self.error,
        }

    def with_chain(self, prev_hash: str) -> AuditEvent:
        """Return a new AuditEvent linked to `prev_hash` via SHA-256 `entry_hash`."""
        digest = _compute_entry_hash(self._core_dict(), prev_hash)
        return replace(self, prev_hash=prev_hash, entry_hash=digest)

    def to_json_line(self) -> str:
        """Serialize to a single compact JSON line."""
        payload = self._core_dict()
        if self.prev_hash is not None:
            payload["prev_hash"] = self.prev_hash
        if self.entry_hash is not None:
            payload["entry_hash"] = self.entry_hash
        return json.dumps(payload, separators=(",", ":"))

    @classmethod
    def from_json_line(cls, line: str) -> AuditEvent:
        """Parse one JSONL audit line back into an AuditEvent."""
        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"Corrupt audit log line: {exc}") from exc
        if not isinstance(data, dict):
            raise ValidationError("Corrupt audit log line: expected JSON object.")
        try:
            return cls(
                timestamp_utc=str(data["timestamp_utc"]),
                category=str(data["category"]),
                command=str(data["command"]),
                target=str(data["target"]),
                resolved_ips=[str(ip) for ip in data.get("resolved_ips", [])],
                scope_id=data.get("scope_id"),
                auth_ref=data.get("auth_ref"),
                authorized_via=str(data.get("authorized_via", "n/a")),
                outcome=str(data["outcome"]),
                exit_code=int(data["exit_code"]),
                duration_ms=int(data.get("duration_ms", 0)),
                error=data.get("error"),
                prev_hash=str(data["prev_hash"]) if data.get("prev_hash") else None,
                entry_hash=str(data["entry_hash"]) if data.get("entry_hash") else None,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidationError(
                f"Corrupt audit log line: missing/invalid field ({exc})."
            ) from exc


@dataclass(frozen=True)
class AuditVerifyResult:
    """Tamper-evidence verification summary for `~/.s1shell/audit.log`."""

    log_path: str
    valid: bool
    total_entries: int
    chained_entries: int
    legacy_unhashed_entries: int
    errors: list[str] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION
    tool_version: str = __version__
    generated_at_utc: str = field(default_factory=utc_now_iso)
    artifact_type: str = "audit_verify_report"


class AuditLogger:
    """Append-only hash-chained JSONL log writer, reader, and integrity verifier."""

    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path

    def _last_chain_hash(self) -> str:
        """Inspect the last non-empty log line to determine the previous hash link."""
        if not self.log_path.exists():
            return GENESIS_HASH
        try:
            lines = [
                ln.strip()
                for ln in self.log_path.read_text(encoding="utf-8").splitlines()
                if ln.strip()
            ]
        except OSError:
            return GENESIS_HASH
        if not lines:
            return GENESIS_HASH
        last_line = lines[-1]
        try:
            last_event = AuditEvent.from_json_line(last_line)
            if last_event.entry_hash:
                return last_event.entry_hash
        except ValidationError:
            pass
        return hashlib.sha256(last_line.encode("utf-8")).hexdigest()

    def log(self, event: AuditEvent) -> None:
        """Append one hash-chained audit line and enforce 0600 permissions."""
        ensure_private_dir(self.log_path.parent)
        chained = event.with_chain(self._last_chain_hash())
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(chained.to_json_line() + "\n")
        chmod_private_file(self.log_path)

    def verify(self) -> AuditVerifyResult:
        """Verify JSON integrity and SHA-256 hash chain continuity across the audit log."""
        if not self.log_path.exists():
            return AuditVerifyResult(
                log_path=str(self.log_path),
                valid=True,
                total_entries=0,
                chained_entries=0,
                legacy_unhashed_entries=0,
            )

        raw_lines = [
            ln.strip()
            for ln in self.log_path.read_text(encoding="utf-8").splitlines()
            if ln.strip()
        ]
        errors: list[str] = []
        chained_count = 0
        legacy_count = 0
        expected_prev = GENESIS_HASH

        for idx, line in enumerate(raw_lines, start=1):
            try:
                ev = AuditEvent.from_json_line(line)
            except ValidationError as exc:
                errors.append(f"Line {idx}: {exc}")
                expected_prev = hashlib.sha256(line.encode("utf-8")).hexdigest()
                continue

            if ev.entry_hash is None and ev.prev_hash is None:
                if chained_count > 0:
                    errors.append(
                        f"Line {idx}: unhashed entry appeared after hash-chained entries."
                    )
                legacy_count += 1
                expected_prev = hashlib.sha256(line.encode("utf-8")).hexdigest()
                continue

            chained_count += 1
            if not ev.prev_hash or not ev.entry_hash:
                errors.append(f"Line {idx}: incomplete hash chain metadata.")
                expected_prev = ev.entry_hash or hashlib.sha256(line.encode("utf-8")).hexdigest()
                continue

            if ev.prev_hash != expected_prev:
                errors.append(
                    f"Line {idx}: broken prev_hash link (expected {expected_prev[:12]}..., "
                    f"got {ev.prev_hash[:12]}...)."
                )

            recomputed = _compute_entry_hash(ev._core_dict(), ev.prev_hash)
            if ev.entry_hash != recomputed:
                errors.append(f"Line {idx}: entry_hash mismatch (record tampered or altered).")
            expected_prev = ev.entry_hash

        return AuditVerifyResult(
            log_path=str(self.log_path),
            valid=len(errors) == 0,
            total_entries=len(raw_lines),
            chained_entries=chained_count,
            legacy_unhashed_entries=legacy_count,
            errors=errors,
        )

    def read_recent(
        self,
        limit: int = 50,
        *,
        category: str | None = None,
        outcome: str | None = None,
        command: str | None = None,
        target: str | None = None,
    ) -> list[AuditEvent]:
        """Return up to the most recent `limit` audit events matching optional filters."""
        if not self.log_path.exists():
            return []
        lines = [
            ln.strip()
            for ln in self.log_path.read_text(encoding="utf-8").splitlines()
            if ln.strip()
        ]
        events = [AuditEvent.from_json_line(ln) for ln in lines]
        if category:
            cat_l = category.strip().lower()
            events = [e for e in events if e.category.lower() == cat_l]
        if outcome:
            out_l = outcome.strip().lower()
            events = [e for e in events if e.outcome.lower() == out_l]
        if command:
            cmd_l = command.strip().lower()
            events = [e for e in events if e.command.lower() == cmd_l]
        if target:
            tgt_l = target.strip().lower()
            events = [e for e in events if tgt_l in e.target.lower()]
        if limit > 0:
            events = events[-limit:]
        return events
