"""Unit tests for the append-only JSONL audit logger."""

from __future__ import annotations

import stat

from s1shell.audit import AuditEvent, AuditLogger


def test_audit_logger_appends_jsonl_and_reads_recent(audit_logger: AuditLogger) -> None:
    e1 = AuditEvent.create(
        category="target",
        command="profile",
        target="https://example.com",
        resolved_ips=["93.184.216.34"],
        scope_id="abc12345",
        auth_ref="SOW-1",
        authorized_via="flag",
        outcome="success",
        exit_code=0,
        duration_ms=42,
    )
    e2 = AuditEvent.create(
        category="target",
        command="profile",
        target="https://blocked.example",
        authorized_via="none",
        outcome="blocked_out_of_scope",
        exit_code=2,
        duration_ms=1,
        error="Not in scope",
    )
    audit_logger.log(e1)
    audit_logger.log(e2)

    events = audit_logger.read_recent(limit=10)
    assert len(events) == 2
    assert events[0].outcome == "success"
    assert events[1].exit_code == 2

    mode = stat.S_IMODE(audit_logger.log_path.stat().st_mode)
    assert mode == 0o600

    assert len(audit_logger.read_recent(outcome="blocked_out_of_scope")) == 1
    assert len(audit_logger.read_recent(category="target", command="profile")) == 2
    assert len(audit_logger.read_recent(target="blocked")) == 1


def test_audit_logger_concurrent_appends_and_large_tail_preserve_hash_chain(
    audit_logger: AuditLogger,
) -> None:
    from concurrent.futures import ThreadPoolExecutor

    # First write an oversized entry (> 10 KiB) to exercise multi-chunk backward tail seeking
    audit_logger.log(
        AuditEvent.create(
            category="target",
            command="profile",
            target="https://large.example.com",
            outcome="error",
            exit_code=1,
            error="E" * 12_000,
        )
    )

    def _worker(worker_id: int) -> None:
        for i in range(10):
            audit_logger.log(
                AuditEvent.create(
                    category="target",
                    command="profile",
                    target=f"https://w{worker_id}-{i}.example.com",
                    outcome="success",
                    exit_code=0,
                    duration_ms=i,
                )
            )

    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(_worker, range(6)))

    verify_res = audit_logger.verify()
    assert verify_res.valid is True
    assert verify_res.total_entries == 61
    assert verify_res.chained_entries == 61
    assert verify_res.errors == []
