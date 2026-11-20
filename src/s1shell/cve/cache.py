"""SQLite TTL cache for CVE API queries."""

from __future__ import annotations

import contextlib
import json
import sqlite3
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from s1shell.config import chmod_private_file, ensure_private_dir


class CVECache:
    """Local SQLite response cache with configurable TTL."""

    def __init__(
        self,
        db_path: Path,
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.db_path = db_path
        self._clock = clock if clock is not None else time.time
        ensure_private_dir(db_path.parent)
        self._init_db()

    def _connect(self) -> contextlib.closing[sqlite3.Connection]:
        return contextlib.closing(sqlite3.connect(self.db_path))

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cve_cache (
                    cache_key TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    fetched_at REAL NOT NULL
                )
                """
            )
            conn.commit()
        chmod_private_file(self.db_path)

    def get(self, cache_key: str, *, ttl_seconds: int) -> Any | None:
        """Return cached JSON value if present and within TTL; otherwise None."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload_json, fetched_at FROM cve_cache WHERE cache_key = ?",
                (cache_key,),
            ).fetchone()
        if row is None:
            return None
        payload_json, fetched_at = row
        age = self._clock() - float(fetched_at)
        if ttl_seconds >= 0 and age > ttl_seconds:
            return None
        return json.loads(str(payload_json))

    def set(self, cache_key: str, payload: Any) -> None:
        """Store a JSON-serializable payload under `cache_key`."""
        now = self._clock()
        encoded = json.dumps(payload, separators=(",", ":"))
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO cve_cache (cache_key, payload_json, fetched_at)
                VALUES (?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    payload_json = excluded.payload_json,
                    fetched_at = excluded.fetched_at
                """,
                (cache_key, encoded, now),
            )
            conn.commit()
        chmod_private_file(self.db_path)

    def clear(self) -> int:
        """Delete all cached entries and return number of rows removed."""
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM cve_cache")
            conn.commit()
            return int(cur.rowcount)

    def count(self) -> int:
        """Return total cached entries currently stored in SQLite."""
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) FROM cve_cache").fetchone()
            return int(row[0]) if row else 0
