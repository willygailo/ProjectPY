"""Sliding-window rate limiter honoring NVD API quotas."""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable


class RateLimiter:
    """Thread-safe sliding window rate limiter with injectable clock/sleep for testing."""

    def __init__(
        self,
        *,
        max_requests: int,
        window_seconds: float,
        clock: Callable[[], float] | None = None,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        if max_requests <= 0 or window_seconds <= 0:
            raise ValueError("max_requests and window_seconds must be positive.")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._clock = clock if clock is not None else time.monotonic
        self._sleeper = sleeper if sleeper is not None else time.sleep
        self._timestamps: deque[float] = deque()
        self._lock = threading.Lock()

    @classmethod
    def for_nvd(
        cls,
        *,
        has_api_key: bool,
        clock: Callable[[], float] | None = None,
        sleeper: Callable[[float], None] | None = None,
    ) -> RateLimiter:
        """Create a limiter matching NVD 2.0 rate quotas (5/30s unauth, 50/30s auth)."""
        return cls(
            max_requests=50 if has_api_key else 5,
            window_seconds=30.0,
            clock=clock,
            sleeper=sleeper,
        )

    def acquire(self) -> None:
        """Block until a request slot is available inside the sliding window."""
        with self._lock:
            now = self._clock()
            cutoff = now - self.window_seconds
            while self._timestamps and self._timestamps[0] <= cutoff:
                self._timestamps.popleft()

            if len(self._timestamps) >= self.max_requests:
                oldest = self._timestamps[0]
                wait_for = max(0.0, (oldest + self.window_seconds) - now)
                if wait_for > 0:
                    self._sleeper(wait_for)
                    now = self._clock()
                    cutoff = now - self.window_seconds
                    while self._timestamps and self._timestamps[0] <= cutoff:
                        self._timestamps.popleft()

            self._timestamps.append(now)
