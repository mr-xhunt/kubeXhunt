"""Rate limiting helpers."""

from __future__ import annotations

import threading
import time


class RateLimiter:
    """Very small token-interval rate limiter for sync clients."""

    def __init__(self, rate_per_second: float = 0.0):
        self.rate_per_second = max(0.0, rate_per_second)
        self._lock = threading.Lock()
        self._next_allowed_at = 0.0

    def acquire(self) -> None:
        """Block until the next request slot is available."""

        if self.rate_per_second <= 0:
            return
        interval = 1.0 / self.rate_per_second
        with self._lock:
            now = time.monotonic()
            if now < self._next_allowed_at:
                time.sleep(self._next_allowed_at - now)
                now = time.monotonic()
            self._next_allowed_at = now + interval
