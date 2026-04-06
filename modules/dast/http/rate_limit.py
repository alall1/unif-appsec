from __future__ import annotations

import time


class RateLimiter:
    """Simple spacing between requests from limits.max_requests_per_minute."""

    def __init__(self, requests_per_minute: int) -> None:
        self._rpm = max(1, int(requests_per_minute))
        self._interval = 60.0 / float(self._rpm)
        self._last: float | None = None

    def wait_turn(self) -> None:
        now = time.monotonic()
        if self._last is None:
            self._last = now
            return
        elapsed = now - self._last
        if elapsed < self._interval:
            time.sleep(self._interval - elapsed)
        self._last = time.monotonic()
