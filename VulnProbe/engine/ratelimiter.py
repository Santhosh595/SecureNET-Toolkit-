"""Per-host request rate limiter.

Default: 150 requests/minute per host. The scanner calls ``acquire(host)``
before each request; the call blocks until the host budget allows it.
Honours ``Retry-After`` headers and auto-backoff on repeated 429s.
"""

from __future__ import annotations

import threading
import time


class RateLimiter:
    """Token-bucket-ish limiter with per-host tracking."""

    def __init__(self, rate_per_minute: int = 150):
        self.rate = max(1, int(rate_per_minute))
        self.min_interval = 60.0 / self.rate
        self._lock = threading.Lock()
        self._last: dict[str, float] = {}
        self._backoff_until: dict[str, float] = {}
        # consecutive 429 counter per host
        self._consecutive_429: dict[str, int] = {}

    def acquire(self, host: str) -> None:
        """Block until it is safe to send a request to ``host``."""
        with self._lock:
            now = time.monotonic()
            backoff = self._backoff_until.get(host, 0.0)
            if backoff > now:
                time.sleep(backoff - now)
            last = self._last.get(host, 0.0)
            wait = self.min_interval - (now - last)
            if wait > 0:
                time.sleep(wait)
            self._last[host] = time.monotonic()

    def note_retry_after(self, host: str, seconds: float) -> None:
        """Server asked us to wait (Retry-After)."""
        with self._lock:
            until = time.monotonic() + max(0.0, float(seconds))
            self._backoff_until[host] = max(self._backoff_until.get(host, 0.0), until)

    def note_429(self, host: str) -> None:
        """Record a 429; pause the host for 60s after 3 consecutive 429s."""
        with self._lock:
            self._consecutive_429[host] = self._consecutive_429.get(host, 0) + 1
            if self._consecutive_429[host] >= 3:
                until = time.monotonic() + 60.0
                self._backoff_until[host] = max(self._backoff_until.get(host, 0.0), until)
                self._consecutive_429[host] = 0

    def note_success(self, host: str) -> None:
        with self._lock:
            self._consecutive_429[host] = 0
