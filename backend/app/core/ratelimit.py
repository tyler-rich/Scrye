"""In-process sliding-window rate limiter for the auth endpoints.

Scrye is a single-container app (locked decision: no Redis in v1), so an
in-memory limiter is sufficient and keeps the dependency surface small. Each
key (client IP) may perform at most ``max_events`` events per ``window_seconds``
rolling window; excess attempts are rejected with a retry hint.
"""

from __future__ import annotations

import threading
import time
from collections import deque


class SlidingWindowRateLimiter:
    """Thread-safe sliding-window counter keyed by an arbitrary string."""

    def __init__(self, max_events: int, window_seconds: float) -> None:
        """Create a limiter allowing ``max_events`` per ``window_seconds``.

        Args:
            max_events: Maximum events allowed inside one rolling window.
            window_seconds: Window length in seconds.
        """
        self.max_events = max_events
        self.window_seconds = window_seconds
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> tuple[bool, float]:
        """Record an attempt for ``key`` and decide whether it is allowed.

        Args:
            key: Bucket identifier (e.g. the client IP address).

        Returns:
            ``(allowed, retry_after_seconds)``. ``retry_after_seconds`` is 0.0
            when allowed, otherwise the time until the oldest counted event
            leaves the window.
        """
        now = time.monotonic()
        with self._lock:
            window = self._events.setdefault(key, deque())
            while window and now - window[0] > self.window_seconds:
                window.popleft()
            if len(window) >= self.max_events:
                retry_after = self.window_seconds - (now - window[0])
                return False, max(retry_after, 0.0)
            window.append(now)
            return True, 0.0

    def reset(self) -> None:
        """Forget all recorded events (used by tests)."""
        with self._lock:
            self._events.clear()
