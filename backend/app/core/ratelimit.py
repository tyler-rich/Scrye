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

#: Once the key map grows past this many entries, sweep fully-expired keys so a
#: stream of distinct client IPs can't grow the backing dict without bound
#: (SEC-10). Each key holds a tiny deque, so the ceiling is generous.
_EVICT_THRESHOLD = 4096
#: Amortize the O(n) sweep: only consider sweeping every this-many events.
_SWEEP_EVERY = 512


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
        self._ops_since_sweep = 0

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
                result = (False, max(self.window_seconds - (now - window[0]), 0.0))
            else:
                window.append(now)
                result = (True, 0.0)
            # Sweep after the current key's window is finalized so the in-flight
            # key (which has just been touched) is never mistaken for idle.
            self._maybe_evict(now)
            return result

    def _maybe_evict(self, now: float) -> None:
        """Periodically drop keys whose window has fully expired.

        The per-key deque is pruned only when that key is next accessed, so an
        idle key lingers forever; without eviction a churn of distinct IPs grows
        the map without bound. Runs at most once per ``_SWEEP_EVERY`` events and
        only when the map is large, so it stays O(1) amortized. Caller holds the
        lock. Note the current key is preserved — it was just accessed.
        """
        self._ops_since_sweep += 1
        if self._ops_since_sweep < _SWEEP_EVERY or len(self._events) <= _EVICT_THRESHOLD:
            return
        self._ops_since_sweep = 0
        expired = [
            key
            for key, events in self._events.items()
            if not events or now - events[-1] > self.window_seconds
        ]
        for key in expired:
            del self._events[key]

    def reset(self) -> None:
        """Forget all recorded events (used by tests)."""
        with self._lock:
            self._events.clear()
