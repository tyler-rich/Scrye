"""Tests for the sliding-window rate limiter, including idle-key eviction (SEC-10)."""

from __future__ import annotations

import pytest

import app.core.ratelimit as ratelimit
from app.core.ratelimit import SlidingWindowRateLimiter


def test_allows_up_to_the_limit_then_blocks() -> None:
    limiter = SlidingWindowRateLimiter(max_events=3, window_seconds=60)
    assert [limiter.allow("ip")[0] for _ in range(4)] == [True, True, True, False]


def test_idle_keys_are_evicted_once_the_map_grows(monkeypatch: pytest.MonkeyPatch) -> None:
    # SEC-10: a churn of distinct client IPs must not grow the backing dict
    # forever. Lower the thresholds so the sweep is exercised deterministically.
    monkeypatch.setattr(ratelimit, "_EVICT_THRESHOLD", 3)
    monkeypatch.setattr(ratelimit, "_SWEEP_EVERY", 1)
    limiter = SlidingWindowRateLimiter(max_events=5, window_seconds=60)

    for i in range(10):
        limiter.allow(f"ip-{i}")
    assert len(limiter._events) == 10  # all within the window, none expired

    # Backdate every recorded event so all 10 keys now sit outside the window.
    for events in limiter._events.values():
        events[-1] -= 120

    limiter.allow("fresh")  # triggers a sweep of the fully-expired idle keys

    # Only keys with activity inside the window survive (here: just "fresh").
    assert len(limiter._events) == 1
    assert "fresh" in limiter._events


def test_active_keys_survive_a_sweep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ratelimit, "_EVICT_THRESHOLD", 2)
    monkeypatch.setattr(ratelimit, "_SWEEP_EVERY", 1)
    limiter = SlidingWindowRateLimiter(max_events=5, window_seconds=60)
    for i in range(5):
        limiter.allow(f"ip-{i}")
    limiter.allow("ip-0")  # re-touch an existing key; sweep runs but nothing expired
    assert len(limiter._events) == 5
