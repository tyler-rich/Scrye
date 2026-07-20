"""Tests for the scheduled scanner-DB auto-update marker timing (CON-12).

The due-check marker must be advanced only when an update actually succeeds, so
a transient failure retries on the next tick instead of silently deferring for a
full interval (during which every scan runs against a stale vulnerability DB).
"""

from __future__ import annotations

import pytest

from app.workers import db_update


@pytest.mark.asyncio
async def test_marker_not_advanced_when_both_updates_fail(db, monkeypatch) -> None:
    monkeypatch.setattr(db_update, "_read_policy", lambda: (True, 24))

    calls = {"n": 0}

    async def _fail(binary, argv, engine):
        calls["n"] += 1
        return False

    monkeypatch.setattr(db_update, "_run_update", _fail)
    db_update.reset_db_update_state()

    # First tick: both fail, so the marker is left unset.
    assert await db_update.maybe_update_scanner_dbs(now=0.0) is True
    # A second tick 60 s later (well within the 24 h interval) must still run —
    # the failure was not treated as "done".
    assert await db_update.maybe_update_scanner_dbs(now=60.0) is True
    assert calls["n"] == 4  # two engines × two ticks


@pytest.mark.asyncio
async def test_marker_advanced_on_success_defers_next_tick(db, monkeypatch) -> None:
    monkeypatch.setattr(db_update, "_read_policy", lambda: (True, 24))

    calls = {"n": 0}

    async def _ok(binary, argv, engine):
        calls["n"] += 1
        return True

    monkeypatch.setattr(db_update, "_run_update", _ok)
    db_update.reset_db_update_state()

    assert await db_update.maybe_update_scanner_dbs(now=0.0) is True
    # The interval is satisfied, so the next nearby tick is skipped.
    assert await db_update.maybe_update_scanner_dbs(now=60.0) is False
    assert calls["n"] == 2  # only the first tick ran the two engines


@pytest.mark.asyncio
async def test_marker_advanced_when_one_engine_succeeds(db, monkeypatch) -> None:
    monkeypatch.setattr(db_update, "_read_policy", lambda: (True, 24))

    async def _mixed(binary, argv, engine):
        return engine == "Trivy"  # Trivy succeeds, Grype fails

    monkeypatch.setattr(db_update, "_run_update", _mixed)
    db_update.reset_db_update_state()

    assert await db_update.maybe_update_scanner_dbs(now=0.0) is True
    # At least one succeeded, so the interval is considered satisfied.
    assert await db_update.maybe_update_scanner_dbs(now=60.0) is False
