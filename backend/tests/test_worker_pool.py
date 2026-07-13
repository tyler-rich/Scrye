"""Tests for the DB-connection-pool handling of running scans (CON-10).

A scan used to pin its pooled connection for its whole wall-clock (across the
minutes-long scanner subprocess), so concurrency was silently bounded by the
pool and every API call 500'd past that. The worker now releases the connection
before the subprocess and re-acquires only for persistence; the pool is also
sized from ``max_concurrent_scans`` (capped) as defense-in-depth.
"""

from __future__ import annotations

import pytest

from app.core.config import Settings
from app.db.session import (
    _POOL_HEADROOM,  # type: ignore[attr-defined]
    SessionLocal,
    create_db_engine,
    engine,
)
from app.workers import inprocess
from app.workers.inprocess import InProcessScanWorker
from tests.test_worker import _make_execution, _queue_scan


@pytest.mark.asyncio
async def test_running_scan_holds_no_pooled_connection_during_subprocess(db, monkeypatch) -> None:
    """While the scanner subprocess runs, the worker must hold no connection."""
    seen: dict[str, int] = {}

    class _PoolProbeScanner:
        async def scan_image(self, target, options, *, env=None):
            # Sampled at the moment the subprocess would be running.
            seen["checked_out"] = engine.pool.checkedout()
            return _make_execution()

    monkeypatch.setattr(inprocess, "get_scanner", lambda s: _PoolProbeScanner())

    scan_id = _queue_scan(db)
    db.rollback()  # release the test session's own connection for a clean baseline

    worker = InProcessScanWorker(SessionLocal, max_concurrent=1)
    await worker.submit(scan_id)
    await worker.shutdown()

    assert seen["checked_out"] == 0, (
        "the worker pinned a pooled connection across the scanner subprocess "
        f"(checked out: {seen['checked_out']})"
    )


def test_pool_is_sized_from_max_concurrent_scans() -> None:
    settings = Settings(max_concurrent_scans=8)
    sized = create_db_engine(settings)
    try:
        # pool_size = max_concurrent_scans + headroom; overflow mirrors it.
        assert sized.pool.size() == 8 + _POOL_HEADROOM
    finally:
        sized.dispose()


def test_max_concurrent_scans_is_capped() -> None:
    with pytest.raises(ValueError):
        Settings(max_concurrent_scans=1000)
    with pytest.raises(ValueError):
        Settings(max_concurrent_scans=0)
