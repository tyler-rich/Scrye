"""Tests for the shielded, fault-isolated lifespan shutdown sequence (CON-7).

The lifespan ``finally`` tears down the maintenance scheduler, backup scheduler,
and scan worker. Previously the three awaits ran sequentially and unshielded, so
a failure (or a second cancellation) mid-sequence skipped ``worker.shutdown()``,
abandoning live scanner subprocesses. ``_shutdown_all`` must always run the
worker shutdown, even when an earlier component's shutdown raises.
"""

from __future__ import annotations

import asyncio

import pytest

from app.main import _shutdown_all


class _Recorder:
    """A stand-in scheduler/worker recording whether ``shutdown`` ran."""

    def __init__(self, *, raises: bool = False) -> None:
        self.raises = raises
        self.called = False

    async def shutdown(self) -> None:
        self.called = True
        if self.raises:
            raise RuntimeError("shutdown boom")


@pytest.mark.asyncio
async def test_worker_shutdown_runs_even_if_a_scheduler_fails() -> None:
    maintenance = _Recorder(raises=True)
    backup = _Recorder(raises=True)
    worker = _Recorder()

    await _shutdown_all(maintenance, backup, worker)

    assert maintenance.called
    assert backup.called
    assert worker.called, "the worker must be shut down even after a scheduler raised"


@pytest.mark.asyncio
async def test_shutdown_completes_under_outer_cancellation() -> None:
    """Wrapped in ``asyncio.shield`` the teardown finishes even if the awaiting
    task is cancelled — mirroring the lifespan forced-exit path."""
    maintenance = _Recorder()
    backup = _Recorder()
    worker = _Recorder()

    async def _run() -> None:
        await asyncio.shield(_shutdown_all(maintenance, backup, worker))

    task = asyncio.create_task(_run())
    await asyncio.sleep(0)  # let it enter the shielded shutdown
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # The shielded inner coroutine still ran to completion.
    assert worker.called and maintenance.called and backup.called
