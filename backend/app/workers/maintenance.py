"""In-process maintenance scheduler (docs/PLAN.md §12, Phase 6).

A single asyncio task on a one-minute tick that drives the periodic background
work Phase 6 adds:

- firing due **scheduled scans** (cron cadence) and handing them to the worker,
- pruning expired **raw artifacts** per the retention policy.

It mirrors the shape of the existing scan/backup workers and stays in-process per
the locked single-container model (§0.2). The short DB queries run inline on the
loop (the same trade-off the scan worker documents); only the scan subprocesses,
launched by the worker, are long-running.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable

from sqlalchemy.orm import Session, sessionmaker

from app.core.retention import run_retention
from app.workers.base import ScanWorker
from app.workers.schedules import fire_due_schedules

logger = logging.getLogger(__name__)

#: How often the maintenance loop wakes. Cron granularity is one minute, so the
#: tick matches: any finer would fire the same minute repeatedly.
_TICK_SECONDS = 60


class MaintenanceScheduler:
    """Periodically fires scheduled scans and prunes expired artifacts."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        worker: ScanWorker,
        *,
        tick_seconds: int = _TICK_SECONDS,
    ) -> None:
        """Create the scheduler.

        Args:
            session_factory: Factory yielding new database sessions.
            worker: The scan worker due schedules submit their scans to.
            tick_seconds: How often the maintenance loop runs.
        """
        self._session_factory: Callable[[], Session] = session_factory
        self._worker = worker
        self._interval = tick_seconds
        self._task: asyncio.Task[None] | None = None
        self._stopping = asyncio.Event()

    def start(self) -> None:
        """Start the background maintenance loop."""
        if self._task is None:
            self._task = asyncio.create_task(self._run_loop())

    async def shutdown(self) -> None:
        """Stop the loop and wait for the task to finish."""
        self._stopping.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def tick(self) -> None:
        """Run one maintenance pass: fire due schedules, then prune artifacts."""
        await self._fire_schedules()
        self._run_retention()

    async def _fire_schedules(self) -> None:
        """Create scans for due schedules and submit them to the worker."""
        db = self._session_factory()
        try:
            scan_ids = fire_due_schedules(db)
        finally:
            db.close()
        for scan_id in scan_ids:
            await self._worker.submit(scan_id)

    def _run_retention(self) -> None:
        """Prune expired raw artifacts per the retention policy."""
        db = self._session_factory()
        try:
            run_retention(db)
        finally:
            db.close()

    async def _run_loop(self) -> None:
        """Sleep, then run one maintenance pass, until shutdown."""
        while not self._stopping.is_set():
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=self._interval)
            except TimeoutError:
                pass
            if self._stopping.is_set():
                break
            try:
                await self.tick()
            except Exception:  # noqa: BLE001 - the loop must survive a bad pass
                logger.exception("Maintenance pass failed; continuing.")
