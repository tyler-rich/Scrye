"""In-process maintenance scheduler (docs/ARCHIVE.md §12, Phase 6).

A single asyncio task on a one-minute tick that drives the periodic background
work Phase 6 adds:

- firing due **scheduled scans** (cron cadence) and handing them to the worker,
- pruning expired **raw artifacts** per the retention policy.

It mirrors the shape of the existing scan/backup workers and stays in-process per
the locked single-container model (§0.2). The scan subprocesses launched by the
worker are the long-running part; the scheduler's own DB/file work (firing due
schedules, pruning artifacts) can still be sizeable on a large instance, so it is
run in a thread rather than inline on the event loop (API-15).
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable

import anyio.to_thread
from sqlalchemy.orm import Session, sessionmaker

from app.core.retention import run_retention
from app.workers.base import ScanWorker
from app.workers.db_update import maybe_update_scanner_dbs
from app.workers.schedules import fire_due_schedules

logger = logging.getLogger(__name__)

#: How often the maintenance loop wakes. Cron granularity is one minute, so the
#: tick matches: any finer would fire the same minute repeatedly.
_TICK_SECONDS = 60

#: How long shutdown waits for the cancelled tick task to unwind before giving
#: up. A tick can be inside a non-cancellable threaded retention/DB pass whose
#: cancellation must wait out the thread; bounding the wait keeps shutdown within
#: the container stop budget rather than blocking on it (CON-6).
_SHUTDOWN_TASK_TIMEOUT_SECONDS = 5


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
        # The scanner-DB refresh runs as its own detached task (up to two
        # 600 s subprocesses) so a slow update can't delay the next tick's due
        # schedules/retention (CON-13). At most one runs at a time.
        self._db_update_task: asyncio.Task[None] | None = None
        self._stopping = asyncio.Event()

    def start(self) -> None:
        """Start the background maintenance loop."""
        if self._task is None:
            self._task = asyncio.create_task(self._run_loop())

    async def shutdown(self) -> None:
        """Stop the loop and wait (bounded) for the tasks to finish.

        Uses :func:`asyncio.wait` rather than :func:`asyncio.wait_for`: a task
        can be suspended at a non-cancellable ``to_thread`` pass (or an
        in-flight DB-update subprocess) whose delivered cancellation won't land
        immediately, and ``wait_for`` would block awaiting it. ``wait`` returns
        after the timeout and any still-running task is abandoned (the process
        is stopping anyway).
        """
        self._stopping.set()
        tasks = {t for t in (self._task, self._db_update_task) if t is not None}
        if tasks:
            for task in tasks:
                task.cancel()
            _, pending = await asyncio.wait(tasks, timeout=_SHUTDOWN_TASK_TIMEOUT_SECONDS)
            if pending:
                logger.warning(
                    "Maintenance tasks did not stop within %ds; abandoning them.",
                    _SHUTDOWN_TASK_TIMEOUT_SECONDS,
                )
        self._task = None
        self._db_update_task = None

    async def tick(self) -> None:
        """Run one maintenance pass: watchdog, schedules, retention, DB refresh."""
        # Self-heal scans stranded queued/running with no live worker task
        # (lost submits on shutdown races, commit chains broken by lock
        # contention) so they recover within a tick instead of at the next
        # container restart (CON-1/CON-11).
        await self._worker.reconcile_stale()
        await self._fire_schedules()
        # Retention can unlink thousands of files + delete their rows on the
        # first pass over a large history; keep it off the event loop (API-15).
        await anyio.to_thread.run_sync(self._run_retention)
        # Refresh the scanner vulnerability DBs when due (FEAT-4) as a detached
        # task: the two updates can each run up to 600 s, and awaiting them here
        # would keep the tick from returning — delaying the next tick's due
        # schedules/retention by up to ~20 min (CON-13).
        self._maybe_start_db_update()

    def _maybe_start_db_update(self) -> None:
        """Kick a scanner-DB refresh unless a previous one is still running.

        The update has its own interval due-check, but a fresh subprocess pair
        must not stack on top of an in-flight one (which can outlast the tick),
        so a new task is only started once the previous has finished.
        """
        if self._db_update_task is not None and not self._db_update_task.done():
            return
        self._db_update_task = asyncio.create_task(self._run_db_update())

    async def _run_db_update(self) -> None:
        """Run the due scanner-DB refresh, logging (never raising) any failure."""
        try:
            await maybe_update_scanner_dbs(now=time.monotonic())
        except Exception:  # noqa: BLE001 - a refresh failure must not kill the loop
            logger.exception("Scanner-DB auto-update failed; continuing.")

    async def _fire_schedules(self) -> None:
        """Create scans for due schedules and submit them to the worker."""
        # The schedule query/insert batch runs off-loop; only the (async) submit
        # of each created scan stays on the loop.
        scan_ids = await anyio.to_thread.run_sync(self._fire_due)
        for scan_id in scan_ids:
            await self._worker.submit(scan_id)

    def _fire_due(self) -> list[int]:
        """Fire due schedules in a fresh session; return the created scan ids."""
        db = self._session_factory()
        try:
            return fire_due_schedules(db)
        finally:
            db.close()

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
