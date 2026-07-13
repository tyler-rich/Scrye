"""In-process scheduled-backup worker (docs/PLAN.md §8).

Mirrors the scan worker's shape: a single asyncio task on a timer that, when a
scheduled backup is due, runs it in a thread (so the CPU-bound scrypt derivation
and synchronous DB work don't block the event loop). Locked decision §0.2 keeps
everything in-process — no external scheduler — which suits a low-frequency,
best-effort backup cadence.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable

import anyio.to_thread
from sqlalchemy.orm import Session, sessionmaker

from app.backup.scheduled import run_due_backup

logger = logging.getLogger(__name__)

#: How long shutdown waits for the cancelled check task to unwind. The task may
#: be inside a non-cancellable threaded backup (scrypt + DB dump) whose cancel
#: must wait out the thread; bound the wait so shutdown stays within the
#: container stop budget instead of blocking on it (CON-6).
_SHUTDOWN_TASK_TIMEOUT_SECONDS = 5


class BackupScheduler:
    """Periodically triggers due scheduled backups."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        check_interval_seconds: int = 600,
    ) -> None:
        """Create the scheduler.

        Args:
            session_factory: Factory yielding new database sessions.
            check_interval_seconds: How often to check whether a backup is due.
        """
        self._session_factory: Callable[[], Session] = session_factory
        self._interval = check_interval_seconds
        self._task: asyncio.Task[None] | None = None
        self._stopping = asyncio.Event()

    def start(self) -> None:
        """Start the background check loop."""
        if self._task is None:
            self._task = asyncio.create_task(self._run_loop())

    async def shutdown(self) -> None:
        """Stop the loop and wait (bounded) for the task to finish.

        Uses :func:`asyncio.wait` rather than :func:`asyncio.wait_for`: the check
        can be suspended at a non-cancellable threaded backup whose delivered
        cancellation won't land until the thread returns, and ``wait_for`` would
        block awaiting that cancellation. ``wait`` returns after the timeout and
        the still-running task is abandoned (the process is stopping anyway).
        """
        self._stopping.set()
        if self._task is not None:
            self._task.cancel()
            _, pending = await asyncio.wait({self._task}, timeout=_SHUTDOWN_TASK_TIMEOUT_SECONDS)
            if pending:
                logger.warning(
                    "Backup-scheduler task did not stop within %ds; abandoning it.",
                    _SHUTDOWN_TASK_TIMEOUT_SECONDS,
                )
            self._task = None

    def _check_once(self) -> None:
        """Run one due-check against a fresh session (synchronous)."""
        db = self._session_factory()
        try:
            run_due_backup(db)
        finally:
            db.close()

    async def _run_loop(self) -> None:
        """Sleep, then check for a due backup, until shutdown."""
        while not self._stopping.is_set():
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=self._interval)
            except TimeoutError:
                pass
            if self._stopping.is_set():
                break
            try:
                await anyio.to_thread.run_sync(self._check_once)
            except Exception:  # noqa: BLE001 - the loop must survive a bad run
                logger.exception("Scheduled-backup check failed; continuing.")
