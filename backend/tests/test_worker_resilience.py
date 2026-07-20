"""Tests for the worker's lock-contention retry, watchdog, and pause seam.

Covers the CON-1/CON-11/CON-3 remediation: bounded retry-with-backoff on the
worker's SQLite commits (provoking *real* ``OperationalError`` contention, not a
simulated one), the maintenance-tick watchdog that self-heals scans stranded
``queued``/``running`` with no live task, and the pause gate a restore uses to
hold executions while the database is rewritten.
"""

from __future__ import annotations

import asyncio
import contextlib
import sqlite3
import threading
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.core.artifacts import artifact_path
from app.core.timeutil import utcnow
from app.db import session as db_session
from app.db.models import Scan, Scanner, ScanStatus, TargetType
from app.db.session import SessionLocal, engine
from app.workers import inprocess
from app.workers.inprocess import InProcessScanWorker
from tests.test_worker import _FakeScanner, _make_execution, _queue_scan


def _blocker_connection() -> sqlite3.Connection:
    """Open a raw autocommit connection suitable for holding the write lock."""
    conn = sqlite3.connect(engine.url.database, isolation_level=None, check_same_thread=False)
    conn.execute("PRAGMA busy_timeout=0")
    return conn


def _insert_scan(status: ScanStatus, **overrides) -> int:
    """Insert a scan row directly (bypassing the worker) and return its id."""
    session = SessionLocal()
    try:
        scan = Scan(
            scanner=Scanner.GRYPE,
            target_type=TargetType.IMAGE,
            target="alpine:3.19",
            status=status,
            options={},
            severity_counts={},
            **overrides,
        )
        session.add(scan)
        session.commit()
        return scan.id
    finally:
        session.close()


class TestCommitRetry:
    def test_retry_recovers_from_real_lock_contention(self, db, monkeypatch) -> None:
        """A writer holding the SQLite write lock past ``busy_timeout`` raises a
        genuine ``OperationalError``; the retry helper must ride it out and land
        the commit once the lock is released."""
        monkeypatch.setattr(inprocess, "_LOCK_RETRY_INITIAL_DELAY_SECONDS", 0.05)
        blocker = _blocker_connection()
        blocker.execute("BEGIN IMMEDIATE")  # hold the write lock

        session = SessionLocal()
        attempts = 0
        try:

            def stage() -> None:
                nonlocal attempts
                attempts += 1
                # Fail fast on contention instead of waiting out the full 5 s
                # busy_timeout per attempt (re-applied per attempt: a rollback
                # can return the connection to the pool).
                session.connection().exec_driver_sql("PRAGMA busy_timeout=50")
                if attempts == 3:
                    blocker.execute("ROLLBACK")  # release mid-retry, deterministically
                session.add(
                    Scan(
                        scanner=Scanner.TRIVY,
                        target_type=TargetType.IMAGE,
                        target="contended:1",
                        status=ScanStatus.QUEUED,
                        options={},
                        severity_counts={},
                    )
                )

            inprocess._commit_with_retry(session, stage, what="contention-test row")
        finally:
            session.close()
            blocker.close()

        # Attempts 1 and 2 hit a real "database is locked" OperationalError.
        assert attempts == 3
        db.expire_all()
        row = db.scalar(select(Scan).where(Scan.target == "contended:1"))
        assert row is not None

    def test_non_lock_errors_are_not_retried(self, db) -> None:
        session = SessionLocal()
        attempts = 0
        try:

            def stage() -> None:
                nonlocal attempts
                attempts += 1
                raise RuntimeError("not a lock problem")

            with pytest.raises(RuntimeError):
                inprocess._commit_with_retry(session, stage, what="failing row")
        finally:
            session.close()
        assert attempts == 1

    @pytest.mark.asyncio
    async def test_worker_persists_results_through_lock_contention(self, db, monkeypatch) -> None:
        """CON-1's data-loss scenario, end-to-end: another writer holds the lock
        while a finished scan's results are being committed. The retry must
        recover — scan succeeded, findings persisted, artifact files intact."""
        monkeypatch.setattr(inprocess, "_LOCK_RETRY_INITIAL_DELAY_SECONDS", 0.1)
        # Fresh connections fail contended writes after 100 ms so the retry
        # path (not the in-driver busy wait) is what rides out the contention.
        monkeypatch.setattr(db_session, "_SQLITE_BUSY_TIMEOUT_MS", 100)
        engine.dispose()

        blocker = _blocker_connection()
        release_timer: threading.Timer | None = None
        execution = _make_execution()

        class _ContendingScanner:
            """Takes the write lock when the scan runs, releasing it shortly
            after — so the *persist* commit is the contended one, not the claim."""

            async def scan_image(self, target, options, *, env=None):
                nonlocal release_timer
                blocker.execute("BEGIN IMMEDIATE")
                release_timer = threading.Timer(0.35, lambda: blocker.execute("ROLLBACK"))
                release_timer.start()
                return execution

        monkeypatch.setattr(inprocess, "get_scanner", lambda scanner: _ContendingScanner())
        try:
            scan_id = _queue_scan(db)
            worker = InProcessScanWorker(SessionLocal, max_concurrent=1)
            await worker.submit(scan_id)
            await worker.shutdown()
        finally:
            if release_timer is not None:
                release_timer.cancel()
            blocker.close()
            engine.dispose()  # drop the 100 ms-timeout connections

        db.expire_all()
        scan = db.get(Scan, scan_id)
        assert scan.status is ScanStatus.SUCCEEDED
        assert scan.findings_count == 2
        # The raw artifact was not unlinked by the transient commit failures.
        assert len(scan.artifacts) == 1
        assert artifact_path(scan.artifacts[0].relative_path).is_file()

    @pytest.mark.asyncio
    async def test_exhausted_retries_leave_stuck_scan_that_watchdog_reconciles(
        self, db, monkeypatch
    ) -> None:
        """When contention outlasts every retry the scan is stranded ``running``
        (the historical CON-1 outcome); the watchdog must then reconcile it to
        ``failed`` on the next maintenance tick instead of waiting for a restart."""
        monkeypatch.setattr(inprocess, "_LOCK_RETRY_ATTEMPTS", 2)
        monkeypatch.setattr(inprocess, "_LOCK_RETRY_INITIAL_DELAY_SECONDS", 0.05)
        monkeypatch.setattr(db_session, "_SQLITE_BUSY_TIMEOUT_MS", 100)
        engine.dispose()

        blocker = _blocker_connection()
        execution = _make_execution()

        class _ContendingScanner:
            async def scan_image(self, target, options, *, env=None):
                blocker.execute("BEGIN IMMEDIATE")  # never released during the scan
                return execution

        monkeypatch.setattr(inprocess, "get_scanner", lambda scanner: _ContendingScanner())
        worker = InProcessScanWorker(SessionLocal, max_concurrent=1)
        try:
            scan_id = _queue_scan(db)
            await worker.submit(scan_id)
            await worker.shutdown()
        finally:
            blocker.execute("ROLLBACK")
            blocker.close()
            engine.dispose()

        db.expire_all()
        scan = db.get(Scan, scan_id)
        # Persist and the follow-up failure write both lost to contention.
        assert scan.status is ScanStatus.RUNNING
        assert scan.artifacts == []

        # The watchdog converts "stuck until restart" into "self-heals in a tick".
        monkeypatch.setattr(inprocess, "_STALE_SCAN_GRACE_SECONDS", 0)
        await worker.reconcile_stale()
        db.expire_all()
        scan = db.get(Scan, scan_id)
        assert scan.status is ScanStatus.FAILED
        assert "watchdog" in (scan.error or "")


class TestStaleScanWatchdog:
    @pytest.mark.asyncio
    async def test_resubmits_stranded_queued_scan(self, db, monkeypatch) -> None:
        monkeypatch.setattr(inprocess, "get_scanner", lambda s: _FakeScanner(_make_execution()))
        scan_id = _insert_scan(ScanStatus.QUEUED, created_at=utcnow() - timedelta(seconds=120))
        worker = InProcessScanWorker(SessionLocal, max_concurrent=1)
        await worker.reconcile_stale()
        await worker.shutdown()
        db.expire_all()
        assert db.get(Scan, scan_id).status is ScanStatus.SUCCEEDED

    @pytest.mark.asyncio
    async def test_fails_running_scan_with_no_live_task(self, db) -> None:
        scan_id = _insert_scan(ScanStatus.RUNNING, started_at=utcnow() - timedelta(seconds=120))
        worker = InProcessScanWorker(SessionLocal, max_concurrent=1)
        await worker.reconcile_stale()
        db.expire_all()
        scan = db.get(Scan, scan_id)
        assert scan.status is ScanStatus.FAILED
        assert scan.finished_at is not None
        assert "watchdog" in (scan.error or "")

    @pytest.mark.asyncio
    async def test_leaves_fresh_queued_scan_alone(self, db, monkeypatch) -> None:
        monkeypatch.setattr(inprocess, "get_scanner", lambda s: _FakeScanner(_make_execution()))
        scan_id = _insert_scan(ScanStatus.QUEUED)  # created now — inside the grace
        worker = InProcessScanWorker(SessionLocal, max_concurrent=1)
        await worker.reconcile_stale()
        await worker.shutdown()
        db.expire_all()
        assert db.get(Scan, scan_id).status is ScanStatus.QUEUED

    @pytest.mark.asyncio
    async def test_skips_running_scan_with_live_task(self, db) -> None:
        scan_id = _insert_scan(ScanStatus.RUNNING, started_at=utcnow() - timedelta(seconds=120))
        worker = InProcessScanWorker(SessionLocal, max_concurrent=1)
        # Simulate the scan's executor still being alive.
        guard = asyncio.create_task(asyncio.sleep(30))
        worker._tasks[scan_id] = guard
        try:
            await worker.reconcile_stale()
        finally:
            guard.cancel()
        db.expire_all()
        assert db.get(Scan, scan_id).status is ScanStatus.RUNNING

    @pytest.mark.asyncio
    async def test_maintenance_tick_invokes_watchdog(self, db, monkeypatch) -> None:
        """The wiring test: a stranded queued scan is healed by tick() itself."""
        from app.workers.maintenance import MaintenanceScheduler

        monkeypatch.setattr(inprocess, "get_scanner", lambda s: _FakeScanner(_make_execution()))
        scan_id = _insert_scan(ScanStatus.QUEUED, created_at=utcnow() - timedelta(seconds=120))
        worker = InProcessScanWorker(SessionLocal, max_concurrent=1)
        scheduler = MaintenanceScheduler(SessionLocal, worker)
        await scheduler.tick()
        await scheduler.shutdown()  # drains the detached DB-update task
        await worker.shutdown()
        db.expire_all()
        assert db.get(Scan, scan_id).status is ScanStatus.SUCCEEDED


class TestBoundedSchedulerShutdown:
    @pytest.mark.asyncio
    async def test_shutdown_gives_up_on_a_wedged_task(self, monkeypatch) -> None:
        """A tick stuck in a non-cancellable thread must not hold shutdown past
        the bound — shutdown logs and abandons it instead of blocking (CON-6)."""
        from app.workers import maintenance as maintenance_mod
        from app.workers.maintenance import MaintenanceScheduler

        monkeypatch.setattr(maintenance_mod, "_SHUTDOWN_TASK_TIMEOUT_SECONDS", 0.2)
        scheduler = MaintenanceScheduler(SessionLocal, InProcessScanWorker(SessionLocal, 1))
        release = asyncio.Event()

        async def _wedged() -> None:
            # Swallow cancellation (mimics a cancel delivered while inside a
            # non-cancellable to_thread pass) until the test lets it go, so
            # shutdown must time out rather than await the cancellation.
            while not release.is_set():
                try:
                    await asyncio.sleep(3600)
                except asyncio.CancelledError:
                    continue

        wedged = asyncio.create_task(_wedged())
        scheduler._task = wedged
        loop = asyncio.get_running_loop()
        started = loop.time()
        await scheduler.shutdown()
        elapsed = loop.time() - started

        assert elapsed < 2, "shutdown must not block on a wedged task"
        assert scheduler._task is None

        # Let the abandoned task finish so it isn't garbage-collected pending.
        release.set()
        wedged.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await wedged


class TestMaintenanceDbUpdateDecoupled:
    @pytest.mark.asyncio
    async def test_slow_db_update_does_not_block_the_tick(self, db, monkeypatch) -> None:
        """A tick must return promptly even while a slow scanner-DB refresh runs;
        the refresh proceeds as a detached task (CON-13)."""
        from app.workers import maintenance as maintenance_mod
        from app.workers.maintenance import MaintenanceScheduler

        started = asyncio.Event()
        release = asyncio.Event()

        async def _slow_update(*, now):
            started.set()
            await release.wait()  # stand in for a multi-minute DB pull
            return True

        monkeypatch.setattr(maintenance_mod, "maybe_update_scanner_dbs", _slow_update)
        worker = InProcessScanWorker(SessionLocal, max_concurrent=1)
        scheduler = MaintenanceScheduler(SessionLocal, worker)

        loop = asyncio.get_running_loop()
        t0 = loop.time()
        await scheduler.tick()  # must not wait for the slow update
        assert loop.time() - t0 < 1.0
        await started.wait()  # the update did start, detached
        assert scheduler._db_update_task is not None and not scheduler._db_update_task.done()

        # A second tick while the first update is still running must not stack
        # another update task.
        first_task = scheduler._db_update_task
        await scheduler.tick()
        assert scheduler._db_update_task is first_task

        release.set()
        await scheduler.shutdown()
        await worker.shutdown()


class TestNotificationSlotRelease:
    @pytest.mark.asyncio
    async def test_notification_does_not_hold_the_concurrency_slot(self, db, monkeypatch) -> None:
        """A scan's finished-notification runs after its semaphore slot is
        released, so a slow/dead channel can't starve queued scans (CON-15).
        With max_concurrent=1, a second scan must run to completion while the
        first scan's notification is still blocked."""
        notify_started = asyncio.Event()
        release_notify = asyncio.Event()

        async def _blocking_dispatch(session, scan):
            notify_started.set()
            await release_notify.wait()

        monkeypatch.setattr(inprocess, "dispatch_scan_event", _blocking_dispatch)
        monkeypatch.setattr(inprocess, "get_scanner", lambda s: _FakeScanner(_make_execution()))

        worker = InProcessScanWorker(SessionLocal, max_concurrent=1)
        first = _queue_scan(db)
        second = _queue_scan(db)
        try:
            await worker.submit(first)
            await asyncio.wait_for(notify_started.wait(), timeout=5)
            # First scan is done and stuck in notify; its slot must be free.
            await worker.submit(second)
            for _ in range(100):
                db.expire_all()
                if db.get(Scan, second).status is ScanStatus.SUCCEEDED:
                    break
                await asyncio.sleep(0.02)
            assert db.get(Scan, second).status is ScanStatus.SUCCEEDED
        finally:
            release_notify.set()
            await worker.shutdown()


class TestTaskLifecycle:
    @pytest.mark.asyncio
    async def test_session_factory_failure_leaves_scan_queued(self, db, monkeypatch) -> None:
        """A session-factory failure must be caught and logged (not a silent
        GC-time 'Task exception was never retrieved'); the scan stays QUEUED for
        the watchdog (CON-16)."""
        scan_id = _queue_scan(db)
        worker = InProcessScanWorker(SessionLocal, max_concurrent=1)

        def _boom():
            raise RuntimeError("engine disposed")

        monkeypatch.setattr(worker, "_session_factory", _boom)
        await worker.submit(scan_id)
        await worker.shutdown()  # drains the task

        db.expire_all()
        assert db.get(Scan, scan_id).status is ScanStatus.QUEUED

    @pytest.mark.asyncio
    async def test_done_callback_logs_a_crashed_task(self, monkeypatch) -> None:
        """The done callback retrieves and logs an escaped task exception."""
        worker = InProcessScanWorker(SessionLocal, max_concurrent=1)
        logged: list[tuple] = []
        monkeypatch.setattr(inprocess.logger, "error", lambda *a, **k: logged.append((a, k)))

        async def _boom() -> None:
            raise RuntimeError("kaboom")

        task = asyncio.create_task(_boom())
        await asyncio.gather(task, return_exceptions=True)
        worker._on_task_done(task, 42)  # must not raise

        assert logged, "a crashed task must be logged"
        assert 42 in logged[0][0], "the log must identify the crashed scan"

    @pytest.mark.asyncio
    async def test_submit_defers_when_task_cap_reached(self, db) -> None:
        """Beyond the task cap, submit leaves the scan QUEUED (no new task) so the
        watchdog re-submits it later — task spawning stays bounded (CON-16)."""
        scan_id = _queue_scan(db)
        worker = InProcessScanWorker(SessionLocal, max_concurrent=1)
        worker._submit_cap = 1
        filler = asyncio.create_task(asyncio.sleep(30))
        worker._tasks[-1] = filler  # occupy the only cap slot
        try:
            await worker.submit(scan_id)
            assert scan_id not in worker._tasks  # deferred, not scheduled
        finally:
            filler.cancel()
            worker._tasks.pop(-1, None)
        db.expire_all()
        assert db.get(Scan, scan_id).status is ScanStatus.QUEUED


class TestNotifyStaleRead:
    @pytest.mark.asyncio
    async def test_no_notification_for_a_concurrently_deleted_scan(self, db, monkeypatch) -> None:
        """A scan deleted the instant after it finished must not be announced;
        _notify re-reads the row rather than trusting the identity map (CON-19)."""
        dispatched: list[int] = []

        async def _spy_dispatch(session, scan):
            dispatched.append(scan.id)

        monkeypatch.setattr(inprocess, "dispatch_scan_event", _spy_dispatch)

        scan_id = _insert_scan(ScanStatus.SUCCEEDED)
        worker = InProcessScanWorker(SessionLocal, max_concurrent=1)
        session = SessionLocal()
        try:
            # Prime the worker session's identity map with the scan and hold a
            # strong reference so the (weak) identity map keeps the stale copy —
            # exactly the just-committed scan the worker holds after persistence.
            primed = session.get(Scan, scan_id)
            assert primed is not None
            # ...then delete it through a different session.
            other = SessionLocal()
            try:
                other.delete(other.get(Scan, scan_id))
                other.commit()
            finally:
                other.close()

            await worker._notify(session, scan_id)
            assert primed is not None  # keep the reference alive across _notify
        finally:
            session.close()

        assert dispatched == [], "notified for a scan that was already deleted"


class TestPauseGate:
    @pytest.mark.asyncio
    async def test_paused_worker_defers_execution_until_resume(self, db, monkeypatch) -> None:
        """While paused (a restore is rewriting the DB), a submitted scan must
        not be claimed; it runs to completion once resumed — never lost."""
        monkeypatch.setattr(inprocess, "get_scanner", lambda s: _FakeScanner(_make_execution()))
        scan_id = _queue_scan(db)
        worker = InProcessScanWorker(SessionLocal, max_concurrent=1)
        worker.pause()
        await worker.submit(scan_id)
        await asyncio.sleep(0.2)
        db.expire_all()
        assert db.get(Scan, scan_id).status is ScanStatus.QUEUED

        worker.resume()
        await worker.shutdown()  # drains the now-released task
        db.expire_all()
        assert db.get(Scan, scan_id).status is ScanStatus.SUCCEEDED

    @pytest.mark.asyncio
    async def test_duplicate_submit_is_a_no_op(self, db, monkeypatch) -> None:
        monkeypatch.setattr(inprocess, "get_scanner", lambda s: _FakeScanner(_make_execution()))
        scan_id = _queue_scan(db)
        worker = InProcessScanWorker(SessionLocal, max_concurrent=1)
        worker.pause()
        await worker.submit(scan_id)
        task = worker._tasks[scan_id]
        await worker.submit(scan_id)  # e.g. the watchdog racing a live submit
        assert worker._tasks[scan_id] is task
        worker.resume()
        await worker.shutdown()
        db.expire_all()
        assert db.get(Scan, scan_id).status is ScanStatus.SUCCEEDED
