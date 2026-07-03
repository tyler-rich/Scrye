"""In-process async scan worker backed by the ``scans`` table + a semaphore.

Each submitted scan becomes an :class:`asyncio.Task`. A shared
:class:`asyncio.Semaphore` caps how many scans run concurrently; extra tasks
wait for a slot while their row stays ``queued``. When a slot frees, the task
marks the scan ``running``, invokes the scanner, stores the raw output, and
persists normalized findings — flipping the scan to ``succeeded`` or ``failed``.

The subprocess call is genuinely async; the short SQLite reads/writes around it
run synchronously on the loop, which is fine at this scale (single-container,
low concurrency — the locked v1 design).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging

from sqlalchemy import select, update
from sqlalchemy.orm import Session, sessionmaker

from app.core.artifacts import artifact_path, store_artifact
from app.core.timeutil import utcnow
from app.db.models import (
    SEVERITY_RANK,
    Artifact,
    ArtifactKind,
    Finding,
    FindingClass,
    Scan,
    Scanner,
    ScanStatus,
    Severity,
)
from app.scanners import ScanExecution, ScannerError, get_scanner
from app.workers.base import ScanWorker

logger = logging.getLogger(__name__)

#: Artifact metadata (filename + kind) for each scanner's raw JSON output.
_RAW_ARTIFACT: dict[Scanner, tuple[str, ArtifactKind]] = {
    Scanner.TRIVY: ("trivy.json", ArtifactKind.RAW_TRIVY_JSON),
    Scanner.GRYPE: ("grype.json", ArtifactKind.RAW_GRYPE_JSON),
}

#: How long shutdown lets in-flight scans finish before cancelling them. A real
#: scan runs for minutes, so a graceful stop can't wait it out (the container
#: stop grace is seconds); scans still running past this are cancelled and
#: reconciled to ``failed`` by :meth:`InProcessScanWorker.recover` on restart.
_SHUTDOWN_GRACE_SECONDS = 10


def _highest_severity(counts: dict[Severity, int]) -> Severity | None:
    """Return the worst severity with a non-zero count, or ``None``."""
    present = [level for level, count in counts.items() if count > 0]
    if not present:
        return None
    return max(present, key=lambda level: SEVERITY_RANK[level])


class InProcessScanWorker(ScanWorker):
    """Runs scans as asyncio tasks under a concurrency semaphore."""

    def __init__(self, session_factory: sessionmaker[Session], max_concurrent: int) -> None:
        """Initialize the worker.

        Args:
            session_factory: Factory yielding new SQLAlchemy sessions.
            max_concurrent: Maximum scans to run at once (>= 1).
        """
        self._session_factory = session_factory
        self._semaphore = asyncio.Semaphore(max(1, max_concurrent))
        self._tasks: set[asyncio.Task[None]] = set()
        self._accepting = True

    async def submit(self, scan_id: int) -> None:
        """Schedule a queued scan for execution."""
        if not self._accepting:
            logger.warning("Worker is shutting down; not scheduling scan %d.", scan_id)
            return
        task = asyncio.create_task(self._execute(scan_id))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def recover(self) -> None:
        """Reconcile scans interrupted by a previous process.

        ``running`` scans cannot resume (their subprocess died with the old
        process) so they are marked failed. ``queued`` scans are re-submitted.
        """
        session = self._session_factory()
        try:
            interrupted = session.scalars(
                select(Scan).where(Scan.status == ScanStatus.RUNNING)
            ).all()
            for scan in interrupted:
                scan.status = ScanStatus.FAILED
                scan.error = "Interrupted by a server restart."
                scan.finished_at = utcnow()
            requeued = session.scalars(select(Scan).where(Scan.status == ScanStatus.QUEUED)).all()
            requeue_ids = [scan.id for scan in requeued]
            session.commit()
        finally:
            session.close()

        if interrupted:
            logger.info("Marked %d interrupted scan(s) as failed on startup.", len(interrupted))
        for scan_id in requeue_ids:
            await self.submit(scan_id)

    async def shutdown(self) -> None:
        """Stop accepting work; drain briefly, then cancel what's still running.

        Quick scans finish within the grace window; anything still running is
        cancelled (which kills its scanner subprocess) so the container can stop
        promptly instead of blocking for the full scan timeout. Cancelled scans
        are left ``running`` and reconciled to ``failed`` by :meth:`recover` on
        the next start.
        """
        self._accepting = False
        tasks = list(self._tasks)
        if not tasks:
            return
        _, pending = await asyncio.wait(tasks, timeout=_SHUTDOWN_GRACE_SECONDS)
        for task in pending:
            task.cancel()
        if pending:
            logger.info("Cancelling %d scan(s) still running at shutdown.", len(pending))
            await asyncio.gather(*pending, return_exceptions=True)

    async def _execute(self, scan_id: int) -> None:
        """Run a single scan end-to-end, holding a concurrency slot."""
        async with self._semaphore:
            session = self._session_factory()
            try:
                scan = session.get(Scan, scan_id)
                if scan is None:
                    logger.warning("Scan %d vanished before execution.", scan_id)
                    return
                if scan.status != ScanStatus.QUEUED:
                    # Canceled while queued, or already handled — skip.
                    return
                await self._run(session, scan)
            except Exception:  # noqa: BLE001 - last-resort guard; detail logged below
                logger.exception("Unexpected failure while executing scan %d.", scan_id)
                session.rollback()
                self._fail(session, scan_id, "Unexpected internal error during scan execution.")
            finally:
                session.close()

    async def _run(self, session: Session, scan: Scan) -> None:
        """Mark the scan running, invoke the scanner, and persist results."""
        # Atomically claim the scan: transition queued -> running only if it is
        # still queued. This closes the race with a concurrent cancel (which
        # flips queued -> canceled the same way) — SQLite serializes the two
        # writes, so exactly one wins and a cancel is never silently lost.
        started_at = utcnow()
        claimed = session.execute(
            update(Scan)
            .where(Scan.id == scan.id, Scan.status == ScanStatus.QUEUED)
            .values(status=ScanStatus.RUNNING, started_at=started_at)
        )
        session.commit()
        if claimed.rowcount == 0:
            session.refresh(scan)
            logger.info("Scan %d was %s before start; skipping.", scan.id, scan.status.value)
            return
        session.refresh(scan)
        logger.info("Scan %d started: %s %s", scan.id, scan.scanner.value, scan.target)

        try:
            scanner = get_scanner(scan.scanner)
            execution = await scanner.scan_image(scan.target, scan.options or {})
        except ScannerError as exc:
            self._fail(session, scan.id, str(exc))
            logger.info("Scan %d failed: %s", scan.id, exc)
            return

        self._persist_success(session, scan, execution)
        logger.info(
            "Scan %d succeeded: %d finding(s), highest=%s",
            scan.id,
            scan.findings_count,
            scan.highest_severity.value if scan.highest_severity else "none",
        )

    def _persist_success(self, session: Session, scan: Scan, execution: ScanExecution) -> None:
        """Store the raw artifact and normalized findings; mark succeeded."""
        filename, kind = _RAW_ARTIFACT[scan.scanner]
        stored = store_artifact(scan.id, filename, execution.raw_output)
        session.add(
            Artifact(
                scan_id=scan.id,
                kind=kind,
                filename=filename,
                content_type="application/json",
                relative_path=stored.relative_path,
                size_bytes=stored.size_bytes,
                sha256=stored.sha256,
            )
        )

        for nf in execution.findings:
            session.add(
                Finding(
                    scan_id=scan.id,
                    finding_class=FindingClass(nf.finding_class),
                    severity=nf.severity,
                    vuln_id=nf.vuln_id,
                    pkg_name=nf.pkg_name,
                    installed_version=nf.installed_version,
                    fixed_version=nf.fixed_version,
                    title=nf.title,
                    description=nf.description,
                    location=nf.location,
                    primary_url=nf.primary_url,
                )
            )

        scan.severity_counts = {
            level.value: count for level, count in execution.severity_counts.items()
        }
        scan.findings_count = len(execution.findings)
        scan.highest_severity = _highest_severity(execution.severity_counts)
        scan.scanner_version = execution.scanner_version
        scan.status = ScanStatus.SUCCEEDED
        scan.finished_at = utcnow()
        try:
            session.commit()
        except Exception:
            # The artifact bytes were already written to disk; if the row that
            # would own them fails to commit, remove the file so it doesn't
            # accumulate as an orphan. Re-raise so _execute marks the scan failed.
            with contextlib.suppress(OSError, ValueError):
                artifact_path(stored.relative_path).unlink(missing_ok=True)
            raise

    def _fail(self, session: Session, scan_id: int, message: str) -> None:
        """Mark a scan failed with a safe error message (best-effort)."""
        try:
            scan = session.get(Scan, scan_id)
            if scan is None:
                return
            scan.status = ScanStatus.FAILED
            scan.error = message
            scan.finished_at = utcnow()
            session.commit()
        except Exception:  # noqa: BLE001 - never mask the original failure
            logger.exception("Could not record failure for scan %d.", scan_id)
            session.rollback()
