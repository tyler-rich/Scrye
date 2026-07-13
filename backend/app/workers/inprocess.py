"""In-process async scan worker backed by the ``scans`` table + a semaphore.

Each submitted scan becomes an :class:`asyncio.Task`. A shared
:class:`asyncio.Semaphore` caps how many scans run concurrently; extra tasks
wait for a slot while their row stays ``queued``. When a slot frees, the task
marks the scan ``running``, invokes the scanner, stores the raw output, and
persists normalized findings — flipping the scan to ``succeeded`` or ``failed``.

The subprocess call is genuinely async. The small status reads/writes around it
run synchronously on the loop, but the potentially large result persistence (a
10k+-findings flush plus the raw-JSON artifact write) is off-loaded to a thread
so it never stalls the event loop — matching the single-container v1 design.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Callable
from contextlib import nullcontext
from datetime import datetime, timedelta

import anyio.to_thread
from sqlalchemy import or_, select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app.core.artifacts import artifact_path, store_artifact
from app.core.config import get_settings
from app.core.logging import redact
from app.core.notification_dispatch import dispatch_scan_event
from app.core.timeutil import utcnow
from app.db.models import (
    SEVERITY_RANK,
    Artifact,
    ArtifactKind,
    Finding,
    FindingClass,
    GitProvider,
    Scan,
    Scanner,
    ScanStatus,
    Severity,
    TargetType,
)
from app.scanners import (
    BaseScanner,
    ScanExecution,
    ScannerError,
    ScannerOutputError,
    get_scanner,
    syft,
)
from app.scanners.credentials import (
    REPO_REF_KEYS,
    docker_config_env,
    generic_repo_checkout,
    git_env_token,
    is_http_url,
)
from app.scanners.grype_policy import load_grype_ignore, materialize_grype_config
from app.scanners.syft import SbomResult
from app.scanners.targets import (
    TargetError,
    resolve_filesystem_path,
    resolve_git_auth,
    resolve_registry_auth,
    resolve_sbom_path,
)
from app.scanners.trivy_policy import load_trivy_policy, materialize_trivy_policy
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

#: Bounded retry policy for worker DB commits that hit SQLite lock contention.
#: A long writer (a large findings flush, a restore, a retention pass) can hold
#: the write lock past the 5 s ``busy_timeout``, turning another committer's
#: ``COMMIT`` into an ``OperationalError``. Losing that commit loses results
#: (CON-1), so the worker retries a few times with exponential backoff — each
#: attempt already waits out ``busy_timeout``, so five attempts ride out ~28 s
#: of sustained contention before giving up.
_LOCK_RETRY_ATTEMPTS = 5
_LOCK_RETRY_INITIAL_DELAY_SECONDS = 0.2
_LOCK_RETRY_BACKOFF_FACTOR = 2.0

#: Age past which a queued/running scan with no live worker task is considered
#: stranded and is reconciled by :meth:`InProcessScanWorker.reconcile_stale`.
#: Generous enough that a scan legitimately in flight between "row committed"
#: and "task registered" is never touched.
_STALE_SCAN_GRACE_SECONDS = 60


def _highest_severity(counts: dict[Severity, int]) -> Severity | None:
    """Return the worst severity with a non-zero count, or ``None``."""
    present = [level for level, count in counts.items() if count > 0]
    if not present:
        return None
    return max(present, key=lambda level: SEVERITY_RANK[level])


def _is_lock_error(exc: OperationalError) -> bool:
    """Return True when ``exc`` is SQLite lock contention (safe to retry)."""
    message = str(exc.orig if exc.orig is not None else exc).lower()
    return "database is locked" in message or "database table is locked" in message


def _commit_with_retry(session: Session, stage: Callable[[], None], *, what: str) -> None:
    """Stage changes and commit, retrying bounded times on SQLite lock errors.

    ``stage`` must (re)apply the pending changes to ``session`` from scratch —
    after a failed attempt the session is rolled back, which expunges pending
    inserts and reverts attribute changes, so each retry re-stages before the
    next commit. Runs synchronously (``time.sleep`` backoff), so callers must
    invoke it from a worker thread, never on the event loop.

    Raises:
        OperationalError: When the final attempt still hits lock contention.
        Exception: Any non-lock error, immediately (no retry).
    """
    delay = _LOCK_RETRY_INITIAL_DELAY_SECONDS
    for attempt in range(1, _LOCK_RETRY_ATTEMPTS + 1):
        try:
            stage()
            session.commit()
            return
        except OperationalError as exc:
            session.rollback()
            if not _is_lock_error(exc) or attempt == _LOCK_RETRY_ATTEMPTS:
                raise
            logger.warning(
                "Database locked while committing %s (attempt %d/%d); retrying in %.1fs.",
                what,
                attempt,
                _LOCK_RETRY_ATTEMPTS,
                delay,
            )
            time.sleep(delay)
            delay *= _LOCK_RETRY_BACKOFF_FACTOR
        except Exception:
            session.rollback()
            raise


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
        self._tasks: dict[int, asyncio.Task[None]] = {}
        self._accepting = True
        # Set = executing normally; cleared = paused (tasks hold before their
        # claim). A restore pauses the worker so nothing new starts while the
        # database is wiped and rebuilt (CON-3).
        self._resume_gate = asyncio.Event()
        self._resume_gate.set()

    def has_task(self, scan_id: int) -> bool:
        """Return True while a live executor task exists for ``scan_id``."""
        return scan_id in self._tasks

    def pause(self) -> None:
        """Hold new scan executions; submissions still queue behind the gate."""
        self._resume_gate.clear()

    def resume(self) -> None:
        """Release executions held by :meth:`pause`."""
        self._resume_gate.set()

    async def submit(self, scan_id: int) -> None:
        """Schedule a queued scan for execution (idempotent per scan)."""
        if not self._accepting:
            logger.warning("Worker is shutting down; not scheduling scan %d.", scan_id)
            return
        if scan_id in self._tasks:
            # Already scheduled (e.g. the watchdog re-submitting a queued scan
            # whose task is alive but waiting on the semaphore) — a second task
            # would only burn a slot to lose the atomic claim.
            return
        task = asyncio.create_task(self._execute(scan_id))
        self._tasks[scan_id] = task
        task.add_done_callback(lambda _task, sid=scan_id: self._tasks.pop(sid, None))

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

    async def reconcile_stale(self) -> None:
        """Self-heal scans stranded with no live executor task (CON-1/CON-11).

        The in-process equivalent of :meth:`recover`, run from the maintenance
        tick: a ``queued`` scan whose submit was lost (shutdown race, task died
        before claiming) is re-submitted — harmless if raced, thanks to the
        atomic claim — and a ``running`` scan whose task is gone (its commit
        chain failed under lock contention) is marked failed instead of sitting
        un-cancellable until the next container restart.
        """
        cutoff = utcnow() - timedelta(seconds=_STALE_SCAN_GRACE_SECONDS)
        stale = await anyio.to_thread.run_sync(self._find_stale, cutoff)
        for scan_id, scan_status in stale:
            if self.has_task(scan_id):
                continue
            if scan_status is ScanStatus.QUEUED:
                if self._accepting:
                    logger.warning("Re-submitting stranded queued scan %d.", scan_id)
                    await self.submit(scan_id)
            else:
                logger.warning("Failing stale running scan %d (no live task).", scan_id)
                await anyio.to_thread.run_sync(self._fail_stale_running, scan_id)

    def _find_stale(self, cutoff: datetime) -> list[tuple[int, ScanStatus]]:
        """Return (id, status) of queued/running scans older than ``cutoff``."""
        session = self._session_factory()
        try:
            rows = session.execute(
                select(Scan.id, Scan.status).where(
                    or_(
                        (Scan.status == ScanStatus.QUEUED) & (Scan.created_at < cutoff),
                        (Scan.status == ScanStatus.RUNNING)
                        & ((Scan.started_at.is_(None)) | (Scan.started_at < cutoff)),
                    )
                )
            ).all()
            return [(row[0], row[1]) for row in rows]
        finally:
            session.close()

    def _fail_stale_running(self, scan_id: int) -> None:
        """Fail a task-less running scan, only if it is still running.

        The conditional UPDATE mirrors the claim: if the scan finished (or was
        otherwise settled) between the stale query and this write, the guard
        makes this a no-op instead of clobbering a terminal state.
        """
        session = self._session_factory()
        try:

            def _stage() -> None:
                session.execute(
                    update(Scan)
                    .where(Scan.id == scan_id, Scan.status == ScanStatus.RUNNING)
                    .values(
                        status=ScanStatus.FAILED,
                        error="Scan was interrupted (no live worker task); "
                        "reconciled by the maintenance watchdog.",
                        finished_at=utcnow(),
                    )
                )

            _commit_with_retry(session, _stage, what=f"watchdog failure of scan {scan_id}")
        except Exception:  # noqa: BLE001 - the watchdog must never kill the tick
            logger.exception("Watchdog could not reconcile stale scan %d.", scan_id)
            session.rollback()
        finally:
            session.close()

    async def shutdown(self) -> None:
        """Stop accepting work; drain briefly, then cancel what's still running.

        Quick scans finish within the grace window; anything still running is
        cancelled (which kills its scanner subprocess) so the container can stop
        promptly instead of blocking for the full scan timeout. Cancelled scans
        are left ``running`` and reconciled to ``failed`` by :meth:`recover` on
        the next start.
        """
        self._accepting = False
        tasks = list(self._tasks.values())
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
            # Hold here while the worker is paused (a restore is rewriting the
            # database); the scan row stays queued and runs after resume.
            await self._resume_gate.wait()
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
                await anyio.to_thread.run_sync(
                    self._fail, session, scan_id, "Unexpected internal error during scan execution."
                )
                await self._notify(session, scan_id)
            finally:
                session.close()

    async def _notify(self, session: Session, scan_id: int) -> None:
        """Dispatch finished-scan notifications; never raise into the worker."""
        try:
            scan = session.get(Scan, scan_id)
            if scan is not None:
                await dispatch_scan_event(session, scan)
        except Exception:  # noqa: BLE001 - notification failures never fail a scan
            logger.exception("Notification dispatch failed for scan %d.", scan_id)

    def _claim(self, session: Session, scan: Scan) -> bool:
        """Atomically claim ``scan`` (queued -> running); True when claimed.

        The conditional UPDATE closes the race with a concurrent cancel (which
        flips queued -> canceled the same way) — SQLite serializes the two
        writes, so exactly one wins and a cancel is never silently lost. The
        commit is lock-retried; runs in a thread (sleeps + synchronous DB I/O).
        """
        claimed_rows = 0

        def _stage() -> None:
            nonlocal claimed_rows
            result = session.execute(
                update(Scan)
                .where(Scan.id == scan.id, Scan.status == ScanStatus.QUEUED)
                .values(status=ScanStatus.RUNNING, started_at=utcnow())
            )
            claimed_rows = result.rowcount

        _commit_with_retry(session, _stage, what=f"claim of scan {scan.id}")
        if claimed_rows == 0:
            # Refresh only to log why; the row may even be gone (e.g. wiped by
            # a concurrent restore), which is equally a reason to skip.
            with contextlib.suppress(Exception):
                session.refresh(scan)
                logger.info("Scan %d was %s before start; skipping.", scan.id, scan.status.value)
            return False
        session.refresh(scan)
        return True

    async def _run(self, session: Session, scan: Scan) -> None:
        """Mark the scan running, invoke the scanner, and persist results."""
        if not await anyio.to_thread.run_sync(self._claim, session, scan):
            return
        logger.info(
            "Scan %d started: %s %s %s",
            scan.id,
            scan.scanner.value,
            scan.target_type.value,
            scan.target,
        )

        try:
            execution, sbom = await self._dispatch(session, scan)
        except ScannerError as exc:
            # A parse failure carries the raw scanner output; persist it so the
            # malformed output stays diagnosable even though the scan failed.
            if isinstance(exc, ScannerOutputError) and exc.raw_output:
                await anyio.to_thread.run_sync(
                    self._store_failure_output, session, scan, exc.raw_output
                )
            # ScannerError/TargetError messages are operator-safe, but repo scans
            # can surface a scanner stderr that echoes a credential-embedded URL;
            # redact() strips URL userinfo before the message is stored/logged.
            await anyio.to_thread.run_sync(self._fail, session, scan.id, str(exc))
            logger.info("Scan %d failed: %s", scan.id, redact(str(exc)))
            await self._notify(session, scan.id)
            return

        # Persisting 10k+ findings + a large raw-JSON write is heavy synchronous
        # DB/disk work; run it in a thread so the event loop (and /healthz, and
        # other scans' subprocess I/O) is not stalled for the flush (API-5).
        await anyio.to_thread.run_sync(self._persist_success, session, scan, execution, sbom)
        logger.info(
            "Scan %d succeeded: %d finding(s), highest=%s",
            scan.id,
            scan.findings_count,
            scan.highest_severity.value if scan.highest_severity else "none",
        )
        await self._notify(session, scan.id)

    async def _dispatch(
        self, session: Session, scan: Scan
    ) -> tuple[ScanExecution, SbomResult | None]:
        """Run the scan for its target type, applying any Trivy policy.

        For Trivy scans the managed VEX documents and ignore rules are resolved
        and materialized into tmpfs for the duration of the run (passed through
        Trivy's ``TRIVY_IGNOREFILE`` / ``TRIVY_VEX`` env vars). Grype scans apply
        the global Grype ignore config the same way, materialized into tmpfs and
        handed to the runner as a ``-c`` config path (FEAT-6).
        """
        # The policy/ignore reads touch the DB (and decrypt secrets); run on the
        # event loop, one arriving while a long writer holds the SQLite lock would
        # stall the whole loop inside busy_timeout, so hop them off (CON-5). Both
        # return detached values (a frozen dataclass / a str) safe to use back on
        # the loop.
        if scan.scanner is Scanner.TRIVY:
            policy = await anyio.to_thread.run_sync(load_trivy_policy, session)
            with materialize_trivy_policy(policy) as policy_env:
                return await self._dispatch_target(session, scan, policy_env)
        if scan.scanner is Scanner.GRYPE:
            grype_ignore = await anyio.to_thread.run_sync(load_grype_ignore, session)
            with materialize_grype_config(grype_ignore) as grype_env:
                return await self._dispatch_target(session, scan, grype_env)
        return await self._dispatch_target(session, scan, {})

    async def _dispatch_target(
        self, session: Session, scan: Scan, base_env: dict[str, str]
    ) -> tuple[ScanExecution, SbomResult | None]:
        """Run the scan appropriate to its target type, resolving credentials.

        Returns the parsed execution plus an optional Syft SBOM (when the scan
        requested one). Registry/git secrets are decrypted here and materialized
        into tmpfs only for the duration of the subprocess. ``base_env`` is a
        non-secret environment overlay (e.g. the Trivy policy) merged under any
        credential overlay.
        """
        scanner = get_scanner(scan.scanner)
        options = scan.options or {}
        target_type = scan.target_type

        if target_type is TargetType.IMAGE:
            return await self._scan_image(session, scanner, scan, options, base_env)
        if target_type is TargetType.REPOSITORY:
            return await self._scan_repo(session, scanner, scan, options, base_env), None
        if target_type is TargetType.FILESYSTEM:
            path = resolve_filesystem_path(scan.target)
            sbom = await self._maybe_sbom(f"dir:{path}", options, base_env or None)
            execution = await scanner.scan_filesystem(path, options, env=base_env or None)
            return execution, sbom
        if target_type is TargetType.SBOM:
            path = resolve_sbom_path(session, scan)
            return await scanner.scan_sbom(path, options, env=base_env or None), None
        raise TargetError(f"Unsupported target type {target_type.value!r}.")

    async def _scan_image(
        self, session: Session, scanner: BaseScanner, scan: Scan, options: dict, base_env: dict
    ) -> tuple[ScanExecution, SbomResult | None]:
        """Scan an image, materializing registry credentials into tmpfs if set.

        The credential file lives only for the lifetime of the ``with`` block —
        which wraps both the optional SBOM pass and the vulnerability scan — and
        is shredded on exit, even on cancellation or error. The credential
        overlay is layered over ``base_env`` (e.g. the Trivy policy).
        """
        auth = resolve_registry_auth(session, options)
        context = docker_config_env(auth) if auth is not None else nullcontext({})
        with context as overlay:
            env = {**base_env, **(overlay or {})} or None
            sbom = await self._maybe_sbom(scan.target, options, env)
            execution = await scanner.scan_image(scan.target, options, env=env)
        return execution, sbom

    async def _scan_repo(
        self, session: Session, scanner: BaseScanner, scan: Scan, options: dict, base_env: dict
    ) -> ScanExecution:
        """Scan a git repository, authenticating a private clone if configured.

        Public repos and hosted providers (GitHub/GitLab) let Trivy clone the
        remote directly — the token, if any, rides in Trivy's native env vars and
        never touches argv. A generic private host is cloned locally first (see
        :func:`generic_repo_checkout`) so its credential stays off the process
        argv, then Trivy scans the local checkout. ``base_env`` (the Trivy policy)
        is merged under any credential overlay.
        """
        auth = resolve_git_auth(session, options)
        if auth is None:
            return await scanner.scan_repo(scan.target, options, env=base_env or None)
        if auth.provider is not GitProvider.GENERIC:
            overlay = git_env_token(auth)
            env = {**base_env, **(overlay or {})} or None
            return await scanner.scan_repo(scan.target, options, env=env)
        if not is_http_url(scan.target):
            # A non-HTTP generic target (e.g. ssh://) carries no URL credential to
            # inject; let Trivy clone it with its own mechanisms.
            return await scanner.scan_repo(scan.target, options, env=base_env or None)

        timeout = get_settings().scan_timeout_seconds
        # The ref is already materialized by our clone; don't re-pass it to Trivy.
        local_options = {k: v for k, v in options.items() if k not in REPO_REF_KEYS}
        async with generic_repo_checkout(scan.target, auth, options, timeout=timeout) as checkout:
            return await scanner.scan_repo(checkout, local_options, env=base_env or None)

    async def _maybe_sbom(
        self, source: str, options: dict, env: dict[str, str] | None
    ) -> SbomResult | None:
        """Generate a Syft SBOM for ``source`` when the scan requested one."""
        if not options.get("generate_sbom"):
            return None
        return await syft.generate_sbom(source, options.get("sbom_format"), env=env)

    def _persist_success(
        self, session: Session, scan: Scan, execution: ScanExecution, sbom: SbomResult | None
    ) -> None:
        """Store artifacts (raw output + optional SBOM) and findings; succeed.

        The artifact files are written to disk once; the DB rows are staged and
        committed under the lock-retry helper, re-staged from scratch on each
        attempt (a rollback expunges the pending inserts). The files are only
        unlinked after the *final* attempt fails — deleting a successful scan's
        results because one commit hit transient contention is exactly the
        data-loss path CON-1 describes.
        """
        filename, kind = _RAW_ARTIFACT[scan.scanner]
        written: list[str] = []
        stored = store_artifact(scan.id, filename, execution.raw_output)
        written.append(stored.relative_path)
        stored_sbom = None
        if sbom is not None:
            stored_sbom = store_artifact(scan.id, sbom.filename, sbom.raw_output)
            written.append(stored_sbom.relative_path)

        def _stage() -> None:
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
            if sbom is not None and stored_sbom is not None:
                session.add(
                    Artifact(
                        scan_id=scan.id,
                        kind=ArtifactKind.SBOM,
                        filename=sbom.filename,
                        content_type="application/json",
                        relative_path=stored_sbom.relative_path,
                        size_bytes=stored_sbom.size_bytes,
                        sha256=stored_sbom.sha256,
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
            _commit_with_retry(session, _stage, what=f"results of scan {scan.id}")
        except Exception:
            # The artifact bytes were already written to disk; if the rows that
            # would own them ultimately fail to commit, remove the files so they
            # don't accumulate as orphans. Re-raise so _execute marks the scan
            # failed.
            for relative_path in written:
                with contextlib.suppress(OSError, ValueError):
                    artifact_path(relative_path).unlink(missing_ok=True)
            raise

    def _store_failure_output(self, session: Session, scan: Scan, raw: bytes) -> None:
        """Persist the raw output attached to a parse failure (best-effort).

        A :class:`ScannerOutputError` means the subprocess ran but produced
        output the parser rejected; storing those bytes as the scan's raw
        artifact is what makes the failure diagnosable. Failures here are
        logged, never raised — the scan is being marked failed regardless.
        """
        filename, kind = _RAW_ARTIFACT[scan.scanner]
        try:
            stored = store_artifact(scan.id, filename, raw)
        except OSError:
            logger.exception("Could not write raw output for failed scan %d.", scan.id)
            return

        def _stage() -> None:
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

        try:
            _commit_with_retry(session, _stage, what=f"raw-output artifact of scan {scan.id}")
        except Exception:  # noqa: BLE001 - never mask the scan's own failure
            logger.exception("Could not record raw-output artifact for scan %d.", scan.id)
            session.rollback()
            with contextlib.suppress(OSError, ValueError):
                artifact_path(stored.relative_path).unlink(missing_ok=True)

    def _fail(self, session: Session, scan_id: int, message: str) -> None:
        """Mark a scan failed with a safe, secret-redacted error message.

        The commit is lock-retried so transient contention (the very condition
        that usually routes a scan here — CON-1) doesn't strand the row
        ``running`` forever. Sleeps between retries: call from a thread.
        """

        def _stage() -> None:
            scan = session.get(Scan, scan_id)
            if scan is None:
                return
            scan.status = ScanStatus.FAILED
            scan.error = redact(message)
            scan.finished_at = utcnow()

        try:
            _commit_with_retry(session, _stage, what=f"failure of scan {scan_id}")
        except Exception:  # noqa: BLE001 - never mask the original failure
            logger.exception("Could not record failure for scan %d.", scan_id)
            session.rollback()
