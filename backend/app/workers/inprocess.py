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
from contextlib import nullcontext

from sqlalchemy import select, update
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
from app.scanners import BaseScanner, ScanExecution, ScannerError, get_scanner, syft
from app.scanners.credentials import (
    REPO_REF_KEYS,
    docker_config_env,
    generic_repo_checkout,
    git_env_token,
    is_http_url,
)
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
            # ScannerError/TargetError messages are operator-safe, but repo scans
            # can surface a scanner stderr that echoes a credential-embedded URL;
            # redact() strips URL userinfo before the message is stored/logged.
            self._fail(session, scan.id, str(exc))
            logger.info("Scan %d failed: %s", scan.id, redact(str(exc)))
            await self._notify(session, scan.id)
            return

        self._persist_success(session, scan, execution, sbom)
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
        Trivy's ``TRIVY_IGNOREFILE`` / ``TRIVY_VEX`` env vars); Grype scans carry
        no such policy, so the overlay is empty.
        """
        if scan.scanner is Scanner.TRIVY:
            policy = load_trivy_policy(session)
            with materialize_trivy_policy(policy) as policy_env:
                return await self._dispatch_target(session, scan, policy_env)
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
        """Store artifacts (raw output + optional SBOM) and findings; succeed."""
        filename, kind = _RAW_ARTIFACT[scan.scanner]
        written: list[str] = []
        stored = store_artifact(scan.id, filename, execution.raw_output)
        written.append(stored.relative_path)
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

        if sbom is not None:
            stored_sbom = store_artifact(scan.id, sbom.filename, sbom.raw_output)
            written.append(stored_sbom.relative_path)
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
            session.commit()
        except Exception:
            # The artifact bytes were already written to disk; if the rows that
            # would own them fail to commit, remove the files so they don't
            # accumulate as orphans. Re-raise so _execute marks the scan failed.
            for relative_path in written:
                with contextlib.suppress(OSError, ValueError):
                    artifact_path(relative_path).unlink(missing_ok=True)
            raise

    def _fail(self, session: Session, scan_id: int, message: str) -> None:
        """Mark a scan failed with a safe, secret-redacted error message."""
        try:
            scan = session.get(Scan, scan_id)
            if scan is None:
                return
            scan.status = ScanStatus.FAILED
            scan.error = redact(message)
            scan.finished_at = utcnow()
            session.commit()
        except Exception:  # noqa: BLE001 - never mask the original failure
            logger.exception("Could not record failure for scan %d.", scan_id)
            session.rollback()
