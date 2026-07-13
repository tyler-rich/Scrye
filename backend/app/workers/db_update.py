"""Scheduled scanner vulnerability-DB updates (FEAT-4).

The Scanners settings group exposes ``auto_update_db`` + ``db_update_interval_hours``.
This module makes those knobs real: on the maintenance tick, when auto-update is
enabled and the configured interval has elapsed, it refreshes the Trivy and Grype
vulnerability databases best-effort (``trivy image --download-db-only`` and
``grype db update``), routed at the writable cache volume like every other scanner
invocation. Failures are logged, never raised — a stale DB is degraded, not fatal,
and scans still auto-update their DBs on demand.

The last-run time is tracked in-process; a restart re-checks on the first tick,
which at worst triggers one extra refresh — acceptable for a best-effort job.
"""

from __future__ import annotations

import logging

import anyio.to_thread

from app.core.app_settings import SettingsService
from app.core.config import get_settings
from app.db.session import SessionLocal
from app.scanners.base import (
    ScannerError,
    inherited_env,
    resolve_binary,
    run_command,
    scanner_cache_env,
)

logger = logging.getLogger(__name__)

#: Wall-clock cap for a single DB-update subprocess (a full DB pull can be slow).
_DB_UPDATE_TIMEOUT_SECONDS = 600

#: Monotonic timestamp of the last successful due-check that ran updates.
_last_update_monotonic: float | None = None


def _read_policy() -> tuple[bool, int]:
    """Return ``(auto_update_enabled, interval_hours)`` from scanner settings."""
    session = SessionLocal()
    try:
        scanners = SettingsService(session).scanners()
        return scanners.auto_update_db, scanners.db_update_interval_hours
    finally:
        session.close()


async def _run_update(binary_setting: str, argv_tail: list[str], engine: str) -> bool:
    """Run one scanner's DB-update command best-effort (logged, never raised).

    Returns True only when the update actually succeeded (exit 0), so the caller
    can decide whether the DBs are fresh enough to defer the next attempt.
    """
    env = {**inherited_env(), **scanner_cache_env()}
    try:
        binary = resolve_binary(binary_setting)
    except ScannerError as exc:
        logger.warning("Skipping %s DB update: %s", engine, exc)
        return False
    try:
        result = await run_command(
            [binary, *argv_tail], timeout=_DB_UPDATE_TIMEOUT_SECONDS, env=env
        )
    except ScannerError as exc:
        logger.warning("%s DB update failed to run: %s", engine, exc)
        return False
    if result.returncode == 0:
        logger.info("%s vulnerability DB updated.", engine)
        return True
    logger.warning("%s DB update exited %d.", engine, result.returncode)
    return False


async def maybe_update_scanner_dbs(*, now: float) -> bool:
    """Refresh the scanner DBs if auto-update is on and the interval has elapsed.

    Args:
        now: A monotonic timestamp (``time.monotonic()``); injected so tests can
            control elapsed time without patching the clock.

    Returns:
        True if an update run was performed this call, else False.
    """
    global _last_update_monotonic
    # This runs on the event loop (the maintenance tick's async path), so the
    # policy read — a fresh session + query on every 60 s tick — is hopped off
    # the loop; a slow writer holding the SQLite lock must not stall the loop
    # inside busy_timeout (CON-5).
    enabled, interval_hours = await anyio.to_thread.run_sync(_read_policy)
    if not enabled:
        return False
    if (
        _last_update_monotonic is not None
        and (now - _last_update_monotonic) < interval_hours * 3600
    ):
        return False

    settings = get_settings()
    trivy_ok = await _run_update(settings.trivy_binary, ["image", "--download-db-only"], "Trivy")
    grype_ok = await _run_update(settings.grype_binary, ["db", "update"], "Grype")
    # Only mark the interval as satisfied when at least one DB actually updated.
    # On a total failure (e.g. a transient registry outage) the marker stays
    # unset so the next tick retries, rather than letting the DBs silently go
    # stale for a full db_update_interval_hours while the UI implies freshness
    # (CON-12).
    if trivy_ok or grype_ok:
        _last_update_monotonic = now
    else:
        logger.warning(
            "Scanner vulnerability-DB auto-update failed for both engines; "
            "will retry on the next maintenance tick."
        )
    return True


def reset_db_update_state() -> None:
    """Clear the in-process last-update marker (app startup / test isolation)."""
    global _last_update_monotonic
    _last_update_monotonic = None
