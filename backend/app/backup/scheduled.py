"""Scheduled-backup execution and retention (docs/PLAN.md §8).

Pure, synchronous helpers the in-process scheduler calls on a timer. Kept out of
the worker so they can be unit-tested directly against a session. The scheduled
passphrase is decrypted here, in memory, only to build the bundle.
"""

from __future__ import annotations

import logging
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import __version__
from app.backup.bundle import build_bundle
from app.backup.store import BUNDLE_SUFFIX, BackupStore, sha256_hex
from app.core.crypto import SecretDecryptError
from app.core.secret_store import AAD_BACKUP_PASSPHRASE, decrypt_secret
from app.core.timeutil import utcnow
from app.db.models import BACKUP_SCHEDULE_ID, Backup, BackupKind, BackupSchedule

logger = logging.getLogger(__name__)


def _is_due(schedule: BackupSchedule) -> bool:
    """Return True when the schedule is enabled and its interval has elapsed."""
    if not schedule.enabled or not schedule.passphrase_ciphertext:
        return False
    if schedule.last_run_at is None:
        return True
    return utcnow() - schedule.last_run_at >= timedelta(hours=schedule.interval_hours)


def prune_scheduled(db: Session, keep: int, *, store: BackupStore | None = None) -> int:
    """Delete scheduled backups beyond the newest ``keep`` (returns count pruned)."""
    store = store or BackupStore()
    rows = db.scalars(
        select(Backup).where(Backup.kind == BackupKind.SCHEDULED).order_by(Backup.created_at.desc())
    ).all()
    pruned = 0
    for old in rows[keep:]:
        store.delete(old.filename)
        db.delete(old)
        pruned += 1
    return pruned


def run_due_backup(db: Session, *, store: BackupStore | None = None, force: bool = False) -> str:
    """Create a scheduled backup if due; return a short status string.

    Args:
        db: Active session (the whole run commits here).
        store: Optional backup store override (for tests).
        force: Ignore the interval check and run if enabled/configured.

    Returns:
        ``"skipped"`` when nothing was due, ``"ok"`` on success, or a short
        error string on failure (also recorded on the schedule row).
    """
    schedule = db.get(BackupSchedule, BACKUP_SCHEDULE_ID)
    if schedule is None or (not force and not _is_due(schedule)):
        return "skipped"
    if not schedule.enabled or not schedule.passphrase_ciphertext:
        return "skipped"

    store = store or BackupStore()
    try:
        passphrase = decrypt_secret(schedule.passphrase_ciphertext, aad=AAD_BACKUP_PASSPHRASE)
    except SecretDecryptError:
        schedule.last_run_at = utcnow()
        schedule.last_status = "error: passphrase could not be decrypted"
        db.commit()
        return schedule.last_status

    try:
        data = build_bundle(db, passphrase)
        filename = f"scrye-scheduled-{utcnow().strftime('%Y%m%dT%H%M%S')}{BUNDLE_SUFFIX}"
        store.write(data, filename)
        backup = Backup(
            filename=filename,
            size_bytes=len(data),
            checksum_sha256=sha256_hex(data),
            kind=BackupKind.SCHEDULED,
            app_version=__version__,
            created_by_username=None,
            note="Scheduled backup",
        )
        db.add(backup)
        pruned = prune_scheduled(db, schedule.retention_count, store=store)
        schedule.last_run_at = utcnow()
        schedule.last_status = "ok" if not pruned else f"ok (pruned {pruned})"
        db.commit()
    except Exception as exc:  # noqa: BLE001 - a scheduled run must not crash the loop
        db.rollback()
        schedule.last_run_at = utcnow()
        schedule.last_status = f"error: {type(exc).__name__}"
        db.commit()
        logger.exception("Scheduled backup failed.")
        return schedule.last_status
    logger.info("Scheduled backup written: %s", filename)
    return "ok"
