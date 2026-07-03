"""Backup bookkeeping models (docs/PLAN.md §8).

:class:`Backup` records one produced backup bundle (its file name, size, and
checksum) so the UI can list and offer downloads. :class:`BackupSchedule` is a
singleton row holding the optional scheduled-backup configuration; the backup
passphrase it needs to re-wrap secrets is itself **field-encrypted** so the
in-process scheduler can use it without the plaintext ever being stored.
"""

from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutil import utcnow
from app.db.base import Base

#: The fixed primary key of the singleton backup-schedule row.
BACKUP_SCHEDULE_ID = 1


class BackupKind(enum.StrEnum):
    """How a backup was produced."""

    MANUAL = "manual"
    SCHEDULED = "scheduled"


class Backup(Base):
    """Metadata for one backup bundle stored on the backups volume."""

    __tablename__ = "backups"

    id: Mapped[int] = mapped_column(primary_key=True)
    #: File name of the bundle within the configured backups directory.
    filename: Mapped[str] = mapped_column(String(255), unique=True)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    #: Hex SHA-256 of the bundle bytes, for integrity verification.
    checksum_sha256: Mapped[str] = mapped_column(String(64))
    kind: Mapped[BackupKind] = mapped_column(
        Enum(
            BackupKind,
            native_enum=False,
            length=16,
            values_callable=lambda e: [m.value for m in e],
        ),
        default=BackupKind.MANUAL,
    )
    app_version: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    created_by_username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    note: Mapped[str | None] = mapped_column(String(255), nullable=True)


class BackupSchedule(Base):
    """Singleton scheduled-backup configuration (id is ``BACKUP_SCHEDULE_ID``)."""

    __tablename__ = "backup_schedules"

    id: Mapped[int] = mapped_column(primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    #: How often to produce a scheduled backup, in hours.
    interval_hours: Mapped[int] = mapped_column(Integer, default=24)
    #: How many scheduled bundles to retain (older ones are pruned).
    retention_count: Mapped[int] = mapped_column(Integer, default=7)
    #: Encrypted passphrase used to re-wrap secrets in scheduled bundles.
    passphrase_ciphertext: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    secret_updated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    #: Short status string from the last scheduled run (e.g. ``"ok"`` or an error).
    last_status: Mapped[str | None] = mapped_column(String(255), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
