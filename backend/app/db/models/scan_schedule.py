"""Scheduled/recurring scan model (docs/ARCHIVE.md §4.6/§12, Phase 6).

A :class:`ScanSchedule` is a saved scan template plus a cron cadence. The
in-process maintenance scheduler fires due schedules, creating a real
:class:`~app.db.models.scan.Scan` from the stored template each time. No secret
material lives here — a private image/repo references a registry/git credential
by id, resolved (and decrypted) only when the scan actually runs.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutil import utcnow
from app.db.base import Base
from app.db.models.scan import Scanner, TargetType, _enum_column


class ScanSchedule(Base):
    """A recurring scan defined by a cron expression and a scan template."""

    __tablename__ = "scan_schedules"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    #: Standard 5-field cron expression (minute hour dom month dow).
    cron: Mapped[str] = mapped_column(String(128))

    scanner: Mapped[Scanner] = mapped_column(_enum_column(Scanner, 16))
    target_type: Mapped[TargetType] = mapped_column(_enum_column(TargetType, 16))
    target: Mapped[str] = mapped_column(String(512))
    #: Stored scan options (scanner selection, severity, ignore-unfixed, ...).
    options: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    registry_id: Mapped[int | None] = mapped_column(
        ForeignKey("registries.id", ondelete="SET NULL"), nullable=True
    )
    git_credential_id: Mapped[int | None] = mapped_column(
        ForeignKey("git_credentials.id", ondelete="SET NULL"), nullable=True
    )

    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    #: Id of the most recent scan this schedule launched (for the UI to link).
    last_scan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    #: Short status string from the last firing (e.g. ``"ok"`` or an error).
    last_status: Mapped[str | None] = mapped_column(String(255), nullable=True)

    created_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_by_username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
