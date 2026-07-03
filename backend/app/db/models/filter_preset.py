"""Saved scan-history filter presets (docs/PLAN.md §4.4).

A :class:`FilterPreset` stores a named, reusable set of history-view filter
parameters. Presets are **owner-scoped**: a user sees and edits only their own,
so the ``filters`` payload carries no cross-user or secret material — just the
non-sensitive filter selections (scanner, status, severity, tags, ...).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutil import utcnow
from app.db.base import Base


class FilterPreset(Base):
    """A named, owner-scoped set of saved scan-history filters."""

    __tablename__ = "filter_presets"

    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(128))
    #: The saved filter selections (non-sensitive; shape mirrors the history query).
    filters: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    __table_args__ = (UniqueConstraint("owner_id", "name", name="uq_filter_presets_owner_name"),)
