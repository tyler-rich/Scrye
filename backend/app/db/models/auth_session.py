"""Server-side login session model.

Sessions are stored in SQLite so they are revocable (docs/ARCHIVE.md §5). Only a
SHA-256 **hash** of the opaque session token is persisted — a database read
cannot recover a usable cookie value. Each session carries its own CSRF token,
required on state-changing requests.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.timeutil import utcnow
from app.db.base import Base

if TYPE_CHECKING:  # pragma: no cover - import cycle guard for type hints only
    from app.db.models.user import User


class AuthSession(Base):
    """One logged-in browser session for a user."""

    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    user: Mapped[User] = relationship(back_populates="sessions")

    @property
    def is_valid(self) -> bool:
        """Return True if the session is neither revoked nor expired."""
        return self.revoked_at is None and self.expires_at > utcnow()
