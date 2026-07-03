"""Personal API token model (docs/PLAN.md §4.5, §5).

An :class:`ApiToken` is a bearer credential a user can present in the
``Authorization: Bearer <token>`` header instead of a session cookie. Only the
**SHA-256 hash** of the token is stored, so a database read cannot yield a usable
credential (the same posture as session tokens). A short, non-secret prefix is
kept for display so a user can recognize which token is which. A token's
effective role is capped at its creator's role at mint time, and it can carry an
optional expiry; both are re-checked on every request.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutil import utcnow
from app.db.base import Base
from app.db.models.user import Role


class ApiToken(Base):
    """A personal access token (only its hash is persisted)."""

    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    #: Human-readable label chosen by the owner.
    name: Mapped[str] = mapped_column(String(128))
    #: Non-secret leading characters of the token, shown so it can be identified.
    token_prefix: Mapped[str] = mapped_column(String(16), index=True)
    #: Hex SHA-256 of the full token; the plaintext is shown once at creation.
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    owner_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    owner_username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: Effective role for requests made with this token (≤ owner's role at mint).
    role: Mapped[Role] = mapped_column(
        Enum(Role, native_enum=False, length=16, values_callable=lambda e: [m.value for m in e])
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    @property
    def is_valid(self) -> bool:
        """Return True when the token is neither revoked nor expired."""
        now = utcnow()
        if self.revoked_at is not None:
            return False
        return not (self.expires_at is not None and self.expires_at <= now)
