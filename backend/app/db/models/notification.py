"""Notification channel model (docs/PLAN.md §4.5).

A :class:`NotificationChannel` records where Scrye can post messages: a generic
webhook, a Discord webhook, an SMTP server, or a Matrix room. Non-secret routing
details (URLs, hosts, recipients) live in the ``config`` JSON; the single secret
per channel (SMTP password, webhook bearer token, or Matrix access token) is
**field-encrypted**, write-only over the API, and decrypted only when a message
is actually sent.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Enum, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutil import utcnow
from app.db.base import Base


class NotificationType(enum.StrEnum):
    """Supported notification channel transports."""

    WEBHOOK = "webhook"
    DISCORD = "discord"
    SMTP = "smtp"
    MATRIX = "matrix"


#: Channel types that carry a stored (encrypted) secret. A plain webhook may be
#: unauthenticated, so its secret is optional; the others' secrets are required.
SECRET_OPTIONAL_TYPES: frozenset[NotificationType] = frozenset({NotificationType.WEBHOOK})


class NotificationChannel(Base):
    """A configured notification destination and its (encrypted) secret."""

    __tablename__ = "notification_channels"

    id: Mapped[int] = mapped_column(primary_key=True)
    #: Human-readable label, unique for selection in the UI.
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    type: Mapped[NotificationType] = mapped_column(
        Enum(
            NotificationType,
            native_enum=False,
            length=16,
            values_callable=lambda e: [m.value for m in e],
        )
    )
    #: Non-secret routing configuration (URLs, SMTP host/port/from/to, room id).
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    #: Encrypted secret (SMTP password / webhook token / Matrix token).
    secret_ciphertext: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    secret_updated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    created_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_by_username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
