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


class NotificationEvent(enum.StrEnum):
    """Events a channel can subscribe to (docs/PLAN.md §4.6, Phase 6).

    Dispatch is opt-in per channel: a channel is only notified about the events
    listed in its ``events`` array.
    """

    #: A scan finished successfully (any result).
    SCAN_COMPLETED = "scan_completed"
    #: A scan failed (scanner/target error).
    SCAN_FAILED = "scan_failed"
    #: A completed scan found at least one CRITICAL or HIGH finding.
    SCAN_HIGH_SEVERITY = "scan_high_severity"


#: Channel types whose stored (encrypted) secret is optional. Every current type
#: requires one: SMTP/Matrix carry a password/token, and webhook/Discord treat
#: their URL as the write-only credential (SEC-1), so all four are mandatory.
SECRET_OPTIONAL_TYPES: frozenset[NotificationType] = frozenset()


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
    #: Event keys this channel is dispatched for (``NotificationEvent`` values).
    events: Mapped[list[str]] = mapped_column(JSON, default=list)
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
