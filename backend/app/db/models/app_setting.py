"""Generic key/value application settings store (docs/PLAN.md §4.5, §7).

The ``settings`` table backs the non-secret configuration that an admin edits at
runtime through the Settings UI: general options, the authentication policy
(local-login toggle, MFA policy), and scanner defaults/thresholds. Each row is a
namespaced key mapping to a JSON value; typed access lives in
``app.core.app_settings``.

Secret-bearing configuration (OIDC client secret, notification credentials, the
backup passphrase) is **not** stored here — those use dedicated field-encrypted
columns so plaintext never lands in a JSON value.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutil import utcnow
from app.db.base import Base


class AppSetting(Base):
    """One namespaced application setting (``key`` → JSON ``value``)."""

    __tablename__ = "settings"

    #: Dotted setting key, e.g. ``general.instance_name`` or ``scanners.defaults``.
    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    #: Arbitrary JSON-serializable value (scalar, list, or object). Never a secret.
    value: Mapped[Any] = mapped_column(JSON, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
    updated_by_username: Mapped[str | None] = mapped_column(String(64), nullable=True)
