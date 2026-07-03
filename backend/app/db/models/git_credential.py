"""Git-provider credential model (docs/PLAN.md §4.1, §7).

A :class:`GitCredential` stores an access token for cloning **private** git
repositories with ``trivy repo``. The token is **field-encrypted**, write-only
over the API, and decrypted only at scan time to authenticate the clone (see
``app.scanners.credentials``). The provider selects how the token is presented
to Trivy: GitHub/GitLab use their documented environment variables; a generic
host embeds the credential in the transient clone URL.
"""

from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutil import utcnow
from app.db.base import Base


class GitProvider(enum.StrEnum):
    """Supported git hosting providers, selecting the auth mechanism.

    ``GITHUB`` / ``GITLAB`` present the token via the ``GITHUB_TOKEN`` /
    ``GITLAB_TOKEN`` environment variables Trivy honors. ``GENERIC`` embeds
    ``username:token`` into the HTTPS clone URL at scan time (never stored,
    never logged).
    """

    GITHUB = "github"
    GITLAB = "gitlab"
    GENERIC = "generic"


class GitCredential(Base):
    """A configured git provider credential (encrypted access token)."""

    __tablename__ = "git_credentials"

    id: Mapped[int] = mapped_column(primary_key=True)
    #: Human-readable label, unique for selection in the UI.
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    provider: Mapped[GitProvider] = mapped_column(
        Enum(
            GitProvider,
            native_enum=False,
            length=16,
            values_callable=lambda e: [m.value for m in e],
        )
    )
    #: Optional host scope hint (e.g. ``git.example.com``); informational.
    host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    #: Non-secret username used for generic HTTPS auth (defaults applied at use).
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    #: Encrypted access token (ciphertext token only; never plaintext).
    token_ciphertext: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    #: When the token was last written (drives the masked read view).
    secret_updated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    created_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_by_username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
