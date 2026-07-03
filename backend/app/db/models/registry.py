"""Container-registry credential model (docs/PLAN.md §4.2, §7).

A :class:`Registry` stores the connection details for a container registry plus
a **field-encrypted** credential (password or token). The plaintext secret is
never stored, never returned by the API (write-only, see ``app.core.masking``),
and is decrypted only at scan time to materialize a transient Docker config file
in tmpfs (see ``app.scanners.credentials``).

The ``username`` is treated as non-sensitive metadata (registries need it to
build the ``auth`` blob and it is not secret on its own); only the password/token
is encrypted. Credential-helper auth types (ECR/GCR/ACR) carry no stored secret
— authentication is delegated to a helper binary at scan time.
"""

from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutil import utcnow
from app.db.base import Base


class RegistryAuthType(enum.StrEnum):
    """How Scrye authenticates to a registry.

    ``USERNAME_PASSWORD`` and ``TOKEN`` store an encrypted secret and produce an
    ``auths`` entry in the transient Docker config. The credential-helper types
    produce a ``credHelpers`` entry instead and store no secret; the matching
    helper binary must be present in the runtime image for them to work.
    """

    USERNAME_PASSWORD = "username_password"
    TOKEN = "token"
    AWS_ECR = "aws_ecr"
    GOOGLE_GCR = "google_gcr"
    AZURE_ACR = "azure_acr"


#: Auth types that carry a stored (encrypted) secret vs. delegate to a helper.
SECRET_BEARING_AUTH_TYPES: frozenset[RegistryAuthType] = frozenset(
    {RegistryAuthType.USERNAME_PASSWORD, RegistryAuthType.TOKEN}
)

#: Docker credential-helper name for each credential-helper auth type.
CREDENTIAL_HELPERS: dict[RegistryAuthType, str] = {
    RegistryAuthType.AWS_ECR: "ecr-login",
    RegistryAuthType.GOOGLE_GCR: "gcr",
    RegistryAuthType.AZURE_ACR: "acr-env",
}


class Registry(Base):
    """A configured container registry and its (encrypted) credential."""

    __tablename__ = "registries"

    id: Mapped[int] = mapped_column(primary_key=True)
    #: Human-readable label, unique for selection in the UI.
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    #: Registry host used as the Docker config auth key (e.g. ``ghcr.io``).
    registry_host: Mapped[str] = mapped_column(String(255))
    auth_type: Mapped[RegistryAuthType] = mapped_column(
        Enum(
            RegistryAuthType,
            native_enum=False,
            length=24,
            values_callable=lambda e: [m.value for m in e],
        )
    )
    #: Non-secret username used to build the auth blob (nullable for helpers).
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    #: Encrypted password/token (ciphertext token only; never plaintext).
    secret_ciphertext: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    #: When the secret was last written (drives the write-only masked read view).
    secret_updated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    #: Whether this registry is offered when launching scans.
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    created_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_by_username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    def uses_credential_helper(self) -> bool:
        """Return True when auth is delegated to a Docker credential helper."""
        return self.auth_type in CREDENTIAL_HELPERS
