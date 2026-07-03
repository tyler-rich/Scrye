"""API schemas for registries, git credentials, and Docker environments.

Secret fields (registry password/token, git access token) are **write-only**
(docs/PLAN.md §6): accepted as :class:`~pydantic.SecretStr` on write and never
returned on read. Read models expose a :class:`~app.core.masking.MaskedSecret`
(mask + "last updated") instead of any plaintext or ciphertext.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator

from app.core.masking import MaskedSecret
from app.db.models import SECRET_BEARING_AUTH_TYPES, GitProvider, RegistryAuthType

# --- Registries --------------------------------------------------------------


class RegistryCreateIn(BaseModel):
    """Payload to create a registry credential."""

    name: str = Field(min_length=1, max_length=128)
    registry_host: str = Field(min_length=1, max_length=255)
    auth_type: RegistryAuthType
    username: str | None = Field(default=None, max_length=255)
    secret: SecretStr | None = Field(
        default=None, description="Password or token; required for static-auth types."
    )
    enabled: bool = True

    @field_validator("name", "registry_host")
    @classmethod
    def _strip(cls, value: str) -> str:
        """Trim whitespace and reject an empty value."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("Value must not be empty.")
        return stripped

    @model_validator(mode="after")
    def _check_auth(self) -> RegistryCreateIn:
        """Enforce secret presence rules for the chosen auth type."""
        if self.auth_type in SECRET_BEARING_AUTH_TYPES:
            if self.secret is None or not self.secret.get_secret_value():
                raise ValueError(f"Auth type '{self.auth_type.value}' requires a secret.")
            if self.auth_type is RegistryAuthType.USERNAME_PASSWORD and not self.username:
                raise ValueError("Username/password auth requires a username.")
        elif self.secret is not None:
            raise ValueError(
                f"Auth type '{self.auth_type.value}' uses a credential helper and takes no secret."
            )
        return self


class RegistryUpdateIn(BaseModel):
    """Payload to update a registry credential (all fields optional).

    Omitting ``secret`` leaves the stored secret unchanged; sending a new value
    replaces it. ``secret`` cannot be cleared to empty for a static-auth type.
    """

    name: str | None = Field(default=None, min_length=1, max_length=128)
    registry_host: str | None = Field(default=None, min_length=1, max_length=255)
    username: str | None = Field(default=None, max_length=255)
    secret: SecretStr | None = None
    enabled: bool | None = None


class RegistryOut(BaseModel):
    """Read view of a registry credential (secret masked, never returned)."""

    id: int
    name: str
    registry_host: str
    auth_type: RegistryAuthType
    username: str | None
    enabled: bool
    secret: MaskedSecret
    created_by_username: str | None
    created_at: datetime
    updated_at: datetime


class RegistryTestOut(BaseModel):
    """Result of a registry connectivity/credential test."""

    ok: bool
    detail: str


# --- Git credentials ---------------------------------------------------------


class GitCredentialCreateIn(BaseModel):
    """Payload to create a git provider credential."""

    name: str = Field(min_length=1, max_length=128)
    provider: GitProvider
    host: str | None = Field(default=None, max_length=255)
    username: str | None = Field(default=None, max_length=255)
    token: SecretStr = Field(description="Access token used to clone private repositories.")

    @field_validator("name")
    @classmethod
    def _strip(cls, value: str) -> str:
        """Trim whitespace and reject an empty name."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("Name must not be empty.")
        return stripped

    @model_validator(mode="after")
    def _check_token(self) -> GitCredentialCreateIn:
        """Reject an empty token."""
        if not self.token.get_secret_value():
            raise ValueError("Token must not be empty.")
        return self


class GitCredentialUpdateIn(BaseModel):
    """Payload to update a git credential (all fields optional)."""

    name: str | None = Field(default=None, min_length=1, max_length=128)
    host: str | None = Field(default=None, max_length=255)
    username: str | None = Field(default=None, max_length=255)
    token: SecretStr | None = None


class GitCredentialOut(BaseModel):
    """Read view of a git credential (token masked, never returned)."""

    id: int
    name: str
    provider: GitProvider
    host: str | None
    username: str | None
    token: MaskedSecret
    created_by_username: str | None
    created_at: datetime
    updated_at: datetime


# --- Docker environments -----------------------------------------------------


class DockerEnvironmentCreateIn(BaseModel):
    """Payload to create a read-only Docker environment."""

    name: str = Field(min_length=1, max_length=128)
    proxy_url: str = Field(min_length=1, max_length=512)
    risk_acknowledged: bool = False
    enabled: bool = True

    @field_validator("name", "proxy_url")
    @classmethod
    def _strip(cls, value: str) -> str:
        """Trim whitespace and reject an empty value."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("Value must not be empty.")
        return stripped


class DockerEnvironmentUpdateIn(BaseModel):
    """Payload to update a Docker environment (all fields optional)."""

    name: str | None = Field(default=None, min_length=1, max_length=128)
    proxy_url: str | None = Field(default=None, min_length=1, max_length=512)
    risk_acknowledged: bool | None = None
    enabled: bool | None = None


class DockerEnvironmentOut(BaseModel):
    """Read view of a Docker environment."""

    id: int
    name: str
    proxy_url: str
    risk_acknowledged: bool
    enabled: bool
    created_by_username: str | None
    created_at: datetime
    updated_at: datetime


class DockerImageOut(BaseModel):
    """One image enumerated from a Docker environment."""

    id: str
    tags: list[str]
    size_bytes: int
