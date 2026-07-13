"""Write-only secret field helpers for API schemas.

Secret fields are accepted on write and **never** returned on read; reads get a
mask plus a "last updated" timestamp (``docs/ARCHIVE.md`` §6). Schemas for
secret-bearing resources (registries, git credentials, OIDC config, ...) should
expose a :class:`MaskedSecret` in their read models and a plain ``SecretStr``
in their write models, and use :func:`masked_secret` to build the read view.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel

#: The literal mask returned by the API in place of any stored secret.
SECRET_MASK = "••••••••"


class MaskedSecret(BaseModel):
    """Read-model view of a write-only secret field."""

    is_set: bool
    value: str
    updated_at: datetime | None


def masked_secret(updated_at: datetime | None) -> MaskedSecret:
    """Build the read view for a stored secret.

    Args:
        updated_at: When the secret was last written, or ``None`` if unset.

    Returns:
        A :class:`MaskedSecret` that exposes only the mask and timestamp —
        never plaintext, and never the ciphertext either.
    """
    is_set = updated_at is not None
    return MaskedSecret(is_set=is_set, value=SECRET_MASK if is_set else "", updated_at=updated_at)
