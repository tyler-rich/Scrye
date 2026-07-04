"""Field-secret helpers for stored credentials (docs/PLAN.md §6).

Thin wrappers over :mod:`app.core.crypto` that bind each stored secret to a
stable **associated-data** (AAD) tag naming its resource **type and field**
(e.g. ``registries.secret``). Encrypt and decrypt for a given field must use the
same tag, so centralizing the tags here keeps the two call sites from drifting (a
mismatch fails authentication rather than silently returning the wrong
plaintext).

Scope note: the AAD binds the *column*, not the *row*. It therefore detects a
ciphertext moved between different fields, but not one relocated between two rows
of the same table. That residual requires DB **write** access, which is outside
the documented threat model (§6 protects against DB **read**); row-binding the
AAD is a possible future hardening but would require re-encrypting every existing
secret under the new tag.

Plaintext rules (unchanged from the crypto module): decrypt only at scan time,
never log the result, never return it from the API.
"""

from __future__ import annotations

from app.core.crypto import get_secret_cipher

#: AAD tag binding a registry password/token blob to its field.
AAD_REGISTRY_SECRET = "registries.secret"
#: AAD tag binding a git access-token blob to its field.
AAD_GIT_TOKEN = "git_credentials.token"
#: AAD tag binding the OIDC client secret blob to its field.
AAD_OIDC_CLIENT_SECRET = "oidc.client_secret"
#: AAD tag binding a notification-channel secret blob to its field.
AAD_NOTIFICATION_SECRET = "notifications.secret"
#: AAD tag binding a user's TOTP MFA secret blob to its field.
AAD_MFA_SECRET = "auth.mfa_secret"
#: AAD tag binding the scheduled-backup passphrase blob to its field.
AAD_BACKUP_PASSPHRASE = "backup.passphrase"

#: Every stored-secret column and its AAD, in ``(table, column, aad)`` form.
#: The backup re-wrap machinery (docs/PLAN.md §8) walks this so a new secret
#: field is portable across hosts the moment it is added here.
SECRET_COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("registries", "secret_ciphertext", AAD_REGISTRY_SECRET),
    ("git_credentials", "token_ciphertext", AAD_GIT_TOKEN),
    ("oidc_config", "client_secret_ciphertext", AAD_OIDC_CLIENT_SECRET),
    ("notification_channels", "secret_ciphertext", AAD_NOTIFICATION_SECRET),
    ("users", "mfa_secret_ciphertext", AAD_MFA_SECRET),
    ("backup_schedules", "passphrase_ciphertext", AAD_BACKUP_PASSPHRASE),
)


def encrypt_secret(plaintext: str, *, aad: str) -> str:
    """Encrypt ``plaintext`` under the current key version, bound to ``aad``."""
    return get_secret_cipher().encrypt(plaintext, aad=aad)


def decrypt_secret(token: str, *, aad: str) -> str:
    """Decrypt a stored secret token that was bound to ``aad`` on write."""
    return get_secret_cipher().decrypt(token, aad=aad)
