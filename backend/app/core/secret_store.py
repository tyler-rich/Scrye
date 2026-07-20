"""Field-secret helpers for stored credentials (docs/ARCHIVE.md §6).

Thin wrappers over :mod:`app.core.crypto` that bind each stored secret to a
stable **associated-data** (AAD) tag naming its resource **type and field**
(e.g. ``registries.secret``). Encrypt and decrypt for a given field must use the
same tag, so centralizing the tags here keeps the two call sites from drifting (a
mismatch fails authentication rather than silently returning the wrong
plaintext).

Row binding (SEC-7): when a caller supplies ``row_id``, the AAD is
``"<table>.<column>:<row-id>"`` — binding the ciphertext to its specific row, so
a blob relocated between two rows of the same column (a DB **write**-access
threat, outside §6's DB-**read** model) no longer authenticates. This is applied
without a migration: :func:`decrypt_secret` tries the row-bound tag first and
**falls back** to the bare column tag, so every secret written before row binding
(or created before its row id exists) still decrypts, and each secret upgrades to
row binding the next time it is written. Callers that omit ``row_id`` keep the
original column-only behavior.

Plaintext rules (unchanged from the crypto module): decrypt only at scan time,
never log the result, never return it from the API.
"""

from __future__ import annotations

from app.core.crypto import SecretDecryptError, get_secret_cipher

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
#: The backup re-wrap machinery (docs/ARCHIVE.md §8) walks this so a new secret
#: field is portable across hosts the moment it is added here.
SECRET_COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("registries", "secret_ciphertext", AAD_REGISTRY_SECRET),
    ("git_credentials", "token_ciphertext", AAD_GIT_TOKEN),
    ("oidc_config", "client_secret_ciphertext", AAD_OIDC_CLIENT_SECRET),
    ("notification_channels", "secret_ciphertext", AAD_NOTIFICATION_SECRET),
    ("users", "mfa_secret_ciphertext", AAD_MFA_SECRET),
    ("backup_schedules", "passphrase_ciphertext", AAD_BACKUP_PASSPHRASE),
)


def row_aad(aad: str, row_id: object | None) -> str:
    """Compose the row-bound AAD ``"<column-tag>:<row-id>"``, or the bare tag.

    ``row_id=None`` yields the column-only tag (the pre-SEC-7 behavior, and the
    legacy form :func:`decrypt_secret` falls back to).
    """
    return f"{aad}:{row_id}" if row_id is not None else aad


def encrypt_secret(plaintext: str, *, aad: str, row_id: object | None = None) -> str:
    """Encrypt ``plaintext`` bound to ``aad`` and, when given, its ``row_id`` (SEC-7)."""
    return get_secret_cipher().encrypt(plaintext, aad=row_aad(aad, row_id))


def decrypt_secret(token: str, *, aad: str, row_id: object | None = None) -> str:
    """Decrypt a stored secret token.

    When ``row_id`` is given, the row-bound AAD is tried first and the bare
    column tag second, so a value written before row binding (SEC-7) still
    decrypts. With no ``row_id`` only the column tag is used.
    """
    cipher = get_secret_cipher()
    if row_id is not None:
        try:
            return cipher.decrypt(token, aad=row_aad(aad, row_id))
        except SecretDecryptError:
            pass  # legacy column-only ciphertext (written before row binding)
    return cipher.decrypt(token, aad=aad)
