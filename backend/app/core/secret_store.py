"""Field-secret helpers for stored credentials (docs/PLAN.md §6).

Thin wrappers over :mod:`app.core.crypto` that bind each stored secret to a
stable **associated-data** (AAD) tag naming its resource and field. Encrypt and
decrypt for a given field must use the same tag, so centralizing the tags here
keeps the two call sites from drifting (a mismatch fails authentication rather
than silently returning the wrong plaintext).

Plaintext rules (unchanged from the crypto module): decrypt only at scan time,
never log the result, never return it from the API.
"""

from __future__ import annotations

from app.core.crypto import get_secret_cipher

#: AAD tag binding a registry password/token blob to its field.
AAD_REGISTRY_SECRET = "registries.secret"
#: AAD tag binding a git access-token blob to its field.
AAD_GIT_TOKEN = "git_credentials.token"


def encrypt_secret(plaintext: str, *, aad: str) -> str:
    """Encrypt ``plaintext`` under the current key version, bound to ``aad``."""
    return get_secret_cipher().encrypt(plaintext, aad=aad)


def decrypt_secret(token: str, *, aad: str) -> str:
    """Decrypt a stored secret token that was bound to ``aad`` on write."""
    return get_secret_cipher().decrypt(token, aad=aad)
