"""Passphrase-derived encryption for portable backups (docs/PLAN.md §8).

A backup bundle must survive a move to a fresh host that has a *different*
application master key, so its secrets cannot stay wrapped under that master key.
Instead the bundle is protected by a **user-supplied passphrase**: a 256-bit key
is derived from the passphrase with **scrypt** (memory-hard, salted per backup),
and that key drives the same AES-256-GCM field encryption used everywhere else.

On backup, each stored secret is decrypted under the host master key and
re-encrypted under the passphrase key; the whole bundle is then encrypted under
the passphrase key too. On restore the reverse happens, re-wrapping secrets
under the new host's master key.
"""

from __future__ import annotations

import hashlib
import os

from app.core.crypto import SecretCipher

#: scrypt cost parameters (RFC 7914). N must be a power of two; these give a
#: ~64 MiB, sub-second derivation that is expensive to brute-force offline.
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
_DERIVED_KEY_BYTES = 32
_SALT_BYTES = 16

#: AAD binding the outer bundle ciphertext, distinct from any field AAD.
AAD_BUNDLE = "backup.bundle"


class PassphraseKdfError(ValueError):
    """Raised when passphrase-derivation parameters are invalid."""


def new_salt() -> bytes:
    """Return a fresh random scrypt salt."""
    return os.urandom(_SALT_BYTES)


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from a passphrase and salt via scrypt.

    Args:
        passphrase: The user-supplied backup passphrase.
        salt: Per-backup random salt (see :func:`new_salt`).

    Returns:
        A 32-byte key suitable for AES-256-GCM.

    Raises:
        PassphraseKdfError: If the passphrase is empty.
    """
    if not passphrase:
        raise PassphraseKdfError("Backup passphrase must not be empty.")
    return hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=_DERIVED_KEY_BYTES,
        maxmem=128 * SCRYPT_N * SCRYPT_R * 2,
    )


def passphrase_cipher(passphrase: str, salt: bytes) -> SecretCipher:
    """Build a :class:`SecretCipher` keyed by a passphrase-derived key.

    The derived key is fed as key-version 1; the cipher's token format and AAD
    handling are identical to the master-key cipher, so a value re-wrapped for a
    backup is decrypted the same way on restore.
    """
    return SecretCipher({1: derive_key(passphrase, salt)})
