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

#: scrypt cost parameters (RFC 7914). N must be a power of two. Memory use is
#: ``128 * N * r`` bytes, so ``N=2**17`` with ``r=8`` needs ~128 MiB per
#: derivation — expensive to brute-force offline, per current OWASP guidance,
#: while still deriving in well under a second on a modern host.
SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1
_DERIVED_KEY_BYTES = 32
_SALT_BYTES = 16

#: Upper bounds on restore-supplied scrypt parameters. A bundle's KDF envelope
#: is attacker-controlled input read *before* the passphrase is verified, so an
#: unbounded ``n``/``r``/``p`` lets a crafted upload demand terabytes of memory
#: (or unbounded CPU) and OOM-kill the container pre-auth (SEC-2). Legitimate
#: bundles only ever record the module defaults above, so these ceilings — well
#: above any default this app has ever shipped — break nothing.
_MAX_SCRYPT_N = 2**20
_MAX_SCRYPT_R = 16
_MAX_SCRYPT_P = 4

#: Fixed scrypt memory budget passed as ``maxmem``. Deliberately a constant —
#: deriving it from the bundle's own ``n``/``r`` (as ``128*n*r*2`` used to)
#: widens the guard to whatever the attacker asks for, defeating its purpose.
#: The defaults need ``128*N*r`` = 128 MiB, comfortably within budget.
_SCRYPT_MAXMEM_BYTES = 512 * 1024 * 1024

#: AAD binding the outer bundle ciphertext, distinct from any field AAD.
AAD_BUNDLE = "backup.bundle"


class PassphraseKdfError(ValueError):
    """Raised when passphrase-derivation parameters are invalid."""


def new_salt() -> bytes:
    """Return a fresh random scrypt salt."""
    return os.urandom(_SALT_BYTES)


def derive_key(
    passphrase: str,
    salt: bytes,
    *,
    n: int = SCRYPT_N,
    r: int = SCRYPT_R,
    p: int = SCRYPT_P,
) -> bytes:
    """Derive a 256-bit key from a passphrase and salt via scrypt.

    Args:
        passphrase: The user-supplied backup passphrase.
        salt: Per-backup random salt (see :func:`new_salt`).
        n: scrypt CPU/memory cost factor (a power of two).
        r: scrypt block size.
        p: scrypt parallelization factor. These default to the current module
            constants for a *new* backup, but restore passes the values the
            bundle recorded so a bundle written under different parameters still
            derives the same key (item (g)).

    Returns:
        A 32-byte key suitable for AES-256-GCM.

    Raises:
        PassphraseKdfError: If the passphrase is empty or the parameters are invalid.
    """
    if not passphrase:
        raise PassphraseKdfError("Backup passphrase must not be empty.")
    if n < 2 or (n & (n - 1)) != 0 or r < 1 or p < 1:
        raise PassphraseKdfError("Invalid scrypt parameters in backup bundle.")
    if n > _MAX_SCRYPT_N or r > _MAX_SCRYPT_R or p > _MAX_SCRYPT_P:
        raise PassphraseKdfError(
            "scrypt parameters in backup bundle exceed the supported maximum "
            f"(n<={_MAX_SCRYPT_N}, r<={_MAX_SCRYPT_R}, p<={_MAX_SCRYPT_P})."
        )
    # scrypt needs a little over 128*n*r bytes; keep the historical 2x headroom
    # but reject before allocating anything if it would blow the fixed budget.
    if 128 * n * r * 2 > _SCRYPT_MAXMEM_BYTES:
        raise PassphraseKdfError(
            "scrypt parameters in backup bundle exceed the supported memory budget."
        )
    return hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=_DERIVED_KEY_BYTES,
        maxmem=_SCRYPT_MAXMEM_BYTES,
    )


def passphrase_cipher(
    passphrase: str,
    salt: bytes,
    *,
    n: int = SCRYPT_N,
    r: int = SCRYPT_R,
    p: int = SCRYPT_P,
) -> SecretCipher:
    """Build a :class:`SecretCipher` keyed by a passphrase-derived key.

    The derived key is fed as key-version 1; the cipher's token format and AAD
    handling are identical to the master-key cipher, so a value re-wrapped for a
    backup is decrypted the same way on restore. ``n``/``r``/``p`` default to the
    current constants for backup; restore supplies the bundle's advertised
    parameters so a bundle made under an older work factor still opens.
    """
    return SecretCipher({1: derive_key(passphrase, salt, n=n, r=r, p=p)})
