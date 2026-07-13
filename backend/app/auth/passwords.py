"""Password hashing with argon2id (docs/ARCHIVE.md §5).

Uses the argon2-cffi ``PasswordHasher`` defaults (argon2id variant, RFC 9106
parameters). Only hashes are ever stored or compared; plaintext passwords must
never be persisted or logged.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_hasher = PasswordHasher()

#: A throwaway hash verified for unknown usernames so login timing does not
#: reveal whether an account exists.
_TIMING_EQUALIZER_HASH = _hasher.hash("scrye-timing-equalizer")


def hash_password(password: str) -> str:
    """Return the argon2id hash of ``password``."""
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Check ``password`` against a stored argon2id hash.

    Returns:
        True on match; False on mismatch or an unusable stored hash (never
        raises on bad input — a corrupt hash reads as "wrong password").
    """
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    """Return True if the stored hash predates the current argon2 parameters."""
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


def equalize_timing() -> None:
    """Burn a verification's worth of CPU for nonexistent-user login attempts."""
    try:
        _hasher.verify(_TIMING_EQUALIZER_HASH, "not-the-equalizer-password")
    except VerifyMismatchError:
        pass  # Expected: the point is the constant-time work, not the result.
