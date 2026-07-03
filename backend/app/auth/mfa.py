"""TOTP multi-factor authentication helpers (docs/PLAN.md §5).

Optional per-account TOTP MFA built on ``pyotp``. The shared secret is generated
server-side, shown to the user **once** during enrollment (as a manual key plus
an ``otpauth://`` provisioning URI), and stored **field-encrypted** — it is only
decrypted in memory to verify a submitted code. A short in-process store holds
the brief "password OK, awaiting code" state between the two login steps.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass

import pyotp

from app.core.secret_store import AAD_MFA_SECRET, decrypt_secret, encrypt_secret

#: Accept codes from the adjacent time windows to tolerate clock drift.
_TOTP_VALID_WINDOW = 1
#: Lifetime of a pending-MFA challenge token (seconds).
_CHALLENGE_TTL_SECONDS = 300


def generate_secret() -> str:
    """Return a fresh base32 TOTP secret."""
    return pyotp.random_base32()


def provisioning_uri(secret: str, *, username: str, issuer: str) -> str:
    """Return the ``otpauth://`` URI for enrolling ``secret`` in an authenticator."""
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify_code(secret: str, code: str) -> bool:
    """Return True if ``code`` is a currently-valid TOTP for ``secret``."""
    cleaned = code.strip().replace(" ", "")
    if not cleaned.isdigit():
        return False
    return pyotp.TOTP(secret).verify(cleaned, valid_window=_TOTP_VALID_WINDOW)


def encrypt_mfa_secret(secret: str) -> str:
    """Encrypt a TOTP secret for storage (bound to the MFA AAD)."""
    return encrypt_secret(secret, aad=AAD_MFA_SECRET)


def decrypt_mfa_secret(token: str) -> str:
    """Decrypt a stored TOTP secret (bound to the MFA AAD)."""
    return decrypt_secret(token, aad=AAD_MFA_SECRET)


@dataclass
class _PendingChallenge:
    """A password-verified login awaiting its TOTP code."""

    user_id: int
    expires_at: float


class PendingMfaStore:
    """In-process store of pending MFA challenges (mirrors the rate limiter).

    Single-container deployment (locked §0.2) makes an in-memory store the right
    fit: challenges are short-lived and losing them on restart just means the
    user re-enters their password. Tokens are opaque 256-bit random values.
    """

    def __init__(self) -> None:
        """Initialize an empty challenge store."""
        self._pending: dict[str, _PendingChallenge] = {}

    def issue(self, user_id: int) -> str:
        """Create a challenge for ``user_id`` and return its opaque token."""
        self._prune()
        token = secrets.token_urlsafe(32)
        self._pending[token] = _PendingChallenge(
            user_id=user_id, expires_at=time.monotonic() + _CHALLENGE_TTL_SECONDS
        )
        return token

    def consume(self, token: str) -> int | None:
        """Return the user id for a valid challenge and delete it, else ``None``."""
        self._prune()
        challenge = self._pending.pop(token, None)
        if challenge is None or challenge.expires_at <= time.monotonic():
            return None
        return challenge.user_id

    def _prune(self) -> None:
        """Drop expired challenges."""
        now = time.monotonic()
        for token in [t for t, c in self._pending.items() if c.expires_at <= now]:
            self._pending.pop(token, None)
