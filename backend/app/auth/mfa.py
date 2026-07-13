"""TOTP multi-factor authentication helpers (docs/PLAN.md §5).

Optional per-account TOTP MFA built on ``pyotp``. The shared secret is generated
server-side, shown to the user **once** during enrollment (as a manual key plus
an ``otpauth://`` provisioning URI), and stored **field-encrypted** — it is only
decrypted in memory to verify a submitted code. A short in-process store holds
the brief "password OK, awaiting code" state between the two login steps.
"""

from __future__ import annotations

import secrets
import threading
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


def encrypt_mfa_secret(secret: str, *, user_id: object) -> str:
    """Encrypt a TOTP secret for storage (bound to the MFA AAD and the user row)."""
    return encrypt_secret(secret, aad=AAD_MFA_SECRET, row_id=user_id)


def decrypt_mfa_secret(token: str, *, user_id: object) -> str:
    """Decrypt a stored TOTP secret (bound to the MFA AAD and the user row, SEC-7)."""
    return decrypt_secret(token, aad=AAD_MFA_SECRET, row_id=user_id)


#: Challenge purposes. ``verify`` completes an existing enrolled login; ``enroll``
#: completes a policy-forced first-time enrollment (see ``api/auth.py``).
PURPOSE_VERIFY = "verify"
PURPOSE_ENROLL = "enroll"


@dataclass
class _PendingChallenge:
    """A password-verified login awaiting its TOTP code."""

    user_id: int
    purpose: str
    expires_at: float


class PendingMfaStore:
    """In-process store of pending MFA challenges (mirrors the rate limiter).

    Single-container deployment (locked §0.2) makes an in-memory store the right
    fit: challenges are short-lived and losing them on restart just means the
    user re-enters their password. Tokens are opaque 256-bit random values.

    The sync ``login``/``verify_mfa`` endpoints run on different threadpool
    threads, so every access is guarded by a lock — exactly like the sibling
    rate limiter. Without it, one thread's ``_prune`` iterating ``_pending``
    while another inserts raises ``RuntimeError: dictionary changed size during
    iteration`` and 500s an otherwise-valid login (CON-8).
    """

    def __init__(self) -> None:
        """Initialize an empty challenge store."""
        self._pending: dict[str, _PendingChallenge] = {}
        self._lock = threading.Lock()

    def issue(self, user_id: int, purpose: str = PURPOSE_VERIFY) -> str:
        """Create a challenge for ``user_id`` and return its opaque token."""
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._prune()
            self._pending[token] = _PendingChallenge(
                user_id=user_id,
                purpose=purpose,
                expires_at=time.monotonic() + _CHALLENGE_TTL_SECONDS,
            )
        return token

    def consume(self, token: str) -> tuple[int, str] | None:
        """Return ``(user_id, purpose)`` for a valid challenge and delete it, else ``None``."""
        with self._lock:
            self._prune()
            challenge = self._pending.pop(token, None)
        if challenge is None or challenge.expires_at <= time.monotonic():
            return None
        return challenge.user_id, challenge.purpose

    def _prune(self) -> None:
        """Drop expired challenges. Caller must hold ``self._lock``."""
        now = time.monotonic()
        for token in [t for t, c in self._pending.items() if c.expires_at <= now]:
            self._pending.pop(token, None)
