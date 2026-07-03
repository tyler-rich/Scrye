"""Personal API token generation helpers (docs/PLAN.md §5).

A token is an opaque random string with a recognizable prefix. Only its SHA-256
hash is stored (via :func:`app.auth.service.hash_token`); the plaintext is shown
to the owner exactly once at creation. A short, non-secret prefix is retained so
the owner can tell their tokens apart in the UI.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from app.auth.service import hash_token

#: Leading marker so a leaked token is recognizable (e.g. in secret scanners).
TOKEN_PREFIX = "scrye_pat_"
#: Number of leading characters retained for display.
_PREFIX_DISPLAY_LEN = 14


@dataclass(frozen=True)
class GeneratedToken:
    """A freshly minted token: its plaintext (shown once) and stored fields."""

    raw: str
    prefix: str
    token_hash: str


def generate_api_token() -> GeneratedToken:
    """Generate a new API token and its storable prefix/hash."""
    raw = TOKEN_PREFIX + secrets.token_urlsafe(32)
    return GeneratedToken(raw=raw, prefix=raw[:_PREFIX_DISPLAY_LEN], token_hash=hash_token(raw))
