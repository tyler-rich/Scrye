"""Session and account operations for local auth.

Session tokens are opaque 256-bit random values; only their SHA-256 hash is
stored, so a database read cannot yield a usable cookie. Sessions are revocable
(``revoked_at``) and expire after the configured lifetime.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.passwords import equalize_timing, hash_password, needs_rehash, verify_password
from app.core.config import get_settings
from app.core.timeutil import utcnow
from app.db.models import AuthSession, Role, User

#: Cookie carrying the opaque session token (HttpOnly).
SESSION_COOKIE = "scrye_session"
#: Readable cookie carrying the CSRF token for the SPA to echo back.
CSRF_COOKIE = "scrye_csrf"
#: Header the SPA must send on state-changing requests.
CSRF_HEADER = "x-csrf-token"


def hash_token(token: str) -> str:
    """Return the hex SHA-256 of an opaque session token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def count_users(db: Session) -> int:
    """Return the total number of user accounts."""
    return db.scalar(select(func.count()).select_from(User)) or 0


def get_user_by_username(db: Session, username: str) -> User | None:
    """Look up a user by (case-insensitive, stored-lowercase) username."""
    return db.scalar(select(User).where(User.username == username.lower()))


def create_user(db: Session, *, username: str, password: str, role: Role) -> User:
    """Create a user with an argon2id-hashed password (caller commits)."""
    user = User(username=username.lower(), password_hash=hash_password(password), role=role)
    db.add(user)
    db.flush()
    return user


def authenticate(db: Session, username: str, password: str) -> User | None:
    """Verify credentials and return the active user, or ``None``.

    Timing is equalized for unknown usernames so responses do not reveal
    whether an account exists. Inactive accounts always fail.
    """
    user = get_user_by_username(db, username)
    if user is None:
        equalize_timing()
        return None
    if not verify_password(user.password_hash, password):
        return None
    if not user.is_active:
        return None
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    return user


def create_session(
    db: Session, user: User, *, ip: str | None, user_agent: str | None
) -> tuple[str, AuthSession]:
    """Create a login session and return ``(raw_token, session_row)``.

    The raw token goes into the cookie only — the database keeps its hash.
    Expired and long-revoked rows are purged opportunistically.
    """
    _purge_dead_sessions(db)
    token = secrets.token_urlsafe(32)
    now = utcnow()
    session = AuthSession(
        token_hash=hash_token(token),
        csrf_token=secrets.token_urlsafe(32),
        user_id=user.id,
        created_at=now,
        expires_at=now + timedelta(hours=get_settings().session_lifetime_hours),
        last_seen_at=now,
        ip=ip,
        user_agent=(user_agent or "")[:255] or None,
    )
    db.add(session)
    db.flush()
    return token, session


def find_valid_session(db: Session, raw_token: str) -> AuthSession | None:
    """Resolve a cookie token to a live (unexpired, unrevoked) session."""
    session = db.scalar(select(AuthSession).where(AuthSession.token_hash == hash_token(raw_token)))
    if session is None or not session.is_valid:
        return None
    session.last_seen_at = utcnow()
    return session


def revoke_session(session: AuthSession) -> None:
    """Mark a session revoked (idempotent; caller commits)."""
    if session.revoked_at is None:
        session.revoked_at = utcnow()


def revoke_all_sessions(db: Session, user: User, *, except_session_id: int | None = None) -> int:
    """Revoke every live session of ``user`` (optionally sparing one).

    Returns:
        The number of sessions revoked.
    """
    revoked = 0
    for session in db.scalars(
        select(AuthSession).where(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None))
    ):
        if except_session_id is not None and session.id == except_session_id:
            continue
        revoke_session(session)
        revoked += 1
    return revoked


def _purge_dead_sessions(db: Session) -> None:
    """Delete rows that are expired or were revoked more than a day ago."""
    cutoff = utcnow() - timedelta(days=1)
    for session in db.scalars(
        select(AuthSession).where(
            (AuthSession.expires_at < utcnow()) | (AuthSession.revoked_at < cutoff)
        )
    ):
        db.delete(session)
