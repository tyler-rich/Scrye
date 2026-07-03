"""FastAPI dependencies for authentication, RBAC, and CSRF enforcement."""

from __future__ import annotations

import hmac
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.auth.service import CSRF_HEADER, SESSION_COOKIE, find_valid_session
from app.db.models import ROLE_RANK, AuthSession, Role, User
from app.db.session import get_db


@dataclass
class AuthContext:
    """The authenticated user and the session that authenticated them."""

    user: User
    session: AuthSession


def client_ip(request: Request) -> str:
    """Best-effort client IP for rate limiting and audit entries."""
    return request.client.host if request.client else "unknown"


def get_optional_auth(request: Request, db: Session = Depends(get_db)) -> AuthContext | None:
    """Resolve the session cookie to an :class:`AuthContext`, if valid."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    session = find_valid_session(db, token)
    if session is None or not session.user.is_active:
        return None
    db.commit()  # persist the last_seen_at touch
    return AuthContext(user=session.user, session=session)


def require_auth(auth: AuthContext | None = Depends(get_optional_auth)) -> AuthContext:
    """Require a valid login session (401 otherwise)."""
    if auth is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.")
    return auth


def require_role(minimum: Role) -> object:
    """Build a dependency requiring at least ``minimum`` privilege (403 otherwise)."""

    def dependency(auth: AuthContext = Depends(require_auth)) -> AuthContext:
        """Check the authenticated user's role against the required minimum."""
        if ROLE_RANK[auth.user.role] < ROLE_RANK[minimum]:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail=f"Requires the '{minimum.value}' role or higher.",
            )
        return auth

    return dependency


def require_csrf(request: Request, auth: AuthContext = Depends(require_auth)) -> AuthContext:
    """CSRF guard for state-changing endpoints.

    The SPA echoes the per-session CSRF token (from the readable ``scrye_csrf``
    cookie) in the ``X-CSRF-Token`` header; it must match the value stored
    server-side for this session.
    """
    provided = request.headers.get(CSRF_HEADER, "")
    if not provided or not hmac.compare_digest(provided, auth.session.csrf_token):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="CSRF token missing or invalid.")
    return auth
