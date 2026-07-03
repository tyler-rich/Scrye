"""FastAPI dependencies for authentication, RBAC, and CSRF enforcement.

Two credential kinds resolve to the same :class:`AuthContext`:

- a **session cookie** (browser SPA), which carries a CSRF token, and
- a personal **API token** (``Authorization: Bearer <token>``), which does not.

CSRF protection applies only to cookie auth — bearer tokens are not sent
automatically by browsers, so they are immune to cross-site request forgery and
skip the CSRF check. An API token's effective privilege is the lesser of its
minted role and the owner's current role, so downgrading an account also
downgrades its tokens.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.service import CSRF_HEADER, SESSION_COOKIE, find_valid_session, hash_token
from app.core.timeutil import utcnow
from app.db.models import ROLE_RANK, ApiToken, AuthSession, Role, User
from app.db.session import get_db


@dataclass
class AuthContext:
    """The authenticated user and how they authenticated.

    Exactly one of ``session`` (cookie login) or ``token`` (API token) is set.
    """

    user: User
    session: AuthSession | None = None
    token: ApiToken | None = None

    @property
    def effective_role(self) -> Role:
        """Return the privilege in effect (min of token role and user role)."""
        if self.token is not None and ROLE_RANK[self.token.role] < ROLE_RANK[self.user.role]:
            return self.token.role
        return self.user.role


def client_ip(request: Request) -> str:
    """Best-effort client IP for rate limiting and audit entries."""
    return request.client.host if request.client else "unknown"


def _bearer_token(request: Request) -> str | None:
    """Extract a bearer token from the Authorization header, if present."""
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() == "bearer" and value.strip():
        return value.strip()
    return None


def get_optional_auth(request: Request, db: Session = Depends(get_db)) -> AuthContext | None:
    """Resolve a session cookie or bearer token to an :class:`AuthContext`."""
    cookie = request.cookies.get(SESSION_COOKIE)
    if cookie:
        session = find_valid_session(db, cookie)
        if session is not None and session.user.is_active:
            db.commit()  # persist the last_seen_at touch
            return AuthContext(user=session.user, session=session)

    raw = _bearer_token(request)
    if raw:
        token = db.scalar(select(ApiToken).where(ApiToken.token_hash == hash_token(raw)))
        if token is not None and token.is_valid:
            user = db.get(User, token.owner_id)
            if user is not None and user.is_active:
                token.last_used_at = utcnow()
                db.commit()
                return AuthContext(user=user, token=token)

    return None


def require_auth(auth: AuthContext | None = Depends(get_optional_auth)) -> AuthContext:
    """Require a valid login session or API token (401 otherwise)."""
    if auth is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.")
    return auth


def require_role(minimum: Role) -> object:
    """Build a dependency requiring at least ``minimum`` privilege (403 otherwise)."""

    def dependency(auth: AuthContext = Depends(require_auth)) -> AuthContext:
        """Check the caller's effective role against the required minimum."""
        if ROLE_RANK[auth.effective_role] < ROLE_RANK[minimum]:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail=f"Requires the '{minimum.value}' role or higher.",
            )
        return auth

    return dependency


def require_csrf(request: Request, auth: AuthContext = Depends(require_auth)) -> AuthContext:
    """CSRF guard for state-changing endpoints.

    Cookie logins must echo the per-session CSRF token (from the readable
    ``scrye_csrf`` cookie) in the ``X-CSRF-Token`` header. Bearer-token requests
    carry no cookie and are not forgeable cross-site, so they skip this check.
    """
    if auth.session is None:  # API-token auth: not subject to CSRF
        return auth
    provided = request.headers.get(CSRF_HEADER, "")
    if not provided or not hmac.compare_digest(provided, auth.session.csrf_token):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="CSRF token missing or invalid.")
    return auth
