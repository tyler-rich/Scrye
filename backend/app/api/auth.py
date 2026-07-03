"""Authentication endpoints: bootstrap, login/logout, sessions, password.

Security posture (docs/PLAN.md §5):

- Login/setup are rate-limited per client IP (in-process sliding window).
- Session cookies are ``HttpOnly`` + ``SameSite=Lax`` (+ ``Secure`` per config);
  the CSRF token rides a readable companion cookie and must be echoed in the
  ``X-CSRF-Token`` header on every state-changing request.
- Failure responses never reveal whether a username exists, and unknown-user
  logins burn an argon2 verification so timing doesn't reveal it either.
- Every security-relevant event lands in the audit log.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.schemas import (
    AuthStatusOut,
    CredentialsIn,
    LoginOut,
    NewUserIn,
    PasswordChangeIn,
    SessionOut,
    UserOut,
)
from app.auth import service
from app.auth.deps import AuthContext, client_ip, get_optional_auth, require_auth, require_csrf
from app.auth.passwords import hash_password, verify_password
from app.core.audit import record_audit
from app.core.config import get_settings
from app.db.models import AuthSession, Role
from app.db.session import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


def _enforce_rate_limit(request: Request) -> None:
    """Apply the per-IP auth rate limit (429 with Retry-After when exceeded)."""
    allowed, retry_after = request.app.state.auth_limiter.allow(client_ip(request))
    if not allowed:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many authentication attempts; try again shortly.",
            headers={"Retry-After": str(max(int(retry_after) + 1, 1))},
        )


def _set_session_cookies(response: Response, token: str, csrf_token: str) -> None:
    """Attach the session (HttpOnly) and CSRF (readable) cookies."""
    settings = get_settings()
    max_age = settings.session_lifetime_hours * 3600
    response.set_cookie(
        service.SESSION_COOKIE,
        token,
        max_age=max_age,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="lax",
        path="/",
    )
    response.set_cookie(
        service.CSRF_COOKIE,
        csrf_token,
        max_age=max_age,
        httponly=False,  # the SPA reads this to build the X-CSRF-Token header
        secure=settings.session_cookie_secure,
        samesite="lax",
        path="/",
    )


def _clear_session_cookies(response: Response) -> None:
    """Expire both auth cookies."""
    response.delete_cookie(service.SESSION_COOKIE, path="/")
    response.delete_cookie(service.CSRF_COOKIE, path="/")


@router.get("/status", response_model=AuthStatusOut)
def auth_status(
    db: Session = Depends(get_db),
    auth: AuthContext | None = Depends(get_optional_auth),
) -> AuthStatusOut:
    """Report bootstrap and login state for the SPA (public)."""
    return AuthStatusOut(
        needs_setup=service.count_users(db) == 0,
        authenticated=auth is not None,
        user=UserOut.model_validate(auth.user) if auth else None,
    )


@router.post("/setup", response_model=LoginOut, status_code=status.HTTP_201_CREATED)
def setup_first_admin(
    payload: NewUserIn,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> LoginOut:
    """Create the first account as ``admin`` and log it in (bootstrap).

    Only works while the users table is empty; afterwards it always 409s.
    """
    _enforce_rate_limit(request)
    if service.count_users(db) > 0:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="Setup has already been completed.")

    ip = client_ip(request)
    user = service.create_user(
        db, username=payload.username, password=payload.password, role=Role.ADMIN
    )
    token, session = service.create_session(
        db, user, ip=ip, user_agent=request.headers.get("user-agent")
    )
    user.last_login_at = session.created_at
    record_audit(
        db, action="auth.setup", actor=user, ip=ip, target_type="user", target_id=str(user.id)
    )
    db.commit()

    logger.info("First admin account created: %s", user.username)
    _set_session_cookies(response, token, session.csrf_token)
    return LoginOut(user=UserOut.model_validate(user), csrf_token=session.csrf_token)


@router.post("/login", response_model=LoginOut)
def login(
    payload: CredentialsIn,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> LoginOut:
    """Authenticate with username + password and start a session."""
    _enforce_rate_limit(request)
    ip = client_ip(request)

    user = service.authenticate(db, payload.username, payload.password)
    if user is None:
        record_audit(
            db,
            action="auth.login_failed",
            ip=ip,
            details={"username": payload.username.lower()},
        )
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password.")

    token, session = service.create_session(
        db, user, ip=ip, user_agent=request.headers.get("user-agent")
    )
    user.last_login_at = session.created_at
    record_audit(db, action="auth.login", actor=user, ip=ip)
    db.commit()

    _set_session_cookies(response, token, session.csrf_token)
    return LoginOut(user=UserOut.model_validate(user), csrf_token=session.csrf_token)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
def logout(
    request: Request,
    response: Response,
    auth: AuthContext = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> None:
    """Revoke the current session and clear cookies."""
    service.revoke_session(auth.session)
    record_audit(db, action="auth.logout", actor=auth.user, ip=client_ip(request))
    db.commit()
    _clear_session_cookies(response)


@router.get("/me", response_model=UserOut)
def me(auth: AuthContext = Depends(require_auth)) -> UserOut:
    """Return the authenticated user."""
    return UserOut.model_validate(auth.user)


@router.post("/password", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
def change_password(
    payload: PasswordChangeIn,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> None:
    """Change the caller's password; revokes their other sessions."""
    if not verify_password(auth.user.password_hash, payload.current_password):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Current password is incorrect.")
    auth.user.password_hash = hash_password(payload.new_password)
    revoked = service.revoke_all_sessions(db, auth.user, except_session_id=auth.session.id)
    record_audit(
        db,
        action="auth.password_changed",
        actor=auth.user,
        ip=client_ip(request),
        details={"other_sessions_revoked": revoked},
    )
    db.commit()


@router.get("/sessions", response_model=list[SessionOut])
def list_own_sessions(
    auth: AuthContext = Depends(require_auth),
    db: Session = Depends(get_db),
) -> list[SessionOut]:
    """List the caller's live sessions (for review/revocation)."""
    rows = db.scalars(
        select(AuthSession)
        .where(AuthSession.user_id == auth.user.id, AuthSession.revoked_at.is_(None))
        .order_by(AuthSession.last_seen_at.desc())
    ).all()
    out = []
    for row in rows:
        if not row.is_valid:
            continue
        view = SessionOut.model_validate(row)
        view.current = row.id == auth.session.id
        out.append(view)
    return out


@router.delete(
    "/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None
)
def revoke_own_session(
    session_id: int,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> None:
    """Revoke one of the caller's own sessions by id."""
    session = db.get(AuthSession, session_id)
    if session is None or session.user_id != auth.user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Session not found.")
    service.revoke_session(session)
    record_audit(
        db,
        action="auth.session_revoked",
        actor=auth.user,
        ip=client_ip(request),
        target_type="session",
        target_id=str(session_id),
    )
    db.commit()
