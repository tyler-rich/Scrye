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
    MfaActivateIn,
    MfaDisableIn,
    MfaEnrollIn,
    MfaEnrollOut,
    MfaVerifyIn,
    NewUserIn,
    OidcStatusOut,
    PasswordChangeIn,
    SessionOut,
    UserOut,
)
from app.auth import mfa, service
from app.auth.cookies import clear_session_cookies, set_session_cookies
from app.auth.deps import AuthContext, client_ip, get_optional_auth, require_auth, require_csrf
from app.auth.passwords import hash_password, verify_password
from app.core.app_settings import MfaPolicy, SettingsService
from app.core.audit import record_audit
from app.db.models import OIDC_CONFIG_ID, AuthSession, OidcConfig, Role, User
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


def _complete_login(
    db: Session, user: User, request: Request, response: Response, *, action: str
) -> LoginOut:
    """Create a session for ``user``, set cookies, audit, and build the response."""
    token, session = service.create_session(
        db, user, ip=client_ip(request), user_agent=request.headers.get("user-agent")
    )
    user.last_login_at = session.created_at
    record_audit(db, action=action, actor=user, ip=client_ip(request))
    db.commit()
    set_session_cookies(response, token, session.csrf_token)
    return LoginOut(user=UserOut.model_validate(user), csrf_token=session.csrf_token)


@router.get("/status", response_model=AuthStatusOut)
def auth_status(
    db: Session = Depends(get_db),
    auth: AuthContext | None = Depends(get_optional_auth),
) -> AuthStatusOut:
    """Report bootstrap and login state for the SPA (public)."""
    oidc = db.get(OidcConfig, OIDC_CONFIG_ID)
    return AuthStatusOut(
        needs_setup=service.count_users(db) == 0,
        authenticated=auth is not None,
        user=UserOut.model_validate(auth.user) if auth else None,
        oidc=OidcStatusOut(
            enabled=bool(oidc and oidc.enabled),
            display_name=oidc.display_name if oidc else "OIDC",
        ),
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
    db.flush()
    record_audit(
        db, action="auth.setup", actor=user, ip=ip, target_type="user", target_id=str(user.id)
    )
    logger.info("First admin account created: %s", user.username)
    return _complete_login(db, user, request, response, action="auth.login")


@router.post("/login", response_model=LoginOut)
def login(
    payload: CredentialsIn,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> LoginOut:
    """Authenticate with username + password and start a session.

    When local login is disabled by policy, password auth is refused (OIDC only).
    When the account has MFA enabled, a challenge is returned instead of a
    session and the caller must complete it via ``/auth/mfa/verify``.
    """
    _enforce_rate_limit(request)
    ip = client_ip(request)

    if not SettingsService(db).auth().local_login_enabled:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, detail="Local login is disabled on this instance."
        )

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

    if user.mfa_enabled:
        challenge = request.app.state.pending_mfa.issue(user.id, mfa.PURPOSE_VERIFY)
        record_audit(db, action="auth.mfa_challenge", actor=user, ip=ip)
        db.commit()
        return LoginOut(mfa_required=True, mfa_token=challenge)

    policy = SettingsService(db).auth().mfa_policy
    if _mfa_required_for(user.role, policy):
        # Mandatory MFA for this role, but the account never enrolled: force
        # enrollment before granting access rather than minting a full session.
        # Reuse any pending secret so repeated logins show the same key; the
        # login only completes once a code is verified (see verify_mfa).
        if user.mfa_secret_ciphertext:
            secret = mfa.decrypt_mfa_secret(user.mfa_secret_ciphertext)
        else:
            secret = mfa.generate_secret()
            user.mfa_secret_ciphertext = mfa.encrypt_mfa_secret(secret)
            user.mfa_enabled = False
        challenge = request.app.state.pending_mfa.issue(user.id, mfa.PURPOSE_ENROLL)
        record_audit(db, action="auth.mfa_enrollment_required", actor=user, ip=ip)
        db.commit()
        instance = SettingsService(db).general().instance_name
        return LoginOut(
            mfa_required=True,
            enrollment_required=True,
            mfa_token=challenge,
            mfa_secret=secret,
            otpauth_uri=mfa.provisioning_uri(secret, username=user.username, issuer=instance),
        )

    return _complete_login(db, user, request, response, action="auth.login")


@router.post("/mfa/verify", response_model=LoginOut)
def verify_mfa(
    payload: MfaVerifyIn,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> LoginOut:
    """Complete a password login by submitting the TOTP code (second step).

    Handles both a normal ``verify`` challenge (existing enrolled account) and an
    ``enroll`` challenge (policy-forced first enrollment): the latter activates
    MFA once the code proves the newly-issued secret, then completes the login.
    """
    _enforce_rate_limit(request)
    ip = client_ip(request)
    resolved = request.app.state.pending_mfa.consume(payload.mfa_token)
    if resolved is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="MFA challenge is invalid.")
    user_id, purpose = resolved
    user = db.get(User, user_id)
    if user is None or not user.is_active or not user.mfa_secret_ciphertext:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="MFA challenge is invalid.")
    # A verify challenge requires an already-active second factor; an enroll
    # challenge is what turns it on.
    if purpose == mfa.PURPOSE_VERIFY and not user.mfa_enabled:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="MFA challenge is invalid.")

    if not mfa.verify_code(mfa.decrypt_mfa_secret(user.mfa_secret_ciphertext), payload.code):
        record_audit(db, action="auth.mfa_failed", actor=user, ip=ip)
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication code.")

    if purpose == mfa.PURPOSE_ENROLL and not user.mfa_enabled:
        user.mfa_enabled = True
        record_audit(db, action="auth.mfa_enabled", actor=user, ip=ip)
        db.commit()

    return _complete_login(db, user, request, response, action="auth.login")


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
def logout(
    request: Request,
    response: Response,
    auth: AuthContext = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> None:
    """Revoke the current session and clear cookies."""
    # Bearer-token callers reach here with no session; there is nothing to revoke.
    if auth.session is not None:
        service.revoke_session(auth.session)
    record_audit(db, action="auth.logout", actor=auth.user, ip=client_ip(request))
    db.commit()
    clear_session_cookies(response)


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
    except_id = auth.session.id if auth.session is not None else None
    revoked = service.revoke_all_sessions(db, auth.user, except_session_id=except_id)
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
    current_session_id = auth.session.id if auth.session is not None else None
    out = []
    for row in rows:
        if not row.is_valid:
            continue
        view = SessionOut.model_validate(row)
        view.current = row.id == current_session_id
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


def _mfa_required_for(role: Role, policy: MfaPolicy) -> bool:
    """Return True when policy mandates MFA for a user of ``role``."""
    if policy is MfaPolicy.REQUIRED_ALL:
        return True
    if policy is MfaPolicy.REQUIRED_ADMIN:
        return role is Role.ADMIN
    return False


@router.post("/mfa/enroll", response_model=MfaEnrollOut)
def enroll_mfa(
    payload: MfaEnrollIn,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> MfaEnrollOut:
    """Begin TOTP enrollment: generate a secret and return its provisioning URI.

    The secret is stored (encrypted) but MFA is not active until a code is
    confirmed via ``/auth/mfa/activate``; re-enrolling replaces any pending or
    active secret.

    Starting re-enrollment deactivates a currently-active second factor, so — like
    disabling MFA — it requires re-authenticating with the current password. This
    stops a session alone (without the password) from stripping MFA.
    """
    if auth.user.mfa_enabled:
        if not payload.current_password or not verify_password(
            auth.user.password_hash, payload.current_password
        ):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail="Re-enrolling MFA requires your current password.",
            )
    secret = mfa.generate_secret()
    auth.user.mfa_secret_ciphertext = mfa.encrypt_mfa_secret(secret)
    auth.user.mfa_enabled = False
    db.commit()
    instance = SettingsService(db).general().instance_name
    return MfaEnrollOut(
        secret=secret,
        otpauth_uri=mfa.provisioning_uri(secret, username=auth.user.username, issuer=instance),
    )


@router.post("/mfa/activate", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
def activate_mfa(
    payload: MfaActivateIn,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> None:
    """Confirm enrollment by proving a code, activating MFA for the account."""
    if not auth.user.mfa_secret_ciphertext:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Start enrollment first.")
    if not mfa.verify_code(mfa.decrypt_mfa_secret(auth.user.mfa_secret_ciphertext), payload.code):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid authentication code.")
    auth.user.mfa_enabled = True
    record_audit(db, action="auth.mfa_enabled", actor=auth.user, ip=client_ip(request))
    db.commit()
    logger.info("MFA activated for user %s", auth.user.username)


@router.post("/mfa/disable", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
def disable_mfa(
    payload: MfaDisableIn,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> None:
    """Disable MFA after re-authenticating with the current password.

    Refused when the instance policy mandates MFA for the caller's role, so a
    user cannot opt out of a required control.
    """
    if not verify_password(auth.user.password_hash, payload.password):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Password is incorrect.")
    policy = SettingsService(db).auth().mfa_policy
    if _mfa_required_for(auth.user.role, policy):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="MFA is required for your role and cannot be disabled.",
        )
    auth.user.mfa_enabled = False
    auth.user.mfa_secret_ciphertext = None
    record_audit(db, action="auth.mfa_disabled", actor=auth.user, ip=client_ip(request))
    db.commit()
