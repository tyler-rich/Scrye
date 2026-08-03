"""Fresh full re-authentication gate for identity-changing operations.

Some operations do not merely *use* an account's existing privileges — they
change **how the account can be authenticated in the future**. Binding an OIDC
identity creates a whole new login path; removing one takes a login path away.
For those, holding a live session (even with its CSRF token) is deliberately not
enough: the caller must prove the credentials themselves, right now.

"Fresh full" means every factor the account actually has:

- the current password, always; and
- a current TOTP code whenever the account has MFA active.

This is the same posture as the MFA re-enroll gate (``/auth/mfa/enroll``
requires the current password whenever a secret exists — docs/ARCHIVE.md §14,
2026-07-04), extended with the second factor because the operation it guards
creates a login path on which that second factor will not be challenged.

**Why this matters for OIDC linking (L2/SEC-8).** Mandatory-MFA policies are
enforced on the local login path only; OIDC delegates the second factor to the
identity provider. Linking therefore widens that accepted limitation from
OIDC-provisioned accounts (which carry no usable local password and no local
TOTP, so there is nothing to bypass) to *any* linked account, including an
MFA-enrolled admin. This gate is the compensating control: a stolen session
alone can never create a new login path for the account, because minting one
costs the attacker the password and the second factor as well.
"""

from __future__ import annotations

import logging

from fastapi import HTTPException, Request, status
from sqlalchemy.orm import Session

from app.auth import mfa
from app.auth.passwords import verify_password
from app.core.audit import record_audit
from app.db.models import User

logger = logging.getLogger(__name__)

#: Audit action recorded when a fresh-re-auth gate rejects a caller. Distinct
#: from ``auth.login_failed`` so an operator can see attempts to change an
#: account's login paths from an already-authenticated session.
AUDIT_REAUTH_FAILED = "auth.reauth_failed"


def enforce_auth_rate_limit(request: Request) -> None:
    """Apply the per-IP auth rate limit (429 with ``Retry-After`` when exceeded).

    Shared by the password-login endpoints and by every fresh-re-auth gate, so a
    session-holding attacker cannot brute-force a password (or a TOTP code) any
    faster through the re-auth surface than through ``/auth/login``.
    """
    allowed, retry_after = request.app.state.auth_limiter.allow(
        request.client.host if request.client else "unknown"
    )
    if not allowed:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many authentication attempts; try again shortly.",
            headers={"Retry-After": str(max(int(retry_after) + 1, 1))},
        )


def require_fresh_auth(
    db: Session,
    user: User,
    *,
    password: str,
    totp_code: str | None,
    ip: str,
    operation: str,
) -> None:
    """Re-verify ``user``'s credentials in full, or raise ``403``.

    Args:
        db: Active database session (an audit row is added on failure; the
            caller's exception handling rolls back nothing else).
        user: The authenticated account being re-verified.
        password: The password submitted with this request.
        totp_code: The TOTP code submitted with this request, if any.
        ip: Client IP for the audit record.
        operation: Short operation name for the audit record (e.g.
            ``"oidc_link"``), so failures are attributable.

    Raises:
        HTTPException: ``403`` when the password is wrong or missing, or when
            MFA is active and the code is wrong or missing. The two are reported
            separately — this caller is already authenticated as the account, so
            distinguishing "wrong password" from "wrong code" discloses nothing
            they do not already know, and a merged message makes a legitimate
            user's failure needlessly hard to act on.
    """
    if not password or not verify_password(user.password_hash, password):
        _audit_reauth_failure(db, user, ip=ip, operation=operation, reason="password")
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail="Your current password is required and did not match.",
        )

    if user.mfa_enabled and user.mfa_secret_ciphertext:
        if not totp_code or not mfa.verify_code(
            mfa.decrypt_mfa_secret(user.mfa_secret_ciphertext, user_id=user.id), totp_code
        ):
            _audit_reauth_failure(db, user, ip=ip, operation=operation, reason="totp")
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail="A current authentication code from your authenticator app is required.",
            )


def _audit_reauth_failure(db: Session, user: User, *, ip: str, operation: str, reason: str) -> None:
    """Record (and commit) a failed re-authentication attempt."""
    logger.warning(
        "Fresh re-authentication failed for user %s on operation %r (%s factor).",
        user.id,
        operation,
        reason,
    )
    record_audit(
        db,
        action=AUDIT_REAUTH_FAILED,
        actor=user,
        ip=ip,
        details={"operation": operation, "factor": reason},
    )
    db.commit()
