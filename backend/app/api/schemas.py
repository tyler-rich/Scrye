"""Shared API schemas for auth and user management.

Read models never expose password hashes or any secret material.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.db.models import Role

#: Validation bounds for local credentials.
USERNAME_PATTERN = r"^[a-zA-Z0-9._-]+$"
PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 128


class UserOut(BaseModel):
    """Public view of a user account (no credential material)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: Role
    is_active: bool
    mfa_enabled: bool
    created_at: datetime
    last_login_at: datetime | None


class CredentialsIn(BaseModel):
    """Username + password payload for login."""

    username: str = Field(min_length=3, max_length=64, pattern=USERNAME_PATTERN)
    password: str = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)


class NewUserIn(BaseModel):
    """Payload for creating an account (setup or admin user management)."""

    username: str = Field(min_length=3, max_length=64, pattern=USERNAME_PATTERN)
    password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)


class OidcStatusOut(BaseModel):
    """Public OIDC availability info for the login screen."""

    enabled: bool
    display_name: str


class AuthStatusOut(BaseModel):
    """Public bootstrap/auth state used by the SPA on load."""

    needs_setup: bool
    authenticated: bool
    user: UserOut | None
    oidc: OidcStatusOut


class LoginOut(BaseModel):
    """Login/setup response.

    On a completed login, ``user`` and ``csrf_token`` are set. When the account
    has MFA enabled, the first step instead returns ``mfa_required=True`` plus a
    short-lived ``mfa_token`` to submit with the TOTP code.

    When a mandatory-MFA policy applies to the role but the account has not yet
    enrolled, the response additionally sets ``enrollment_required=True`` and
    carries the one-time enrollment material (``mfa_secret`` + ``otpauth_uri``):
    the caller scans it and submits a code to the same ``/auth/mfa/verify`` step,
    which activates MFA and completes the login. Access is not granted until then.
    """

    user: UserOut | None = None
    csrf_token: str | None = None
    mfa_required: bool = False
    mfa_token: str | None = None
    enrollment_required: bool = False
    mfa_secret: str | None = None
    otpauth_uri: str | None = None


class MfaVerifyIn(BaseModel):
    """Second-step login payload: the challenge token plus the TOTP code."""

    mfa_token: str = Field(min_length=1, max_length=128)
    code: str = Field(min_length=6, max_length=10)


class MfaEnrollIn(BaseModel):
    """Begin authenticated MFA (re-)enrollment.

    ``current_password`` is required only when the account already has MFA active,
    because starting re-enrollment deactivates it — the same password re-auth that
    disabling MFA requires, so a session alone cannot strip the second factor.
    """

    current_password: str | None = Field(default=None, max_length=PASSWORD_MAX_LENGTH)


class MfaEnrollOut(BaseModel):
    """One-time enrollment material for setting up an authenticator app."""

    secret: str
    otpauth_uri: str


class MfaActivateIn(BaseModel):
    """Confirm MFA enrollment by proving a code from the new secret."""

    code: str = Field(min_length=6, max_length=10)


class MfaDisableIn(BaseModel):
    """Disable MFA, re-authenticating with the current password."""

    password: str = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)


class SessionOut(BaseModel):
    """One of the caller's login sessions."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    ip: str | None
    user_agent: str | None
    current: bool = False


class PasswordChangeIn(BaseModel):
    """Change-own-password payload."""

    current_password: str = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)
    new_password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)
