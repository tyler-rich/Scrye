"""Session/CSRF cookie helpers shared by the login, OIDC, and MFA flows.

Centralizing cookie attributes keeps every sign-in path (local password, OIDC
callback, MFA completion) setting identical ``HttpOnly``/``Secure``/``SameSite``
flags, so a new entry point can't accidentally weaken the cookie posture.
"""

from __future__ import annotations

from fastapi import Response

from app.auth import service
from app.core.config import get_settings


def set_session_cookies(response: Response, token: str, csrf_token: str) -> None:
    """Attach the session (HttpOnly) and CSRF (readable) cookies to ``response``."""
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


def clear_session_cookies(response: Response) -> None:
    """Expire both auth cookies on ``response``."""
    response.delete_cookie(service.SESSION_COOKIE, path="/")
    response.delete_cookie(service.CSRF_COOKIE, path="/")
