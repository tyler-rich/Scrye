"""Session/CSRF cookie helpers shared by the login, OIDC, and MFA flows.

Centralizing cookie attributes keeps every sign-in path (local password, OIDC
callback, MFA completion) setting identical ``HttpOnly``/``Secure``/``SameSite``
flags, so a new entry point can't accidentally weaken the cookie posture.

This module also owns the **HTTPS-enforcement guard** that the sign-in endpoints
apply before minting a session. When ``SCRYE_SESSION_COOKIE_SECURE`` is on (the
default) and the request did not reach Scrye over HTTPS, a browser will silently
discard the ``Secure`` cookies this module sets: the login response looks like a
success, nothing is stored, and every request afterwards is unauthenticated. That
failure is invisible from both ends, so the endpoints refuse the sign-in and say
why instead of appearing to work — see :func:`session_cookie_would_be_dropped`.
"""

from __future__ import annotations

from fastapi import Request, Response

from app.auth import service
from app.core.config import get_settings
from app.core.forwarded import request_is_secure

#: Operator-facing explanation returned to the client (and echoed on the login
#: screen) when HTTPS enforcement blocks a sign-in. It describes the **transport
#: only** and is byte-for-byte identical whether or not the submitted credentials
#: were correct, so it can never be used to probe for valid accounts.
HTTPS_REQUIRED_DETAIL = (
    "Sign-in is unavailable over plain HTTP. This server marks its session cookie "
    "Secure, and browsers refuse to store a Secure cookie on an http:// page, so a "
    "login could never take effect. This is a transport/configuration problem, not "
    "a problem with the credentials you entered. Fix it in one of three ways: reach "
    "Scrye over https://; or, if a reverse proxy terminates TLS, have it send "
    "X-Forwarded-Proto: https and set SCRYE_FORWARDED_ALLOW_IPS to the address the "
    "proxy connects from; or, for a deliberate plain-HTTP deployment, set "
    "SCRYE_SESSION_COOKIE_SECURE=false and restart (the session cookie then travels "
    "unencrypted)."
)


def https_enforcement_enabled() -> bool:
    """Return True when session cookies are marked ``Secure`` (HTTPS enforced)."""
    return get_settings().session_cookie_secure


def session_cookie_would_be_dropped(request: Request) -> bool:
    """Return True when this request cannot receive a usable session cookie.

    True exactly when HTTPS enforcement is on and ``request`` did not arrive over
    HTTPS — where "over HTTPS" means real TLS at this process **or** an
    ``X-Forwarded-Proto: https`` from a peer listed in
    ``SCRYE_FORWARDED_ALLOW_IPS`` (never from an arbitrary client; see
    :mod:`app.core.forwarded`).

    The scheme is deliberately **not** used to weaken the cookie: dropping
    ``Secure`` because the app happens to see HTTP would silently downgrade every
    deployment behind a TLS-terminating proxy. It is used only to detect, and
    then explain, a sign-in that cannot succeed.
    """
    return https_enforcement_enabled() and not request_is_secure(request)


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
