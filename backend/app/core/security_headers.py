"""Baseline security-header response middleware (SEC / account-takeover chain).

Adds a defence-in-depth set of response headers to every response:

* **Content-Security-Policy** — the primary XSS containment. Tuned for the built
  Mantine SPA, which loads its JS as a single same-origin module bundle and its
  CSS as a same-origin stylesheet, but injects theme CSS at runtime through an
  inline ``<style>`` element and inline ``style=`` attributes. Scripts are
  therefore locked to ``'self'`` (no ``'unsafe-inline'``), while styles must
  allow ``'unsafe-inline'``. The SPA only ever talks to its own origin
  (``/api``), so ``connect-src`` stays ``'self'``.
* **X-Frame-Options: DENY** / ``frame-ancestors 'none'`` — clickjacking defence.
* **X-Content-Type-Options: nosniff** — stop MIME sniffing.
* **Referrer-Policy** — trim referrer leakage to cross-origin destinations.

The interactive API docs (Swagger UI / ReDoc) are deliberately exempted from the
CSP: they load their assets from a CDN and run an inline bootstrap script, which
a SPA-appropriate CSP would break. They still receive every other header.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

# A single-line CSP appropriate for the built Mantine SPA. See the module
# docstring for why styles allow 'unsafe-inline' but scripts do not.
CONTENT_SECURITY_POLICY = "; ".join(
    (
        "default-src 'self'",
        "base-uri 'self'",
        "object-src 'none'",
        "frame-ancestors 'none'",
        "form-action 'self'",
        "img-src 'self' data:",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline'",
        "font-src 'self'",
        "connect-src 'self'",
    )
)

REFERRER_POLICY = "strict-origin-when-cross-origin"

# Documentation UIs (Swagger UI, ReDoc) need inline scripts + CDN assets, which
# the SPA CSP forbids; skip the CSP header on these paths only.
_CSP_EXEMPT_PREFIXES = ("/docs", "/redoc")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach baseline security headers to every response."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Set the security headers on the downstream response."""
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = REFERRER_POLICY
        if not request.url.path.startswith(_CSP_EXEMPT_PREFIXES):
            response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
        return response
