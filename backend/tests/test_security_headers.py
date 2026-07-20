"""Tests for the baseline security-header middleware.

Verifies that every response carries the clickjacking / MIME-sniffing /
referrer headers and a SPA-appropriate Content-Security-Policy, and that the
interactive API-docs UIs are exempted from the CSP (they need inline scripts +
CDN assets a SPA CSP would break).
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.security_headers import CONTENT_SECURITY_POLICY, REFERRER_POLICY


def test_baseline_headers_present(client: TestClient) -> None:
    """A normal API response carries all baseline security headers."""
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Referrer-Policy"] == REFERRER_POLICY
    assert response.headers["Content-Security-Policy"] == CONTENT_SECURITY_POLICY


def test_csp_is_spa_appropriate(client: TestClient) -> None:
    """The CSP locks scripts to self while permitting Mantine's inline styles."""
    csp = client.get("/healthz").headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "object-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    # Scripts must NOT allow inline execution (the XSS containment).
    assert "script-src 'self'" in csp
    assert "script-src 'self' 'unsafe-inline'" not in csp
    # Styles must allow inline (Mantine injects theme CSS at runtime).
    assert "style-src 'self' 'unsafe-inline'" in csp


def test_headers_present_on_error_response(client: TestClient) -> None:
    """Headers are attached even to error (non-2xx) responses."""
    response = client.get("/api/scans/does-not-exist")
    assert response.status_code >= 400
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Content-Security-Policy"] == CONTENT_SECURITY_POLICY


def test_docs_ui_exempted_from_csp(client: TestClient) -> None:
    """The Swagger UI keeps the other headers but is exempt from the CSP."""
    response = client.get("/docs")
    assert response.status_code == 200
    assert "Content-Security-Policy" not in response.headers
    # The non-CSP headers still apply everywhere.
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
