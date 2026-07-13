"""Tests for the unified 422 error-body envelope (APIR-2).

FastAPI's default ``RequestValidationError`` body carries a *list* in ``detail``
while hand-raised ``HTTPException(422, ...)`` carries a *string*; the SPA only
renders the string shape. ``main._flatten_validation_error`` normalizes schema
failures to that string shape so validation errors surface with their reason.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.test_auth import CSRF, setup_admin


class TestValidationEnvelope:
    def test_schema_error_detail_is_a_string(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        # vuln_id exceeds max_length=128 → Pydantic RequestValidationError.
        resp = client.post(
            "/api/trivy/ignore-rules",
            json={"vuln_id": "C" * 200},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 422
        detail = resp.json()["detail"]
        assert isinstance(detail, str)
        # The offending field is named so the UI can point at it.
        assert "vuln_id" in detail

    def test_hand_raised_422_still_a_string(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        # Invalid VEX JSON is rejected via HTTPException(422, detail="<string>").
        resp = client.post(
            "/api/trivy/vex-documents",
            json={"name": "bad", "format": "openvex", "content": "not json{"},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 422
        assert isinstance(resp.json()["detail"], str)
