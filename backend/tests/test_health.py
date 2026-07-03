"""Tests for the /healthz endpoint."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app import __version__


def test_healthz_reports_healthy(client: TestClient) -> None:
    """A reachable database yields a healthy status with version + db ok."""
    response = client.get("/healthz")
    assert response.status_code == 200

    body = response.json()
    assert body["status"] == "healthy"
    assert body["database"] == "ok"
    assert body["version"] == __version__


def test_healthz_does_not_leak_config(client: TestClient) -> None:
    """The health payload exposes only status/version/database keys."""
    body = client.get("/healthz").json()
    assert set(body.keys()) == {"status", "version", "database"}
