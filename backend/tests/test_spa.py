"""Tests for serving the built SPA from FastAPI.

Verifies the catch-all fallback so client-side routing works, and that API
paths are not shadowed by the SPA handler. Skips when no frontend build exists
(e.g. backend-only CI lanes).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app

_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"


@pytest.fixture
def spa_client() -> TestClient:
    """Return a client configured to serve the real built SPA."""
    settings = Settings(frontend_dist_dir=_DIST)
    return TestClient(create_app(settings))


@pytest.mark.skipif(not (_DIST / "index.html").is_file(), reason="frontend not built")
def test_root_serves_spa(spa_client: TestClient) -> None:
    """GET / returns the SPA shell."""
    response = spa_client.get("/")
    assert response.status_code == 200
    assert '<div id="root">' in response.text


@pytest.mark.skipif(not (_DIST / "index.html").is_file(), reason="frontend not built")
def test_deep_link_falls_back_to_spa(spa_client: TestClient) -> None:
    """An unknown GET route returns index.html so client routing works."""
    response = spa_client.get("/history")
    assert response.status_code == 200
    assert '<div id="root">' in response.text


@pytest.mark.skipif(not (_DIST / "index.html").is_file(), reason="frontend not built")
def test_api_paths_not_shadowed_by_spa(spa_client: TestClient) -> None:
    """Health endpoint still returns JSON even when the SPA is mounted."""
    response = spa_client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] in {"healthy", "degraded"}
