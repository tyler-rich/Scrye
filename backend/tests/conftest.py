"""Shared pytest fixtures and test-time configuration.

An isolated SQLite database path is configured **before** the application (and
its module-level engine) is imported, so tests never touch a real data volume.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator
from pathlib import Path

# Must be set before importing app modules that build the engine at import time.
_TEST_DB = Path(tempfile.gettempdir()) / "scrye_pytest.db"
os.environ.setdefault("SCRYE_DATABASE_PATH", str(_TEST_DB))
os.environ.setdefault("SCRYE_ENVIRONMENT", "development")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import create_app  # noqa: E402


@pytest.fixture
def client() -> Iterator[TestClient]:
    """Yield a FastAPI test client backed by the isolated test database."""
    app = create_app()
    with TestClient(app) as test_client:
        yield test_client
