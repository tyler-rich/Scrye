"""Shared pytest fixtures and test-time configuration.

Environment is prepared **before** the application (and its module-level
engine) is imported: an isolated SQLite path, a generated throwaway master-key
file (never a real key), and non-Secure cookies so the plain-HTTP test client
can round-trip them.
"""

from __future__ import annotations

import base64
import os
import tempfile
from collections.abc import Iterator
from pathlib import Path

# Must be set before importing app modules that read settings at import time.
_TMP = Path(tempfile.mkdtemp(prefix="scrye-tests-"))
_KEY_FILE = _TMP / "app_secret_key"
_KEY_FILE.write_bytes(base64.b64encode(os.urandom(48)))

os.environ.setdefault("SCRYE_DATABASE_PATH", str(_TMP / "scrye_pytest.db"))
os.environ.setdefault("SCRYE_ENVIRONMENT", "development")
os.environ.setdefault("SCRYE_APP_SECRET_KEY_FILE", str(_KEY_FILE))
os.environ.setdefault("SCRYE_SESSION_COOKIE_SECURE", "false")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.db.base import Base  # noqa: E402
from app.db.session import SessionLocal, engine  # noqa: E402
from app.main import create_app  # noqa: E402


@pytest.fixture
def db() -> Iterator[Session]:
    """Yield a session against a freshly reset schema."""
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client() -> Iterator[TestClient]:
    """Yield a test client with a fresh app instance and a clean database."""
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    app = create_app()
    with TestClient(app) as test_client:
        yield test_client
