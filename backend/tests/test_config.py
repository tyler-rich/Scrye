"""Tests for the Settings model and .env.example generation."""

from __future__ import annotations

from pathlib import Path

from app.core.config import Settings
from scripts.gen_env_example import render_env_example


def test_database_url_derived_from_path() -> None:
    """database_url is derived from the configured SQLite path."""
    settings = Settings(database_path=Path("/data/scrye.db"))
    assert settings.database_url == "sqlite:////data/scrye.db"


def test_master_key_default_is_a_secret_file_path() -> None:
    """The master key is referenced by file path, never an inline value."""
    # Read the field default directly: the test env overrides the env var.
    default = Settings.model_fields["app_secret_key_file"].default
    assert default == Path("/run/secrets/app_secret_key")


def test_env_example_excludes_master_key() -> None:
    """Generated .env.example must never include the master key content var."""
    rendered = render_env_example()
    assert "SCRYE_APP_SECRET_KEY_FILE" in rendered
    # The key itself is read from the secret file; there is no value var for it.
    assert "SCRYE_APP_SECRET_KEY=" not in rendered


def test_env_example_documents_non_sensitive_vars() -> None:
    """Generated .env.example surfaces the key non-sensitive settings."""
    rendered = render_env_example()
    for var in ("SCRYE_PORT", "SCRYE_DATABASE_PATH", "SCRYE_LOG_LEVEL"):
        assert var in rendered
