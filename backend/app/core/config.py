"""Application configuration.

This module is the **single source of truth** for runtime configuration. The
repository's ``.env.example`` is generated from the :class:`Settings` model
(see ``scripts/gen_env_example.py``) — keep the two in sync.

Security notes:
- This model holds **non-sensitive** configuration only. The application master
  key is **never** an env var; it is read at runtime from the Docker secret file
  pointed to by ``APP_SECRET_KEY_FILE``. Only the *path* lives here.
- Stored credentials/secrets (registry creds, git tokens, OIDC client secret,
  API tokens) are field-encrypted and are not configured here.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Typed application settings, loaded from environment variables / ``.env``.

    Every field documented here should appear (non-sensitive ones only) in the
    generated ``.env.example``.
    """

    model_config = SettingsConfigDict(
        env_prefix="SCRYE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- General -----------------------------------------------------------
    app_name: str = Field(
        default="Scrye",
        description="Human-readable application name shown in the UI and logs.",
    )
    environment: str = Field(
        default="production",
        description="Deployment environment: 'development' or 'production'.",
    )
    log_level: str = Field(
        default="INFO",
        description="Root log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).",
    )

    # --- HTTP server -------------------------------------------------------
    host: str = Field(
        default="0.0.0.0",  # noqa: S104 — bound to loopback by the proxy/compose layer.
        description="Bind address for the API server inside the container.",
    )
    port: int = Field(
        default=8089,
        description="Port the API server listens on inside the container.",
    )
    cors_origins: list[str] = Field(
        default_factory=list,
        description=(
            "Comma-separated list of allowed CORS origins for the dev frontend "
            "(e.g. http://localhost:5173). Empty in production (same-origin SPA)."
        ),
    )

    # --- Database ----------------------------------------------------------
    database_path: Path = Field(
        default=Path("/data/scrye.db"),
        description="Filesystem path to the SQLite database file.",
    )

    # --- Master key (path only; the key itself is read from the file) ------
    app_secret_key_file: Path = Field(
        default=Path("/run/secrets/app_secret_key"),
        description=(
            "Path to the Docker secret file holding the application master key. "
            "The key content is NEVER set via an environment variable."
        ),
    )

    # --- Auth & sessions ----------------------------------------------------
    session_lifetime_hours: int = Field(
        default=168,
        description="Login session lifetime in hours (default 168 = 7 days).",
    )
    session_cookie_secure: bool = Field(
        default=True,
        description=(
            "Set the Secure flag on session cookies. Keep true in production "
            "(behind TLS-terminating Caddy); set false only for plain-HTTP local dev."
        ),
    )
    auth_rate_limit_attempts: int = Field(
        default=5,
        description="Max authentication attempts allowed per client IP per window.",
    )
    auth_rate_limit_window_seconds: int = Field(
        default=60,
        description="Length of the auth rate-limit window in seconds.",
    )

    # --- Optional sidecars -------------------------------------------------
    trivy_server_url: str | None = Field(
        default=None,
        description="Optional Trivy server URL for a shared vuln-DB cache.",
    )
    docker_proxy_url: str | None = Field(
        default=None,
        description="Optional read-only docker-socket-proxy URL ('scan running images').",
    )

    # --- Frontend ----------------------------------------------------------
    frontend_dist_dir: Path = Field(
        default=Path("/app/frontend/dist"),
        description="Directory containing the built React SPA served by FastAPI.",
    )

    @property
    def database_url(self) -> str:
        """Return the SQLAlchemy database URL for the configured SQLite file."""
        return f"sqlite:///{self.database_path}"

    @property
    def is_development(self) -> bool:
        """Return True when running in a development environment."""
        return self.environment.lower() in {"development", "dev", "local"}


@lru_cache
def get_settings() -> Settings:
    """Return a cached :class:`Settings` instance."""
    return Settings()
