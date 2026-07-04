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
    forwarded_allow_ips: str = Field(
        default="172.16.0.0/12",
        description=(
            "Trusted upstream hops for uvicorn --forwarded-allow-ips (consumed by "
            "docker/entrypoint.sh). Only X-Forwarded-* from these addresses is "
            "honored, so the real client IP drives the auth rate limiter and audit "
            "log. Default trusts the Docker bridge range Caddy connects from; set "
            "it to the reverse proxy's exact IP/CIDR for other topologies. Never "
            "set it to '*' — that lets any client spoof X-Forwarded-For."
        ),
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

    # --- Scanning ----------------------------------------------------------
    trivy_binary: str = Field(
        default="trivy",
        description="Path or name of the Trivy binary (resolved on PATH if a bare name).",
    )
    grype_binary: str = Field(
        default="grype",
        description="Path or name of the Grype binary (resolved on PATH if a bare name).",
    )
    syft_binary: str = Field(
        default="syft",
        description="Path or name of the Syft binary (resolved on PATH if a bare name).",
    )
    max_concurrent_scans: int = Field(
        default=2,
        description="Maximum number of scans the in-process worker runs concurrently.",
    )
    scan_timeout_seconds: int = Field(
        default=1800,
        description="Per-scan wall-clock timeout in seconds (default 1800 = 30 minutes).",
    )
    scanner_cache_dir: Path = Field(
        default=Path("/cache"),
        description=(
            "Writable directory (a persistent volume) for scanner vulnerability "
            "databases and scratch space. Under the hardened runtime the "
            "container runs as a non-root uid on a read-only root filesystem, so "
            "a scanner's default cache ($HOME/.cache) is unwritable and the small "
            "tmpfs /tmp cannot hold a vulnerability DB; Trivy/Grype/Syft are "
            "pointed here for their cache dir and TMPDIR instead."
        ),
    )
    artifacts_dir: Path = Field(
        default=Path("/data/artifacts"),
        description="Directory holding raw scanner artifacts (JSON output, SBOMs).",
    )
    backups_dir: Path = Field(
        default=Path("/data/backups"),
        description="Directory holding backup bundles (manual and scheduled).",
    )
    filesystem_scan_roots: list[str] = Field(
        default_factory=list,
        description=(
            "Comma-separated absolute paths under which filesystem (Grype 'dir:') "
            "scans are allowed. Empty disables filesystem scanning so arbitrary "
            "host paths (e.g. the database or secret files) can never be read."
        ),
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
