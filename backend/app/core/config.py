"""Application configuration.

This module is the **single source of truth** for runtime configuration. The
repository's ``.env.example`` is generated from the :class:`Settings` model
(see ``scripts/gen_env_example.py``) — keep the two in sync.

Security notes:
- This model holds **non-sensitive** configuration only. The application master
  key is **never** an env var; it is read at runtime from the Docker secret file
  pointed to by ``APP_SECRET_KEY_FILE``, or from the auto-generated key file at
  ``APP_SECRET_KEY_AUTOGEN_FILE`` when no secret is supplied. Only the *paths*
  live here.
- Stored credentials/secrets (registry creds, git tokens, OIDC client secret,
  API tokens) are field-encrypted and are not configured here.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from app.core.forwarded import TrustedProxies, parse_trusted_proxies


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
            "REQUIRED per-deployment: the IP/CIDR your reverse proxy actually "
            "connects to Scrye from (uvicorn --forwarded-allow-ips, consumed by "
            "docker/entrypoint.sh). Only X-Forwarded-For and X-Forwarded-Proto "
            "from these addresses are trusted, so the real client IP drives the "
            "auth rate limiter and audit log, and a TLS-terminating proxy's "
            "X-Forwarded-Proto: https satisfies the HTTPS check that guards the "
            "Secure session cookie. Works with any proxy that sets them (Caddy, nginx, "
            "Traefik, ...) — the logic is proxy-agnostic; only this value is "
            "deployment-specific. The default 172.16.0.0/12 assumes Caddy as a "
            "Docker container on the default bridge network; set it to your proxy's "
            "real source, e.g. 127.0.0.1 for a host-networked nginx, or the proxy's "
            "Docker subnet for Traefik. If it does NOT match the connecting peer, "
            "the app FAILS SAFE (X-Forwarded-For is ignored and the raw proxy IP is "
            "used — no spoofing, but per-client IPs won't take effect). Never set it "
            "to '*': that trusts every hop and lets any client spoof "
            "X-Forwarded-For. Do not include the client LAN range."
        ),
    )
    cors_origins: Annotated[list[str], NoDecode] = Field(
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

    # --- Master key (paths only; the key itself is read from the file) -----
    app_secret_key_file: Path = Field(
        default=Path("/run/secrets/app_secret_key"),
        description=(
            "Path to the Docker secret file holding the application master key. "
            "The key content is NEVER set via an environment variable. This is the "
            "highest-precedence key source; when it holds a key file, that key is "
            "used and no key is ever generated. Setting this variable explicitly "
            "asserts the key lives there: if the file is then missing, Scrye "
            "REFUSES to start rather than quietly generate a different key (which "
            "would orphan every stored secret). Leave it unset to fall back to "
            "SCRYE_APP_SECRET_KEY_AUTOGEN_FILE."
        ),
    )
    app_secret_key_autogenerate: bool = Field(
        default=True,
        description=(
            "Generate a master key on first launch when no key file exists at "
            "either master-key path, so a fresh deployment starts without "
            "pre-seeding a secret. An existing key file is ALWAYS used and never "
            "overwritten; a key file that exists but cannot be loaded fails "
            "startup instead of being regenerated. Set false to require an "
            "operator-provided key (startup then fails when none is found)."
        ),
    )
    app_secret_key_autogen_file: Path = Field(
        default=Path("/data/app_secret_key"),
        description=(
            "Path the auto-generated master key is written to (mode 0600) and read "
            "back from on every later start. It MUST be on a persistent volume: "
            "lose this file and every stored secret is unrecoverable. Ignored "
            "whenever a key file exists at SCRYE_APP_SECRET_KEY_FILE."
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
            "HTTPS enforcement for sign-in: set the Secure flag on the session and "
            "CSRF cookies. Browsers refuse to store a Secure cookie on an http:// "
            "page, so with this true a login over PLAIN HTTP cannot take effect - "
            "the credentials are accepted and every following request still looks "
            "unauthenticated. Scrye therefore refuses such a sign-in outright and "
            "says so, rather than appearing to work. Keep true in production. "
            "Behind a TLS-terminating reverse proxy keep it true as well: have the "
            "proxy send X-Forwarded-Proto: https and point "
            "SCRYE_FORWARDED_ALLOW_IPS at the proxy. Set false ONLY to opt out "
            "deliberately on a plain-HTTP LAN/evaluation deployment - the session "
            "cookie then travels in cleartext and anyone on the network path can "
            "steal it."
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

    # --- Outbound egress ---------------------------------------------------
    allow_internal_egress: bool = Field(
        default=False,
        description=(
            "Allow server-side fetchers (notification webhooks/SMTP, the registry "
            "probe) to reach RFC-1918/private/internal addresses. Off by default to "
            "block SSRF to internal services; enable only if you use an internal "
            "SMTP relay or private registry. Loopback and cloud-metadata addresses "
            "are always refused regardless of this setting."
        ),
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
        ge=1,
        le=32,
        description=(
            "Maximum number of scans the in-process worker runs concurrently "
            "(1-32; the DB pool is sized from this value)."
        ),
    )
    scan_timeout_seconds: int = Field(
        default=1800,
        description="Per-scan wall-clock timeout in seconds (default 1800 = 30 minutes).",
    )
    scanner_max_output_bytes: int = Field(
        default=512 * 1024 * 1024,
        description=(
            "Maximum bytes of stdout captured from a single scanner subprocess "
            "(default 536870912 = 512 MiB). A scan whose output exceeds this is "
            "killed and failed, bounding memory use against a very large or "
            "hostile image that would otherwise emit unbounded JSON."
        ),
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
    filesystem_scan_roots: Annotated[list[str], NoDecode] = Field(
        default_factory=list,
        description=(
            "Comma-separated absolute paths under which filesystem (Grype 'dir:') "
            "scans are allowed. Empty disables filesystem scanning so arbitrary "
            "host paths (e.g. the database or secret files) can never be read."
        ),
    )

    @field_validator("cors_origins", "filesystem_scan_roots", mode="before")
    @classmethod
    def _split_comma_separated(cls, value: object) -> object:
        """Parse a comma-separated env string into a list of trimmed entries.

        pydantic-settings would otherwise try ``json.loads`` on a ``list[str]``
        env value, so the documented ``SCRYE_FILESYSTEM_SCAN_ROOTS=/a,/b`` (or a
        single ``/a``) fails to parse at startup (SCN-3). ``NoDecode`` on the
        field hands us the raw string; a real list (defaults, tests) passes
        through untouched.
        """
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    # --- Frontend ----------------------------------------------------------
    frontend_dist_dir: Path = Field(
        default=Path("/app/frontend/dist"),
        description="Directory containing the built React SPA served by FastAPI.",
    )

    @property
    def app_secret_key_file_is_explicit(self) -> bool:
        """Return True if the master-key path came from configuration, not the default.

        ``model_fields_set`` covers every pydantic-settings source (environment,
        ``.env``, explicit constructor kwargs), so this is true exactly when an
        operator (or a test) named the path. The master-key resolver treats an
        explicitly named path as an assertion that the key lives there and refuses
        to auto-generate around it — see :func:`app.core.crypto.resolve_master_keys`.
        """
        return "app_secret_key_file" in self.model_fields_set

    @property
    def trusted_proxies(self) -> TrustedProxies:
        """Return :attr:`forwarded_allow_ips` parsed into a trust boundary.

        The same value uvicorn is given for ``--forwarded-allow-ips``; the app
        re-parses it so ``X-Forwarded-Proto`` is honoured from exactly the peers
        the operator named, and from nobody else (see :mod:`app.core.forwarded`).
        """
        return parse_trusted_proxies(self.forwarded_allow_ips)

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
