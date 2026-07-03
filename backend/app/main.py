"""Scrye FastAPI application entrypoint.

Creates the FastAPI app, wires CORS for local development, mounts the API
routers, and serves the built React SPA (with client-side-routing fallback) when
a build is present. In development the SPA is served by the Vite dev server
instead, and this app exposes only the API.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import __version__
from app.api.api_tokens import router as api_tokens_router
from app.api.audit import router as audit_router
from app.api.auth import router as auth_router
from app.api.backups import router as backups_router
from app.api.dashboard import router as dashboard_router
from app.api.docker_environments import router as docker_environments_router
from app.api.filter_presets import router as filter_presets_router
from app.api.git_credentials import router as git_credentials_router
from app.api.health import router as health_router
from app.api.metrics import router as metrics_router
from app.api.notifications import router as notifications_router
from app.api.oidc import config_router as oidc_config_router
from app.api.oidc import login_router as oidc_login_router
from app.api.registries import router as registries_router
from app.api.scan_schedules import router as scan_schedules_router
from app.api.scans import router as scans_router
from app.api.settings import router as settings_router
from app.api.trivy_policy import router as trivy_policy_router
from app.api.users import router as users_router
from app.auth.mfa import PendingMfaStore
from app.core.config import Settings, get_settings
from app.core.crypto import MasterKeyError, get_secret_cipher
from app.core.logging import configure_logging
from app.core.ratelimit import SlidingWindowRateLimiter
from app.db.session import SessionLocal
from app.workers import InProcessScanWorker, MaintenanceScheduler
from app.workers.backup_scheduler import BackupScheduler

logger = logging.getLogger(__name__)


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Validate the master key and start the scan worker at startup.

    In production a missing/invalid key file is a fatal misconfiguration —
    failing fast beats discovering it on the first secret write. Development
    setups get a warning so the API can run before a key has been generated.

    The in-process scan worker is created here and reconciles any scans left
    mid-flight by a previous process before accepting new work.
    """
    settings = get_settings()
    try:
        cipher = get_secret_cipher()
        logger.info("Master key loaded (current key version v%d).", cipher.current_version)
    except MasterKeyError as exc:
        if settings.is_development:
            logger.warning("Master key unavailable (dev mode, continuing): %s", exc)
        else:
            raise RuntimeError(f"Refusing to start without a valid master key: {exc}") from exc

    worker = InProcessScanWorker(SessionLocal, settings.max_concurrent_scans)
    app.state.scan_worker = worker
    try:
        await worker.recover()
    except Exception:  # noqa: BLE001 - startup recovery must not crash the app
        logger.exception("Scan-worker startup recovery failed; continuing.")
    logger.info("Scan worker ready (max %d concurrent).", settings.max_concurrent_scans)

    backup_scheduler = BackupScheduler(SessionLocal)
    backup_scheduler.start()
    app.state.backup_scheduler = backup_scheduler
    logger.info("Backup scheduler started.")

    maintenance = MaintenanceScheduler(SessionLocal, worker)
    maintenance.start()
    app.state.maintenance_scheduler = maintenance
    logger.info("Maintenance scheduler started (scheduled scans + retention).")

    try:
        yield
    finally:
        await maintenance.shutdown()
        await backup_scheduler.shutdown()
        await worker.shutdown()
        logger.info("Scan worker, backup, and maintenance schedulers stopped.")


def _mount_spa(app: FastAPI, dist_dir: Path) -> None:
    """Serve the built SPA with a catch-all fallback to ``index.html``.

    Static assets are served from ``<dist>/assets``; any other non-API path
    returns ``index.html`` so client-side routing works on deep links.
    """
    index_file = dist_dir / "index.html"
    assets_dir = dist_dir / "assets"
    if assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    @app.get("/", include_in_schema=False)
    def serve_index() -> FileResponse:
        """Serve the SPA entrypoint."""
        return FileResponse(index_file)

    @app.exception_handler(StarletteHTTPException)
    async def spa_fallback(request, exc: StarletteHTTPException):  # type: ignore[no-untyped-def]
        """Return the SPA shell for unmatched GET routes; pass through API 404s."""
        path = request.url.path
        if (
            exc.status_code == 404
            and request.method == "GET"
            and not path.startswith(("/api", "/healthz", "/docs", "/openapi.json", "/assets"))
        ):
            return FileResponse(index_file)
        from fastapi.responses import JSONResponse

        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build and configure the FastAPI application.

    Args:
        settings: Optional settings override (defaults to the cached settings).

    Returns:
        A configured :class:`~fastapi.FastAPI` instance.
    """
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        description="Unified self-hosted web UI for the Trivy and Grype scanners.",
        lifespan=_lifespan,
    )
    app.state.auth_limiter = SlidingWindowRateLimiter(
        settings.auth_rate_limit_attempts, settings.auth_rate_limit_window_seconds
    )
    app.state.pending_mfa = PendingMfaStore()

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    app.include_router(health_router)
    app.include_router(metrics_router)
    app.include_router(auth_router, prefix="/api")
    app.include_router(oidc_login_router, prefix="/api")
    app.include_router(oidc_config_router, prefix="/api")
    app.include_router(users_router, prefix="/api")
    app.include_router(audit_router, prefix="/api")
    app.include_router(dashboard_router, prefix="/api")
    app.include_router(scans_router, prefix="/api")
    app.include_router(scan_schedules_router, prefix="/api")
    app.include_router(filter_presets_router, prefix="/api")
    app.include_router(registries_router, prefix="/api")
    app.include_router(git_credentials_router, prefix="/api")
    app.include_router(docker_environments_router, prefix="/api")
    app.include_router(settings_router, prefix="/api")
    app.include_router(trivy_policy_router, prefix="/api")
    app.include_router(notifications_router, prefix="/api")
    app.include_router(api_tokens_router, prefix="/api")
    app.include_router(backups_router, prefix="/api")

    dist_dir = settings.frontend_dist_dir
    if (dist_dir / "index.html").is_file():
        _mount_spa(app, dist_dir)
    else:
        logger.info("No SPA build at %s; serving API only (dev mode).", dist_dir)

    return app


app = create_app()
