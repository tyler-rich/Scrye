"""Scrye FastAPI application entrypoint.

Creates the FastAPI app, wires CORS for local development, mounts the API
routers, and serves the built React SPA (with client-side-routing fallback) when
a build is present. In development the SPA is served by the Vite dev server
instead, and this app exposes only the API.
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import __version__
from app.api.health import router as health_router
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging

logger = logging.getLogger(__name__)


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
    )

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    app.include_router(health_router)

    dist_dir = settings.frontend_dist_dir
    if (dist_dir / "index.html").is_file():
        _mount_spa(app, dist_dir)
    else:
        logger.info("No SPA build at %s; serving API only (dev mode).", dist_dir)

    return app


app = create_app()
