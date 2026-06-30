"""Health-check endpoint.

``GET /healthz`` is used by the container ``HEALTHCHECK`` and by Caddy/uptime
probes. It reports application liveness and basic database connectivity without
leaking any sensitive configuration.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app import __version__
from app.db.session import get_db

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


class HealthStatus(BaseModel):
    """Response body for the health endpoint."""

    status: str
    version: str
    database: str


@router.get("/healthz", response_model=HealthStatus)
def healthz(db: Session = Depends(get_db)) -> HealthStatus:
    """Return application and database health.

    Performs a trivial ``SELECT 1`` to confirm the database is reachable. A
    database failure degrades the reported status but still returns 200 so the
    probe can distinguish "process up, DB down" from "process down".
    """
    database = "ok"
    try:
        db.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:  # pragma: no cover - exercised via failure tests
        logger.warning("Health check database probe failed: %s", exc)
        database = "error"

    status = "healthy" if database == "ok" else "degraded"
    return HealthStatus(status=status, version=__version__, database=database)
