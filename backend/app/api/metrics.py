"""Prometheus ``/metrics`` endpoint (docs/ARCHIVE.md §12, Phase 6).

Exposes Scrye's metrics in Prometheus text-exposition format. Because the
metrics reveal scan volumes and the open vulnerability posture, the endpoint is
**authenticated** (``viewer`` role) rather than public — a Prometheus scrape
configures a personal API token as a bearer credential (``authorization`` in the
scrape config), which satisfies the same dependency without a cookie/CSRF flow.
This keeps the security-first posture (docs/ARCHIVE.md §1) intact for a
loopback-bound instance behind Caddy.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app.auth.deps import AuthContext, require_role
from app.core.metrics import CONTENT_TYPE, render_metrics
from app.db.models import Role
from app.db.session import get_db

router = APIRouter(tags=["metrics"])

_viewer = require_role(Role.VIEWER)


@router.get("/metrics", response_class=PlainTextResponse, include_in_schema=False)
def metrics(
    _: AuthContext = Depends(_viewer),
    db: Session = Depends(get_db),
) -> PlainTextResponse:
    """Return Scrye metrics in Prometheus text-exposition format (viewer role)."""
    return PlainTextResponse(content=render_metrics(db), media_type=CONTENT_TYPE)
