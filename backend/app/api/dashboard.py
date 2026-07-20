"""Dashboard aggregation endpoint (docs/ARCHIVE.md §4.6, Phase 6).

Serves the aggregate widgets shown on the landing page: total scans, scans over
time, top vulnerable targets, open critical/high counts, scanner-DB freshness,
recent scans, and failed-scan alerts. Read-only; requires the ``viewer`` role.
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.api.scan_schemas import ScanSummaryOut
from app.api.schema_types import UtcDatetime
from app.auth.deps import AuthContext, require_role
from app.core.dashboard import (
    DashboardData,
    compute_dashboard_cached,
    failed_scan_alerts,
    recent_scans,
)
from app.core.system_info import scanner_db_status
from app.db.models import Role, Scan
from app.db.session import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

_viewer = require_role(Role.VIEWER)


class TargetPostureOut(BaseModel):
    """Open critical/high posture for one target."""

    scanner: str
    target_type: str
    target: str
    critical: int
    high: int
    total: int


class ScannerDbOut(BaseModel):
    """Vulnerability-DB freshness for one scanner."""

    name: str
    available: bool
    updated_at: str | None = None
    next_update: str | None = None
    detail: str | None = None


class FailedAlertOut(BaseModel):
    """A failed-scan alert entry."""

    id: int
    scanner: str
    target: str
    error: str | None
    created_at: UtcDatetime
    finished_at: UtcDatetime | None


class DashboardOut(BaseModel):
    """The full dashboard payload."""

    total_scans: int
    scans_by_status: dict[str, int]
    scans_by_scanner: dict[str, int]
    open_critical: int
    open_high: int
    scans_over_time: list[dict[str, object]]
    top_vulnerable_targets: list[TargetPostureOut]
    recent_scans: list[ScanSummaryOut]
    failed_alerts: list[FailedAlertOut]
    scanner_db: list[ScannerDbOut]
    schedules_enabled: int
    schedules_total: int


def _load_dashboard_data(db: Session) -> tuple[DashboardData, list[Scan], list[Scan]]:
    """Run every synchronous dashboard DB query in one batch.

    Grouped into a single function so the whole batch runs in one threadpool
    hop (the session is used by exactly one thread at a time) instead of
    blocking the event loop with synchronous aggregation queries.
    """
    return compute_dashboard_cached(db), recent_scans(db), failed_scan_alerts(db)


@router.get("", response_model=DashboardOut)
async def get_dashboard(
    _: AuthContext = Depends(_viewer),
    db: Session = Depends(get_db),
) -> DashboardOut:
    """Return the aggregate dashboard widgets (docs/ARCHIVE.md §4.6)."""
    # DB aggregation happens off the event loop, concurrently with the
    # (subprocess-backed, TTL-cached) scanner-DB freshness probes.
    # return_exceptions=True so that if the DB branch fails, gather still awaits
    # the probe branch to completion instead of leaving its subprocesses running
    # detached (CON-18); each branch's failure is then handled explicitly.
    data_result, db_status = await asyncio.gather(
        run_in_threadpool(_load_dashboard_data, db),
        scanner_db_status(),
        return_exceptions=True,
    )
    if isinstance(data_result, BaseException):
        raise data_result
    if isinstance(db_status, BaseException):
        # A probe failure degrades gracefully to "unknown" rather than failing
        # the whole dashboard.
        logger.warning("Scanner-DB freshness probe failed: %r", db_status)
        db_status = []
    data, recent, failed = data_result
    return DashboardOut(
        total_scans=data.total_scans,
        scans_by_status=data.scans_by_status,
        scans_by_scanner=data.scans_by_scanner,
        open_critical=data.open_critical,
        open_high=data.open_high,
        scans_over_time=data.scans_over_time,
        top_vulnerable_targets=[TargetPostureOut(**vars(p)) for p in data.top_vulnerable_targets],
        recent_scans=[ScanSummaryOut.model_validate(s) for s in recent],
        failed_alerts=[
            FailedAlertOut(
                id=s.id,
                scanner=s.scanner.value,
                target=s.target,
                error=s.error,
                created_at=s.created_at,
                finished_at=s.finished_at,
            )
            for s in failed
        ],
        scanner_db=[ScannerDbOut(**vars(info)) for info in db_status],
        schedules_enabled=data.schedules_enabled,
        schedules_total=data.schedules_total,
    )
