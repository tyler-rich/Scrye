"""Dashboard aggregation queries (docs/PLAN.md §4.6, Phase 6).

Pure, synchronous helpers that compute the dashboard widgets from the ``scans``
table: totals, status/scanner breakdowns, a scans-over-time series, the current
open critical/high posture, and the most-vulnerable targets. "Open" counts are
derived from the **latest succeeded scan per target** so re-scanning a fixed
target lowers the number, giving a live posture rather than a running total.

Keeping these off the API layer makes them directly unit-testable against a
session and keeps the endpoint a thin adapter.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session, load_only, selectinload

from app.core.timeutil import utcnow
from app.db.models import Scan, ScanStatus, Severity

#: Number of days covered by the scans-over-time series.
_TIME_SERIES_DAYS = 30
#: Number of targets shown in the top-vulnerable-targets widget.
_TOP_TARGETS = 10
#: Number of most-recent scans returned.
_RECENT_SCANS = 10
#: Number of most-recent failed scans returned as alerts.
_FAILED_ALERTS = 10


@dataclass
class TargetPosture:
    """The current open findings for one scanned target."""

    scanner: str
    target_type: str
    target: str
    critical: int
    high: int
    total: int


@dataclass
class DashboardData:
    """The computed dashboard aggregates (before serialization)."""

    total_scans: int = 0
    scans_by_status: dict[str, int] = field(default_factory=dict)
    scans_by_scanner: dict[str, int] = field(default_factory=dict)
    open_critical: int = 0
    open_high: int = 0
    scans_over_time: list[dict[str, object]] = field(default_factory=list)
    top_vulnerable_targets: list[TargetPosture] = field(default_factory=list)
    schedules_enabled: int = 0
    schedules_total: int = 0


def _count_by(db: Session, column) -> dict[str, int]:
    """Return a ``{value: count}`` map grouping scans by an enum column."""
    rows = db.execute(select(column, func.count()).group_by(column)).all()
    return {str(value): count for value, count in rows}


def latest_succeeded_scans(db: Session) -> list[Scan]:
    """Return the latest succeeded scan per (scanner, target type, target).

    The target *type* is part of the identity: the same target string can name
    unrelated things across types (an image ref vs. a filesystem path vs. an
    uploaded SBOM filename), and folding them together would silently drop one
    target's posture from the aggregates. ``max(id)`` stands in for "most
    recent" since ids increase with creation, so this needs no correlated
    timestamp subquery.
    """
    latest_ids = (
        select(func.max(Scan.id))
        .where(Scan.status == ScanStatus.SUCCEEDED)
        .group_by(Scan.scanner, Scan.target_type, Scan.target)
    )
    # Load only the columns the posture aggregation reads, not the whole row
    # (skips the heavy ``options``/``error`` columns) per distinct target (API-7).
    return list(
        db.scalars(
            select(Scan)
            .where(Scan.id.in_(latest_ids))
            .options(
                load_only(
                    Scan.scanner,
                    Scan.target_type,
                    Scan.target,
                    Scan.severity_counts,
                    Scan.findings_count,
                )
            )
        ).all()
    )


def _time_series(db: Session, *, now: datetime) -> list[dict[str, object]]:
    """Return per-day scan counts over the trailing window (zero-filled)."""
    cutoff = (now - timedelta(days=_TIME_SERIES_DAYS - 1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    rows = db.execute(
        select(func.date(Scan.created_at), func.count())
        .where(Scan.created_at >= cutoff)
        .group_by(func.date(Scan.created_at))
    ).all()
    counts = {str(day): count for day, count in rows}
    series: list[dict[str, object]] = []
    for offset in range(_TIME_SERIES_DAYS):
        day = (cutoff + timedelta(days=offset)).date().isoformat()
        series.append({"date": day, "count": counts.get(day, 0)})
    return series


def compute_dashboard(db: Session, *, now: datetime | None = None) -> DashboardData:
    """Compute all dashboard aggregates from the scans table."""
    from app.db.models import ScanSchedule  # local import avoids a cycle at import time

    now = now or utcnow()
    total = db.scalar(select(func.count()).select_from(Scan)) or 0

    latest = latest_succeeded_scans(db)
    open_critical = sum((s.severity_counts or {}).get(Severity.CRITICAL.value, 0) for s in latest)
    open_high = sum((s.severity_counts or {}).get(Severity.HIGH.value, 0) for s in latest)

    postures = [
        TargetPosture(
            scanner=s.scanner.value,
            target_type=s.target_type.value,
            target=s.target,
            critical=(s.severity_counts or {}).get(Severity.CRITICAL.value, 0),
            high=(s.severity_counts or {}).get(Severity.HIGH.value, 0),
            total=s.findings_count,
        )
        for s in latest
    ]
    postures = [p for p in postures if p.critical or p.high]
    postures.sort(key=lambda p: (p.critical, p.high, p.total), reverse=True)

    schedules_total = db.scalar(select(func.count()).select_from(ScanSchedule)) or 0
    schedules_enabled = (
        db.scalar(
            select(func.count()).select_from(ScanSchedule).where(ScanSchedule.enabled.is_(True))
        )
        or 0
    )

    return DashboardData(
        total_scans=total,
        scans_by_status=_count_by(db, Scan.status),
        scans_by_scanner=_count_by(db, Scan.scanner),
        open_critical=open_critical,
        open_high=open_high,
        scans_over_time=_time_series(db, now=now),
        top_vulnerable_targets=postures[:_TOP_TARGETS],
        schedules_enabled=schedules_enabled,
        schedules_total=schedules_total,
    )


#: Short TTL for the dashboard aggregate cache. The posture changes only when a
#: scan finishes, so a few seconds keeps it near-live while collapsing bursts of
#: dashboard loads and Prometheus scrapes onto one computation.
_DASHBOARD_TTL_SECONDS = 15.0
#: Cached ``(monotonic timestamp, aggregates)`` shared across requests.
_dashboard_cache: tuple[float, DashboardData] | None = None


def compute_dashboard_cached(db: Session, *, now: datetime | None = None) -> DashboardData:
    """Return the dashboard aggregates with a short process-wide TTL cache (API-7).

    Both the dashboard endpoint and every Prometheus scrape read these
    aggregates; without a cache each recomputes a ``GROUP BY`` over the whole
    scans table plus a per-target load. A few-seconds TTL collapses read bursts
    onto one computation. Callers wanting a guaranteed-fresh result (tests) call
    :func:`compute_dashboard` directly.
    """
    global _dashboard_cache
    cached = _dashboard_cache
    if cached is not None and time.monotonic() - cached[0] < _DASHBOARD_TTL_SECONDS:
        return cached[1]
    data = compute_dashboard(db, now=now)
    _dashboard_cache = (time.monotonic(), data)
    return data


def reset_dashboard_cache() -> None:
    """Clear the dashboard TTL cache (app startup and test isolation)."""
    global _dashboard_cache
    _dashboard_cache = None


def recent_scans(db: Session) -> list[Scan]:
    """Return the most-recent scans for the dashboard's recent-scans widget.

    Tags are eager-loaded because the API serializes them (``ScanOut.tags``);
    without this each scan would lazy-load its tag rows one query at a time,
    on the event loop, after the aggregation batch has already returned.
    """
    return list(
        db.scalars(
            select(Scan)
            .options(selectinload(Scan.tag_rows))
            .order_by(Scan.created_at.desc(), Scan.id.desc())
            .limit(_RECENT_SCANS)
        ).all()
    )


def failed_scan_alerts(db: Session) -> list[Scan]:
    """Return the most-recent failed scans for the failed-scan alerts widget."""
    return list(
        db.scalars(
            select(Scan)
            .where(Scan.status == ScanStatus.FAILED)
            .order_by(Scan.created_at.desc(), Scan.id.desc())
            .limit(_FAILED_ALERTS)
        ).all()
    )
