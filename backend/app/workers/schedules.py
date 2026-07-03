"""Fire due scheduled scans (docs/PLAN.md §4.6/§12, Phase 6).

A pure, synchronous helper the maintenance scheduler calls on a timer. For each
enabled :class:`~app.db.models.scan_schedule.ScanSchedule` whose cron cadence has
come due since it last ran, it creates a queued :class:`~app.db.models.scan.Scan`
from the stored template and records the firing. The scheduler is responsible for
handing the returned scan ids to the worker; keeping the DB work here (and off
the event loop's async path) makes it directly unit-testable.
"""

from __future__ import annotations

import logging
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import record_audit
from app.core.cron import CronError, CronExpression
from app.core.timeutil import utcnow
from app.db.models import Scan, ScanSchedule, ScanStatus

logger = logging.getLogger(__name__)


def _scan_from_schedule(schedule: ScanSchedule) -> Scan:
    """Build a queued scan from a schedule's stored template."""
    return Scan(
        scanner=schedule.scanner,
        target_type=schedule.target_type,
        target=schedule.target,
        status=ScanStatus.QUEUED,
        options=dict(schedule.options or {}),
        severity_counts={},
        created_by_id=schedule.created_by_id,
        created_by_username=schedule.created_by_username,
    )


def fire_due_schedules(db: Session, *, now: datetime | None = None) -> list[int]:
    """Create scans for all due schedules; return the new scan ids.

    Never raises for an individual bad schedule — an unparseable cron is recorded
    on the row and skipped so one typo can't stall every other schedule.
    """
    now = now or utcnow()
    created: list[int] = []
    schedules = db.scalars(select(ScanSchedule).where(ScanSchedule.enabled.is_(True))).all()

    for schedule in schedules:
        try:
            cron = CronExpression.parse(schedule.cron)
        except CronError as exc:
            schedule.last_status = f"error: invalid cron ({exc})"[:255]
            continue
        last_fired = schedule.last_run_at or schedule.created_at
        if not cron.is_due(last_fired, now):
            continue

        scan = _scan_from_schedule(schedule)
        db.add(scan)
        db.flush()
        schedule.last_run_at = now
        schedule.last_scan_id = scan.id
        schedule.last_status = "ok"
        record_audit(
            db,
            action="scan.scheduled_fired",
            actor=None,
            target_type="scan_schedule",
            target_id=str(schedule.id),
            details={"scan_id": scan.id, "schedule": schedule.name},
        )
        created.append(scan.id)
        logger.info("Schedule %r fired scan %d.", schedule.name, scan.id)

    if created:
        db.commit()
    else:
        # Persist any last_status updates from skipped/invalid schedules.
        db.commit()
    return created
