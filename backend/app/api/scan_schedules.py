"""Scheduled/recurring scan management (docs/PLAN.md §4.6/§12, Phase 6).

CRUD for cron-driven scan schedules, plus a "run now" action. A schedule stores a
scan template (scanner, target type, target, options, and an optional
registry/git credential referenced by id) and a 5-field cron cadence; the
in-process maintenance scheduler fires due schedules automatically.

RBAC: managing schedules is an ``operator`` action (the same role that launches
scans); reading them requires ``viewer``. Writes are CSRF-guarded.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.scan_schemas import ScanCreateIn
from app.api.schema_types import UtcDatetime
from app.auth.deps import AuthContext, client_ip, require_csrf, require_role
from app.core.audit import record_audit
from app.core.cron import CronError, validate_cron
from app.core.timeutil import utcnow
from app.db.models import (
    GitCredential,
    Registry,
    Role,
    Scan,
    Scanner,
    ScanSchedule,
    ScanStatus,
    TargetType,
)
from app.db.session import get_db
from app.scanners.support import scanner_supports

router = APIRouter(prefix="/scan-schedules", tags=["scan-schedules"])

_viewer = require_role(Role.VIEWER)
_operator = require_role(Role.OPERATOR)


class ScanScheduleIn(ScanCreateIn):
    """Full definition of a scan schedule (scan template + cadence)."""

    name: str = Field(min_length=1, max_length=128)
    cron: str = Field(min_length=1, max_length=128, description="5-field cron expression.")
    enabled: bool = True

    @field_validator("cron")
    @classmethod
    def _validate_cron(cls, value: str) -> str:
        """Validate and normalize the cron expression."""
        try:
            return validate_cron(value)
        except CronError as exc:
            raise ValueError(str(exc)) from exc


class ScanScheduleOut(BaseModel):
    """Read view of a scan schedule."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    enabled: bool
    cron: str
    scanner: Scanner
    target_type: TargetType
    target: str
    options: dict
    registry_id: int | None
    git_credential_id: int | None
    last_run_at: UtcDatetime | None
    last_scan_id: int | None
    last_status: str | None
    created_by_username: str | None
    created_at: UtcDatetime
    updated_at: UtcDatetime


def _get_or_404(db: Session, schedule_id: int) -> ScanSchedule:
    """Fetch a schedule by id or raise 404."""
    schedule = db.get(ScanSchedule, schedule_id)
    if schedule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Scan schedule not found.")
    return schedule


def _validate_template(db: Session, payload: ScanScheduleIn) -> None:
    """Validate the scan template (target type / scanner / referenced creds)."""
    if payload.target_type is TargetType.SBOM:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="SBOM scans cannot be scheduled (they require a file upload).",
        )
    if not scanner_supports(payload.target_type, payload.scanner):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"{payload.scanner.value} does not support "
            f"{payload.target_type.value} targets.",
        )
    if (
        payload.target_type is TargetType.IMAGE
        and payload.registry_id is not None
        and db.get(Registry, payload.registry_id) is None
    ):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, detail="The selected registry does not exist."
        )
    if (
        payload.target_type is TargetType.REPOSITORY
        and payload.git_credential_id is not None
        and db.get(GitCredential, payload.git_credential_id) is None
    ):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="The selected git credential does not exist.",
        )


def _apply_template(schedule: ScanSchedule, payload: ScanScheduleIn) -> None:
    """Copy the validated scan template onto a schedule row."""
    schedule.name = payload.name
    schedule.enabled = payload.enabled
    schedule.cron = payload.cron
    schedule.scanner = payload.scanner
    schedule.target_type = payload.target_type
    schedule.target = payload.target
    schedule.options = payload.to_options()
    schedule.registry_id = payload.registry_id if payload.target_type is TargetType.IMAGE else None
    schedule.git_credential_id = (
        payload.git_credential_id if payload.target_type is TargetType.REPOSITORY else None
    )


@router.get("", response_model=list[ScanScheduleOut])
def list_schedules(
    _: AuthContext = Depends(_viewer),
    db: Session = Depends(get_db),
) -> list[ScanScheduleOut]:
    """List all scan schedules."""
    rows = db.scalars(select(ScanSchedule).order_by(ScanSchedule.name)).all()
    return [ScanScheduleOut.model_validate(r) for r in rows]


@router.post("", response_model=ScanScheduleOut, status_code=status.HTTP_201_CREATED)
def create_schedule(
    payload: ScanScheduleIn,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_operator),
    db: Session = Depends(get_db),
) -> ScanScheduleOut:
    """Create a recurring scan schedule."""
    if db.scalar(select(ScanSchedule).where(ScanSchedule.name == payload.name)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="A schedule with that name exists.")
    _validate_template(db, payload)

    schedule = ScanSchedule(created_by_id=auth.user.id, created_by_username=auth.user.username)
    _apply_template(schedule, payload)
    db.add(schedule)
    db.flush()
    record_audit(
        db,
        action="schedule.created",
        actor=auth.user,
        ip=client_ip(request),
        target_type="scan_schedule",
        target_id=str(schedule.id),
        details={"name": schedule.name, "cron": schedule.cron},
    )
    db.commit()
    return ScanScheduleOut.model_validate(schedule)


@router.get("/{schedule_id}", response_model=ScanScheduleOut)
def get_schedule(
    schedule_id: int,
    _: AuthContext = Depends(_viewer),
    db: Session = Depends(get_db),
) -> ScanScheduleOut:
    """Return a single scan schedule."""
    return ScanScheduleOut.model_validate(_get_or_404(db, schedule_id))


@router.put("/{schedule_id}", response_model=ScanScheduleOut)
def update_schedule(
    schedule_id: int,
    payload: ScanScheduleIn,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_operator),
    db: Session = Depends(get_db),
) -> ScanScheduleOut:
    """Replace a scan schedule's definition."""
    schedule = _get_or_404(db, schedule_id)
    clash = db.scalar(
        select(ScanSchedule).where(
            ScanSchedule.name == payload.name, ScanSchedule.id != schedule_id
        )
    )
    if clash is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="A schedule with that name exists.")
    _validate_template(db, payload)
    _apply_template(schedule, payload)
    record_audit(
        db,
        action="schedule.updated",
        actor=auth.user,
        ip=client_ip(request),
        target_type="scan_schedule",
        target_id=str(schedule.id),
        details={"name": schedule.name, "cron": schedule.cron},
    )
    db.commit()
    return ScanScheduleOut.model_validate(schedule)


@router.delete("/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_schedule(
    schedule_id: int,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_operator),
    db: Session = Depends(get_db),
) -> Response:
    """Delete a scan schedule."""
    schedule = _get_or_404(db, schedule_id)
    record_audit(
        db,
        action="schedule.deleted",
        actor=auth.user,
        ip=client_ip(request),
        target_type="scan_schedule",
        target_id=str(schedule.id),
        details={"name": schedule.name},
    )
    db.delete(schedule)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{schedule_id}/run", response_model=ScanScheduleOut)
async def run_schedule_now(
    schedule_id: int,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_operator),
    db: Session = Depends(get_db),
) -> ScanScheduleOut:
    """Fire a schedule immediately, launching one scan from its template."""
    schedule = _get_or_404(db, schedule_id)
    scan = Scan(
        scanner=schedule.scanner,
        target_type=schedule.target_type,
        target=schedule.target,
        status=ScanStatus.QUEUED,
        options=dict(schedule.options or {}),
        severity_counts={},
        created_by_id=auth.user.id,
        created_by_username=auth.user.username,
    )
    db.add(scan)
    db.flush()
    schedule.last_scan_id = scan.id
    # Record this as a run: the cron tick fires on ``last_run_at``, so stamping
    # it now stops the tick from firing the same schedule again within this
    # minute — a duplicate back-to-back scan and a raced ``last_scan_id`` (CON-17).
    schedule.last_run_at = utcnow()
    schedule.last_status = "ok (manual run)"
    record_audit(
        db,
        action="schedule.run_now",
        actor=auth.user,
        ip=client_ip(request),
        target_type="scan_schedule",
        target_id=str(schedule.id),
        details={"scan_id": scan.id},
    )
    db.commit()
    await request.app.state.scan_worker.submit(scan.id)
    db.refresh(schedule)
    return ScanScheduleOut.model_validate(schedule)
