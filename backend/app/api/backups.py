"""Backup & restore endpoints and scheduled-backup config (docs/PLAN.md §8).

All actions are admin-only and CSRF-guarded. Creating a backup builds a
passphrase-protected bundle, stores it, and records its metadata. Restore is
**destructive**: it wipes and repopulates the database from an uploaded bundle
and therefore requires an explicit confirmation flag. The scheduled-backup
passphrase is field-encrypted like every other stored secret.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Request,
    Response,
    UploadFile,
    status,
)
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.deps import AuthContext, client_ip, require_csrf, require_role
from app.backup import (
    BackupError,
    build_bundle,
    read_manifest,
    restore_bundle,
)
from app.backup.store import BUNDLE_SUFFIX, BackupStore, sha256_hex
from app.core.audit import record_audit
from app.core.masking import MaskedSecret, masked_secret
from app.core.secret_store import AAD_BACKUP_PASSPHRASE, encrypt_secret
from app.core.timeutil import utcnow
from app.db.models import BACKUP_SCHEDULE_ID, Backup, BackupKind, BackupSchedule, Role
from app.db.session import get_db

router = APIRouter(prefix="/backups", tags=["backups"])

_admin = require_role(Role.ADMIN)

#: Upper bound on an uploaded bundle (guards against oversized uploads).
_MAX_UPLOAD_BYTES = 200 * 1024 * 1024
_MIN_PASSPHRASE_LEN = 8


class BackupOut(BaseModel):
    """Metadata for one stored backup bundle."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    filename: str
    size_bytes: int
    checksum_sha256: str
    kind: BackupKind
    app_version: str
    created_at: datetime
    created_by_username: str | None
    note: str | None


class BackupCreateIn(BaseModel):
    """Payload for creating a manual backup."""

    passphrase: SecretStr = Field(min_length=_MIN_PASSPHRASE_LEN)
    note: str | None = Field(default=None, max_length=255)


class RestoreOut(BaseModel):
    """Result of a completed restore."""

    tables: int
    rows: int
    app_version: str


class ScheduleOut(BaseModel):
    """Scheduled-backup configuration (passphrase masked)."""

    enabled: bool
    interval_hours: int
    retention_count: int
    passphrase: MaskedSecret
    last_run_at: datetime | None
    last_status: str | None


class ScheduleUpdateIn(BaseModel):
    """Payload for updating the scheduled-backup configuration."""

    enabled: bool | None = None
    interval_hours: int | None = Field(default=None, ge=1, le=720)
    retention_count: int | None = Field(default=None, ge=1, le=365)
    passphrase: SecretStr | None = None


def _backup_filename() -> str:
    """Return a timestamped bundle file name."""
    return f"scrye-backup-{utcnow().strftime('%Y%m%dT%H%M%S')}{BUNDLE_SUFFIX}"


@router.get("", response_model=list[BackupOut])
def list_backups(
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> list[BackupOut]:
    """List stored backups, newest first (admin)."""
    rows = db.scalars(select(Backup).order_by(Backup.created_at.desc())).all()
    return [BackupOut.model_validate(r) for r in rows]


@router.post("", response_model=BackupOut, status_code=status.HTTP_201_CREATED)
def create_backup(
    payload: BackupCreateIn,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> BackupOut:
    """Create a passphrase-protected backup bundle and store it (admin)."""
    try:
        data = build_bundle(db, payload.passphrase.get_secret_value())
    except BackupError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    filename = _backup_filename()
    BackupStore().write(data, filename)
    backup = Backup(
        filename=filename,
        size_bytes=len(data),
        checksum_sha256=sha256_hex(data),
        kind=BackupKind.MANUAL,
        app_version=read_manifest(data)["app_version"] or "",
        created_by_username=auth.user.username,
        note=payload.note,
    )
    db.add(backup)
    db.flush()
    record_audit(
        db,
        action="backup.created",
        actor=auth.user,
        ip=client_ip(request),
        target_type="backup",
        target_id=str(backup.id),
        details={"filename": filename, "kind": backup.kind.value},
    )
    db.commit()
    return BackupOut.model_validate(backup)


@router.get("/{backup_id}/download")
def download_backup(
    backup_id: int,
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> Response:
    """Download a stored backup bundle (admin)."""
    backup = db.get(Backup, backup_id)
    if backup is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Backup not found.")
    try:
        data = BackupStore().read(backup.filename)
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(
            status.HTTP_410_GONE, detail="Backup file is no longer available."
        ) from exc
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{backup.filename}"'},
    )


@router.delete("/{backup_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_backup(
    backup_id: int,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> Response:
    """Delete a stored backup (file and record) (admin)."""
    backup = db.get(Backup, backup_id)
    if backup is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Backup not found.")
    BackupStore().delete(backup.filename)
    record_audit(
        db,
        action="backup.deleted",
        actor=auth.user,
        ip=client_ip(request),
        target_type="backup",
        target_id=str(backup.id),
        details={"filename": backup.filename},
    )
    db.delete(backup)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/restore", response_model=RestoreOut)
async def restore_backup(
    request: Request,
    file: UploadFile = File(...),
    passphrase: str = Form(...),
    confirm: bool = Form(False),
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> RestoreOut:
    """Restore the database from an uploaded bundle (destructive; admin).

    Requires ``confirm=true``. On success every session is cleared, so the caller
    is signed out and must log in again with a restored account.
    """
    if not confirm:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="Restore is destructive; resubmit with confirmation.",
        )
    data = await file.read()
    if len(data) > _MAX_UPLOAD_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Backup file too big.")

    actor_username = auth.user.username
    actor_ip = client_ip(request)
    try:
        summary = restore_bundle(db, data, passphrase)
    except BackupError as exc:
        db.rollback()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    # The audit log itself was just repopulated from the bundle; record the
    # restore with no actor FK (the user table was replaced) to avoid dangling
    # references, keeping the acting username in details.
    record_audit(
        db,
        action="backup.restored",
        ip=actor_ip,
        details={"restored_by": actor_username, "rows": summary.rows, "tables": summary.tables},
    )
    db.commit()
    return RestoreOut(tables=summary.tables, rows=summary.rows, app_version=summary.app_version)


def _get_or_create_schedule(db: Session) -> BackupSchedule:
    """Return the singleton schedule row, creating a default if absent."""
    schedule = db.get(BackupSchedule, BACKUP_SCHEDULE_ID)
    if schedule is None:
        schedule = BackupSchedule(id=BACKUP_SCHEDULE_ID)
        db.add(schedule)
        db.flush()
    return schedule


def _schedule_out(schedule: BackupSchedule) -> ScheduleOut:
    """Build the masked read view of the schedule."""
    return ScheduleOut(
        enabled=schedule.enabled,
        interval_hours=schedule.interval_hours,
        retention_count=schedule.retention_count,
        passphrase=masked_secret(schedule.secret_updated_at),
        last_run_at=schedule.last_run_at,
        last_status=schedule.last_status,
    )


@router.get("/schedule", response_model=ScheduleOut)
def get_schedule(
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> ScheduleOut:
    """Return the scheduled-backup configuration (admin; passphrase masked)."""
    return _schedule_out(_get_or_create_schedule(db))


@router.put("/schedule", response_model=ScheduleOut)
def update_schedule(
    payload: ScheduleUpdateIn,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> ScheduleOut:
    """Update the scheduled-backup configuration (admin)."""
    schedule = _get_or_create_schedule(db)
    if payload.enabled is not None:
        schedule.enabled = payload.enabled
    if payload.interval_hours is not None:
        schedule.interval_hours = payload.interval_hours
    if payload.retention_count is not None:
        schedule.retention_count = payload.retention_count
    if payload.passphrase is not None:
        secret = payload.passphrase.get_secret_value()
        if len(secret) < _MIN_PASSPHRASE_LEN:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Passphrase must be at least {_MIN_PASSPHRASE_LEN} characters.",
            )
        schedule.passphrase_ciphertext = encrypt_secret(secret, aad=AAD_BACKUP_PASSPHRASE)
        schedule.secret_updated_at = utcnow()

    if schedule.enabled and not schedule.passphrase_ciphertext:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="A passphrase is required to enable scheduled backups.",
        )

    record_audit(
        db,
        action="backup.schedule_updated",
        actor=auth.user,
        ip=client_ip(request),
        details={"enabled": schedule.enabled, "interval_hours": schedule.interval_hours},
    )
    db.commit()
    return _schedule_out(schedule)
