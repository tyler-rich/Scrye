"""Scan endpoints: launch scans, browse results, download raw artifacts.

RBAC (docs/PLAN.md §5): launching a scan requires ``operator``; reading scans,
findings, and artifacts requires ``viewer``. Launch and cancel are CSRF-guarded
state-changing operations.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import FileResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.scan_schemas import (
    ArtifactOut,
    FindingOut,
    FindingsPage,
    ScanCreateIn,
    ScanOut,
)
from app.auth.deps import AuthContext, client_ip, require_csrf, require_role
from app.core.artifacts import artifact_path
from app.core.audit import record_audit
from app.core.timeutil import utcnow
from app.db.models import (
    Artifact,
    Finding,
    FindingClass,
    Role,
    Scan,
    Scanner,
    ScanStatus,
    Severity,
    TargetType,
)
from app.db.session import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])

_viewer = require_role(Role.VIEWER)
_operator = require_role(Role.OPERATOR)


def _get_scan_or_404(db: Session, scan_id: int) -> Scan:
    """Fetch a scan by id or raise 404."""
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    return scan


@router.post("", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
async def create_scan(
    payload: ScanCreateIn,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_operator),
    db: Session = Depends(get_db),
) -> ScanOut:
    """Queue a new scan and hand it to the worker.

    Phase 2 supports image targets only; other target types are rejected until
    Phase 3 adds them.
    """
    if payload.target_type is not TargetType.IMAGE:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Target type '{payload.target_type.value}' is not supported yet.",
        )

    scan = Scan(
        scanner=payload.scanner,
        target_type=payload.target_type,
        target=payload.target,
        status=ScanStatus.QUEUED,
        options=payload.to_options(),
        severity_counts={},
        created_by_id=auth.user.id,
        created_by_username=auth.user.username,
    )
    db.add(scan)
    db.flush()
    record_audit(
        db,
        action="scan.created",
        actor=auth.user,
        ip=client_ip(request),
        target_type="scan",
        target_id=str(scan.id),
        details={"scanner": scan.scanner.value, "target": scan.target},
    )
    db.commit()

    await request.app.state.scan_worker.submit(scan.id)
    logger.info("Queued scan %d (%s %s).", scan.id, scan.scanner.value, scan.target)
    return ScanOut.model_validate(scan)


@router.get("", response_model=list[ScanOut])
def list_scans(
    _: AuthContext = Depends(_viewer),
    db: Session = Depends(get_db),
    scanner: Scanner | None = Query(default=None),
    scan_status: ScanStatus | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> list[ScanOut]:
    """List scans, newest first (basic filters; full history in Phase 4)."""
    stmt = select(Scan).order_by(Scan.created_at.desc(), Scan.id.desc())
    if scanner is not None:
        stmt = stmt.where(Scan.scanner == scanner)
    if scan_status is not None:
        stmt = stmt.where(Scan.status == scan_status)
    scans = db.scalars(stmt.limit(limit).offset(offset)).all()
    return [ScanOut.model_validate(s) for s in scans]


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: int,
    _: AuthContext = Depends(_viewer),
    db: Session = Depends(get_db),
) -> ScanOut:
    """Return a single scan's status and summary."""
    return ScanOut.model_validate(_get_scan_or_404(db, scan_id))


@router.get("/{scan_id}/findings", response_model=FindingsPage)
def list_findings(
    scan_id: int,
    _: AuthContext = Depends(_viewer),
    db: Session = Depends(get_db),
    severity: Severity | None = Query(default=None),
    finding_class: FindingClass | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> FindingsPage:
    """Return a page of a scan's normalized findings."""
    _get_scan_or_404(db, scan_id)
    conditions = [Finding.scan_id == scan_id]
    if severity is not None:
        conditions.append(Finding.severity == severity)
    if finding_class is not None:
        conditions.append(Finding.finding_class == finding_class)

    total = db.scalar(select(func.count()).select_from(Finding).where(*conditions)) or 0
    rows = db.scalars(
        select(Finding).where(*conditions).order_by(Finding.id).limit(limit).offset(offset)
    ).all()
    return FindingsPage(total=total, items=[FindingOut.model_validate(r) for r in rows])


@router.get("/{scan_id}/artifacts", response_model=list[ArtifactOut])
def list_artifacts(
    scan_id: int,
    _: AuthContext = Depends(_viewer),
    db: Session = Depends(get_db),
) -> list[ArtifactOut]:
    """List a scan's stored artifacts (raw scanner output, SBOMs)."""
    _get_scan_or_404(db, scan_id)
    rows = db.scalars(
        select(Artifact).where(Artifact.scan_id == scan_id).order_by(Artifact.id)
    ).all()
    return [ArtifactOut.model_validate(r) for r in rows]


@router.get("/{scan_id}/artifacts/{artifact_id}/download")
def download_artifact(
    scan_id: int,
    artifact_id: int,
    _: AuthContext = Depends(_viewer),
    db: Session = Depends(get_db),
) -> FileResponse:
    """Download an artifact's raw bytes (the source-of-truth scanner output)."""
    artifact = db.get(Artifact, artifact_id)
    if artifact is None or artifact.scan_id != scan_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Artifact not found.")
    try:
        path = artifact_path(artifact.relative_path)
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Artifact path is invalid."
        ) from exc
    if not path.is_file():
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Artifact file is missing on disk.")
    return FileResponse(
        path,
        media_type=artifact.content_type,
        filename=artifact.filename,
    )


@router.post("/{scan_id}/cancel", response_model=ScanOut)
def cancel_scan(
    scan_id: int,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_operator),
    db: Session = Depends(get_db),
) -> ScanOut:
    """Cancel a scan that is still queued.

    A scan already running cannot be interrupted in v1 (the in-process worker
    has no cancellation channel to a live subprocess); only ``queued`` scans can
    be canceled.
    """
    scan = _get_scan_or_404(db, scan_id)
    if scan.status != ScanStatus.QUEUED:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"Only queued scans can be canceled (status is '{scan.status.value}').",
        )
    scan.status = ScanStatus.CANCELED
    scan.finished_at = utcnow()
    record_audit(
        db,
        action="scan.canceled",
        actor=auth.user,
        ip=client_ip(request),
        target_type="scan",
        target_id=str(scan.id),
    )
    db.commit()
    return ScanOut.model_validate(scan)
