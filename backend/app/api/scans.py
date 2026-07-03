"""Scan endpoints: launch scans, browse results, download raw artifacts.

RBAC (docs/PLAN.md §5): launching a scan requires ``operator``; reading scans,
findings, and artifacts requires ``viewer``. Launch and cancel are CSRF-guarded
state-changing operations.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
    status,
)
from fastapi.responses import FileResponse
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.api.scan_schemas import (
    ArtifactOut,
    FindingOut,
    FindingsPage,
    ScanCreateIn,
    ScanOut,
)
from app.auth.deps import AuthContext, client_ip, require_csrf, require_role
from app.core.artifacts import artifact_path, store_artifact
from app.core.audit import record_audit
from app.core.timeutil import utcnow
from app.db.models import (
    Artifact,
    ArtifactKind,
    Finding,
    FindingClass,
    GitCredential,
    Registry,
    Role,
    Scan,
    Scanner,
    ScanStatus,
    Severity,
    TargetType,
)
from app.db.session import get_db
from app.scanners.targets import TargetError, resolve_filesystem_path

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])

_viewer = require_role(Role.VIEWER)
_operator = require_role(Role.OPERATOR)

#: Which scanners may run against each target type (docs/PLAN.md §4).
_ALLOWED_SCANNERS: dict[TargetType, set[Scanner]] = {
    TargetType.IMAGE: {Scanner.TRIVY, Scanner.GRYPE},
    TargetType.REPOSITORY: {Scanner.TRIVY},
    TargetType.FILESYSTEM: {Scanner.GRYPE},
    TargetType.SBOM: {Scanner.GRYPE},
}

#: Filename used to store an uploaded SBOM (the display target keeps the original).
_UPLOADED_SBOM_FILENAME = "uploaded-sbom.json"
#: Maximum accepted uploaded-SBOM size (SBOMs are JSON; 25 MiB is generous).
_MAX_SBOM_UPLOAD_BYTES = 25 * 1024 * 1024


def _get_scan_or_404(db: Session, scan_id: int) -> Scan:
    """Fetch a scan by id or raise 404."""
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    return scan


def _reject_unsupported_combo(target_type: TargetType, scanner: Scanner) -> None:
    """Raise 422 if ``scanner`` cannot run against ``target_type``."""
    if scanner not in _ALLOWED_SCANNERS[target_type]:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"{scanner.value} does not support {target_type.value} targets.",
        )


async def _queue_scan(request: Request, db: Session, scan: Scan, auth: AuthContext) -> ScanOut:
    """Persist a queued scan, audit it, hand it to the worker, and return it."""
    db.add(scan)
    db.flush()
    record_audit(
        db,
        action="scan.created",
        actor=auth.user,
        ip=client_ip(request),
        target_type="scan",
        target_id=str(scan.id),
        details={
            "scanner": scan.scanner.value,
            "target_type": scan.target_type.value,
            "target": scan.target,
        },
    )
    db.commit()
    await request.app.state.scan_worker.submit(scan.id)
    logger.info(
        "Queued scan %d (%s %s %s).",
        scan.id,
        scan.scanner.value,
        scan.target_type.value,
        scan.target,
    )
    return ScanOut.model_validate(scan)


@router.post("", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
async def create_scan(
    payload: ScanCreateIn,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_operator),
    db: Session = Depends(get_db),
) -> ScanOut:
    """Queue an image, repository, or filesystem scan and hand it to the worker.

    SBOM targets are launched via ``POST /scans/sbom`` (they carry an uploaded
    file). Registry/git credentials are referenced by id and resolved — and
    decrypted — only when the worker runs the scan.
    """
    if payload.target_type is TargetType.SBOM:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="SBOM scans require a file upload; use POST /api/scans/sbom.",
        )
    _reject_unsupported_combo(payload.target_type, payload.scanner)

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
    if payload.target_type is TargetType.FILESYSTEM:
        # Reject an out-of-bounds or missing path up front (the worker re-checks).
        try:
            resolve_filesystem_path(payload.target)
        except TargetError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

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
    return await _queue_scan(request, db, scan, auth)


@router.post("/sbom", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
async def create_sbom_scan(
    request: Request,
    file: UploadFile = File(..., description="An SBOM file (CycloneDX/SPDX/Syft JSON)."),
    scanner: Scanner = Form(Scanner.GRYPE),
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_operator),
    db: Session = Depends(get_db),
) -> ScanOut:
    """Queue a Grype scan of an uploaded SBOM (``grype sbom:<file>``).

    The SBOM is stored as the scan's input artifact; the worker feeds it to
    Grype. Only Grype scans SBOMs (docs/PLAN.md §4.2).
    """
    _reject_unsupported_combo(TargetType.SBOM, scanner)

    data = await file.read()
    if not data:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail="The SBOM file is empty.")
    if len(data) > _MAX_SBOM_UPLOAD_BYTES:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"SBOM exceeds the {_MAX_SBOM_UPLOAD_BYTES // (1024 * 1024)} MiB limit.",
        )
    try:
        json.loads(data)
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, detail="The SBOM file is not valid JSON."
        ) from exc

    display_name = Path(file.filename or "sbom.json").name or "sbom.json"
    scan = Scan(
        scanner=scanner,
        target_type=TargetType.SBOM,
        target=display_name[:512],
        status=ScanStatus.QUEUED,
        options={},
        severity_counts={},
        created_by_id=auth.user.id,
        created_by_username=auth.user.username,
    )
    db.add(scan)
    db.flush()
    stored = store_artifact(scan.id, _UPLOADED_SBOM_FILENAME, data)
    db.add(
        Artifact(
            scan_id=scan.id,
            kind=ArtifactKind.SBOM,
            filename=_UPLOADED_SBOM_FILENAME,
            content_type="application/json",
            relative_path=stored.relative_path,
            size_bytes=stored.size_bytes,
            sha256=stored.sha256,
        )
    )
    return await _queue_scan(request, db, scan, auth)


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
    # Atomically flip queued -> canceled only if still queued. This races the
    # worker, which claims a scan with the mirror update (queued -> running);
    # SQLite serializes the two writes so a cancel can't clobber a scan the
    # worker already started (and vice versa).
    canceled = db.execute(
        update(Scan)
        .where(Scan.id == scan_id, Scan.status == ScanStatus.QUEUED)
        .values(status=ScanStatus.CANCELED, finished_at=utcnow())
    )
    if canceled.rowcount == 0:
        db.rollback()
        db.refresh(scan)
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"Only queued scans can be canceled (status is '{scan.status.value}').",
        )
    record_audit(
        db,
        action="scan.canceled",
        actor=auth.user,
        ip=client_ip(request),
        target_type="scan",
        target_id=str(scan_id),
    )
    db.commit()
    db.refresh(scan)
    return ScanOut.model_validate(scan)
