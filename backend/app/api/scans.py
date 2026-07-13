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
    Response,
    UploadFile,
    status,
)
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from sqlalchemy import case, func, select, update
from sqlalchemy.orm import Session, load_only, selectinload

from app.api.history_schemas import (
    DiffFindingOut,
    FilterOptionsOut,
    ScanDiffOut,
    ScanHistoryPage,
    ScanTagsIn,
)
from app.api.scan_filters import HistoryFilters, history_filters
from app.api.scan_schemas import (
    ArtifactOut,
    FindingOut,
    FindingsPage,
    ScanCreateIn,
    ScanOut,
    ScanSummaryOut,
)
from app.api.uploads import read_upload_capped
from app.auth.deps import AuthContext, client_ip, require_csrf, require_role
from app.core.artifacts import artifact_path, remove_scan_artifacts, store_artifact
from app.core.audit import record_audit
from app.core.timeutil import utcnow
from app.db.models import (
    SEVERITY_RANK,
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
    ScanTag,
    Severity,
    TargetType,
)
from app.db.session import get_db
from app.reports import ExportFormat, diff_findings, export_history, export_scan
from app.scanners.support import scanner_supports
from app.scanners.targets import TargetError, resolve_filesystem_path

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])

_viewer = require_role(Role.VIEWER)
_operator = require_role(Role.OPERATOR)

#: Filename used to store an uploaded SBOM (the display target keeps the original).
_UPLOADED_SBOM_FILENAME = "uploaded-sbom.json"
#: Maximum accepted uploaded-SBOM size (SBOMs are JSON; 25 MiB is generous).
_MAX_SBOM_UPLOAD_BYTES = 25 * 1024 * 1024
#: Maximum number of scans a single filtered-history export will emit.
_MAX_HISTORY_EXPORT_SCANS = 5000

#: SQL expression ranking a scan's highest severity for severity-aware sorting.
_HIGHEST_SEVERITY_RANK = case(
    *((Scan.highest_severity == sev.value, rank) for sev, rank in SEVERITY_RANK.items()),
    else_=-1,
)

#: Sortable history columns → their ORM sort expression.
_SORT_COLUMNS: dict[str, object] = {
    "created_at": Scan.created_at,
    "findings_count": Scan.findings_count,
    "target": Scan.target,
    "status": Scan.status,
    "scanner": Scan.scanner,
    "severity": _HIGHEST_SEVERITY_RANK,
}


def _get_scan_or_404(db: Session, scan_id: int) -> Scan:
    """Fetch a scan by id or raise 404."""
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    return scan


def _reject_unsupported_combo(target_type: TargetType, scanner: Scanner) -> None:
    """Raise 422 if ``scanner`` cannot run against ``target_type``."""
    if not scanner_supports(target_type, scanner):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"{scanner.value} does not support {target_type.value} targets.",
        )


def _persist_queued_scan(db: Session, scan: Scan, *, actor: AuthContext, ip: str | None) -> None:
    """Insert a queued scan and its audit row, then commit (synchronous)."""
    db.add(scan)
    db.flush()
    record_audit(
        db,
        action="scan.created",
        actor=actor.user,
        ip=ip,
        target_type="scan",
        target_id=str(scan.id),
        details={
            "scanner": scan.scanner.value,
            "target_type": scan.target_type.value,
            "target": scan.target,
        },
    )
    db.commit()


async def _queue_scan(request: Request, db: Session, scan: Scan, auth: AuthContext) -> ScanOut:
    """Persist a queued scan, audit it, hand it to the worker, and return it."""
    # The insert/flush/audit/commit run on the event loop; hop them off so a
    # concurrent long writer holding the SQLite lock can't stall the loop inside
    # busy_timeout (CON-5). expire_on_commit=False keeps ``scan`` usable after.
    await run_in_threadpool(_persist_queued_scan, db, scan, actor=auth, ip=client_ip(request))
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

    # Enforce the size cap while reading so an oversized upload is never fully
    # materialized in memory before the check (API-4).
    data = await read_upload_capped(file, _MAX_SBOM_UPLOAD_BYTES, what="SBOM")
    if not data:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail="The SBOM file is empty.")
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


@router.get("", response_model=list[ScanSummaryOut])
def list_scans(
    _: AuthContext = Depends(_viewer),
    db: Session = Depends(get_db),
    scanner: Scanner | None = Query(default=None),
    scan_status: ScanStatus | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> list[ScanSummaryOut]:
    """List scans, newest first (basic filters; full history in Phase 4)."""
    # Eager-load tags to avoid an N+1 SELECT per row when the row reads them (API-1).
    stmt = (
        select(Scan)
        .options(selectinload(Scan.tag_rows))
        .order_by(Scan.created_at.desc(), Scan.id.desc())
    )
    if scanner is not None:
        stmt = stmt.where(Scan.scanner == scanner)
    if scan_status is not None:
        stmt = stmt.where(Scan.status == scan_status)
    scans = db.scalars(stmt.limit(limit).offset(offset)).all()
    return [ScanSummaryOut.model_validate(s) for s in scans]


@router.get("/history", response_model=ScanHistoryPage)
def list_history(
    _: AuthContext = Depends(_viewer),
    db: Session = Depends(get_db),
    filters: HistoryFilters = Depends(history_filters),
    sort: str = Query(default="created_at", description="Sort column."),
    order: str = Query(default="desc", pattern="^(asc|desc)$", description="Sort direction."),
    limit: int = Query(default=25, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> ScanHistoryPage:
    """Return a filtered, sorted, paginated page of scan history (docs/PLAN.md §4.4).

    Supports the full filter set — scanner, target type, target full-text search,
    status, date range, initiator, highest severity, severity-threshold presence,
    and tags — plus sorting and a total count for pagination.
    """
    if sort not in _SORT_COLUMNS:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown sort column '{sort}'.",
        )
    base = filters.apply(select(Scan))
    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0

    column = _SORT_COLUMNS[sort]
    direction = column.desc() if order == "desc" else column.asc()
    # A stable secondary key keeps pagination deterministic across equal values;
    # eager-load tags to avoid an N+1 SELECT per row when ScanOut reads them (API-1).
    stmt = (
        base.options(selectinload(Scan.tag_rows))
        .order_by(direction, Scan.id.desc())
        .limit(limit)
        .offset(offset)
    )
    scans = db.scalars(stmt).all()
    return ScanHistoryPage(total=total, items=[ScanSummaryOut.model_validate(s) for s in scans])


@router.get("/filter-options", response_model=FilterOptionsOut)
def history_filter_options(
    _: AuthContext = Depends(_viewer),
    db: Session = Depends(get_db),
) -> FilterOptionsOut:
    """List the distinct initiators and tags for populating history filters."""
    initiators = db.scalars(
        select(Scan.created_by_username)
        .where(Scan.created_by_username.is_not(None))
        .distinct()
        .order_by(Scan.created_by_username)
    ).all()
    tags = db.scalars(select(ScanTag.tag).distinct().order_by(ScanTag.tag)).all()
    return FilterOptionsOut(initiators=list(initiators), tags=list(tags))


@router.get("/export")
def export_history_view(
    fmt: ExportFormat = Query(default=ExportFormat.JSON, alias="format"),
    _: AuthContext = Depends(_viewer),
    db: Session = Depends(get_db),
    filters: HistoryFilters = Depends(history_filters),
) -> Response:
    """Export the filtered history result set as CSV, Markdown, or JSON.

    The export follows the same filters as the history view (newest first) and is
    capped at a generous row limit to keep a single download bounded.
    """
    base = filters.apply(select(Scan))
    # Count the full matching set so the export can flag when the cap truncated it
    # (APIR-4); the count query is cheap next to materializing thousands of rows.
    total = db.scalar(select(func.count()).select_from(base.subquery())) or 0
    stmt = (
        base
        # Every exporter reads scan.tags; eager-load them in one query instead
        # of one lazy SELECT per exported scan (the cap allows thousands).
        .options(selectinload(Scan.tag_rows))
        .order_by(Scan.created_at.desc(), Scan.id.desc())
        .limit(_MAX_HISTORY_EXPORT_SCANS)
    )
    scans = list(db.scalars(stmt).all())
    result = export_history(scans, fmt, filters=filters.as_metadata(), total=total)
    headers = {"Content-Disposition": f'attachment; filename="{result.filename}"'}
    if total > len(scans):
        # Machine-readable signal that works for every format, including CSV.
        headers["X-Scrye-Truncated"] = "true"
        headers["X-Scrye-Total"] = str(total)
    return Response(
        content=result.content,
        media_type=result.media_type,
        headers=headers,
    )


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


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(
    scan_id: int,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_operator),
    db: Session = Depends(get_db),
) -> Response:
    """Delete a completed scan and every trace of it (docs/PLAN.md §5, RBAC).

    Removing the ``scans`` row cascades — via the ORM relationships and the
    ``ON DELETE CASCADE`` foreign keys — to its findings, stored-artifact
    metadata, and tags, so the scan stops contributing to dashboard aggregates,
    history, and diffs. The raw artifact files on disk are removed afterwards.

    Only scans in a terminal state can be deleted; a queued or running scan must
    be canceled first (the worker still references it). Deletion requires the
    ``operator`` role and is CSRF-guarded.
    """
    scan = _get_scan_or_404(db, scan_id)
    if scan.status in (ScanStatus.QUEUED, ScanStatus.RUNNING):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=(
                f"Only completed scans can be deleted (status is '{scan.status.value}'); "
                "cancel the scan first."
            ),
        )

    record_audit(
        db,
        action="scan.deleted",
        actor=auth.user,
        ip=client_ip(request),
        target_type="scan",
        target_id=str(scan_id),
        details={
            "scanner": scan.scanner.value,
            "target_type": scan.target_type.value,
            "target": scan.target,
            "findings_count": scan.findings_count,
        },
    )
    # ORM delete cascades to findings/artifacts/tags (relationship + FK cascade).
    db.delete(scan)
    db.commit()
    # Remove the raw artifact files only after the rows are gone; an orphaned
    # directory would be harmless, a dangling row pointing at deleted bytes is not.
    remove_scan_artifacts(scan_id)
    logger.info("Deleted scan %d and all associated data.", scan_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


#: Finding columns the export/diff paths actually read. ``description`` (up to
#: 4 kB per row) is deliberately absent: neither the exporters nor the diff
#: serialize it, and fetching it for every finding of a large scan is the bulk
#: of the query's payload.
_REPORT_FINDING_COLUMNS = (
    Finding.scan_id,
    Finding.finding_class,
    Finding.severity,
    Finding.vuln_id,
    Finding.pkg_name,
    Finding.installed_version,
    Finding.fixed_version,
    Finding.title,
    Finding.location,
    Finding.primary_url,
)


def _scan_findings(db: Session, scan_id: int) -> list[Finding]:
    """Fetch a scan's findings for export/diff, ordered by id.

    Only the columns those paths read are selected (see
    :data:`_REPORT_FINDING_COLUMNS`); anything else stays lazily loadable.
    """
    return list(
        db.scalars(
            select(Finding)
            .options(load_only(*_REPORT_FINDING_COLUMNS))
            .where(Finding.scan_id == scan_id)
            .order_by(Finding.id)
        ).all()
    )


@router.get("/{scan_id}/export")
def export_scan_view(
    scan_id: int,
    fmt: ExportFormat = Query(default=ExportFormat.JSON, alias="format"),
    _: AuthContext = Depends(_viewer),
    db: Session = Depends(get_db),
) -> Response:
    """Export a single scan's findings as CSV, Markdown, or JSON (docs/PLAN.md §4.3)."""
    scan = _get_scan_or_404(db, scan_id)
    findings = _scan_findings(db, scan_id)
    result = export_scan(scan, findings, fmt)
    return Response(
        content=result.content,
        media_type=result.media_type,
        headers={"Content-Disposition": f'attachment; filename="{result.filename}"'},
    )


@router.get("/{scan_id}/diff/{other_scan_id}", response_model=ScanDiffOut)
def diff_scans(
    scan_id: int,
    other_scan_id: int,
    _: AuthContext = Depends(_viewer),
    db: Session = Depends(get_db),
) -> ScanDiffOut:
    """Diff two scans of the same target: new vs. fixed findings (docs/PLAN.md §4.4).

    ``scan_id`` is the base (older) scan and ``other_scan_id`` is the comparison
    (newer) scan. Both must share the same scanner and target so the diff is
    meaningful; ``added`` are findings new in the comparison scan and ``removed``
    are findings fixed since the base scan.
    """
    if scan_id == other_scan_id:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Cannot diff a scan against itself."
        )
    base = _get_scan_or_404(db, scan_id)
    compare = _get_scan_or_404(db, other_scan_id)
    # The target type is part of the identity: the same target string can name
    # unrelated things across types (image ref / filesystem path / uploaded SBOM
    # filename), and a cross-type diff would compare unrelated scans.
    if (
        base.scanner != compare.scanner
        or base.target_type != compare.target_type
        or base.target != compare.target
    ):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Scans must share the same scanner, target type, and target to be diffed.",
        )

    diff = diff_findings(_scan_findings(db, scan_id), _scan_findings(db, other_scan_id))
    return ScanDiffOut(
        base_scan_id=base.id,
        compare_scan_id=compare.id,
        target=base.target,
        scanner=base.scanner.value,
        added=[DiffFindingOut.model_validate(f) for f in diff.added],
        removed=[DiffFindingOut.model_validate(f) for f in diff.removed],
        unchanged_count=diff.unchanged_count,
        added_count=diff.added_count,
        removed_count=diff.removed_count,
        severity_delta=diff.severity_delta,
    )


@router.put("/{scan_id}/tags", response_model=ScanOut)
def set_scan_tags(
    scan_id: int,
    payload: ScanTagsIn,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_operator),
    db: Session = Depends(get_db),
) -> ScanOut:
    """Replace the full set of tags on a scan (docs/PLAN.md §4.4).

    Tags are free-form labels used to filter scan history. Setting them requires
    the ``operator`` role and is CSRF-guarded; the incoming list is trimmed,
    lowercased, and de-duplicated by the request schema.
    """
    scan = _get_scan_or_404(db, scan_id)
    existing = {row.tag: row for row in scan.tag_rows}
    desired = set(payload.tags)

    for tag, row in existing.items():
        if tag not in desired:
            db.delete(row)
    for tag in desired:
        if tag not in existing:
            db.add(ScanTag(scan_id=scan.id, tag=tag))

    record_audit(
        db,
        action="scan.tagged",
        actor=auth.user,
        ip=client_ip(request),
        target_type="scan",
        target_id=str(scan_id),
        details={"tags": sorted(desired)},
    )
    db.commit()
    db.refresh(scan)
    return ScanOut.model_validate(scan)
