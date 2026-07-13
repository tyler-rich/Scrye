"""Trivy VEX document and ignore-rule management (docs/PLAN.md §4.1/§4.5, Phase 6).

Admin-managed policy that shapes Trivy scan results: VEX documents (used to mark
vulnerabilities not-affected) and structured ``.trivyignore`` rules. Both are
non-secret policy data applied to every Trivy scan when enabled (materialized
into tmpfs at scan time — see :mod:`app.scanners.trivy_policy`).

RBAC: managing policy is ``admin`` (it affects all users' scan results, like
settings); reading it requires ``viewer``. Writes are CSRF-guarded.
"""

from __future__ import annotations

import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.schema_types import UtcDatetime
from app.auth.deps import AuthContext, client_ip, require_csrf, require_role
from app.core.audit import record_audit
from app.core.timeutil import to_naive_utc
from app.db.models import Role, TrivyIgnoreRule, VexDocument, VexFormat
from app.db.session import get_db

router = APIRouter(prefix="/trivy", tags=["trivy-policy"])

_viewer = require_role(Role.VIEWER)
_admin = require_role(Role.ADMIN)

#: Cap on a stored VEX document body (VEX docs are small JSON statements).
_MAX_VEX_BYTES = 512 * 1024


# --- VEX documents -----------------------------------------------------------


class VexDocumentOut(BaseModel):
    """Read view of a stored VEX document."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    enabled: bool
    format: VexFormat
    content: str
    created_by_username: str | None
    created_at: UtcDatetime
    updated_at: UtcDatetime


class VexDocumentIn(BaseModel):
    """Payload to create or replace a VEX document."""

    name: str = Field(min_length=1, max_length=128)
    format: VexFormat
    content: str = Field(min_length=1, max_length=_MAX_VEX_BYTES)
    enabled: bool = True


def _validate_vex_content(content: str) -> None:
    """Reject a VEX body that is not valid JSON (all supported formats are JSON)."""
    try:
        json.loads(content)
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="VEX document content must be valid JSON.",
        ) from exc


def _get_vex_or_404(db: Session, vex_id: int) -> VexDocument:
    """Fetch a VEX document by id or raise 404."""
    doc = db.get(VexDocument, vex_id)
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="VEX document not found.")
    return doc


@router.get("/vex-documents", response_model=list[VexDocumentOut])
def list_vex_documents(
    _: AuthContext = Depends(_viewer),
    db: Session = Depends(get_db),
) -> list[VexDocumentOut]:
    """List stored VEX documents."""
    rows = db.scalars(select(VexDocument).order_by(VexDocument.name)).all()
    return [VexDocumentOut.model_validate(r) for r in rows]


@router.post("/vex-documents", response_model=VexDocumentOut, status_code=status.HTTP_201_CREATED)
def create_vex_document(
    payload: VexDocumentIn,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> VexDocumentOut:
    """Create a VEX document applied to Trivy scans when enabled."""
    if db.scalar(select(VexDocument).where(VexDocument.name == payload.name)) is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail="A VEX document with that name exists."
        )
    _validate_vex_content(payload.content)
    doc = VexDocument(
        name=payload.name,
        format=payload.format,
        content=payload.content,
        enabled=payload.enabled,
        created_by_id=auth.user.id,
        created_by_username=auth.user.username,
    )
    db.add(doc)
    db.flush()
    record_audit(
        db,
        action="trivy.vex_created",
        actor=auth.user,
        ip=client_ip(request),
        target_type="vex_document",
        target_id=str(doc.id),
        details={"name": doc.name, "format": doc.format.value},
    )
    db.commit()
    return VexDocumentOut.model_validate(doc)


@router.put("/vex-documents/{vex_id}", response_model=VexDocumentOut)
def update_vex_document(
    vex_id: int,
    payload: VexDocumentIn,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> VexDocumentOut:
    """Replace a VEX document's definition."""
    doc = _get_vex_or_404(db, vex_id)
    clash = db.scalar(
        select(VexDocument).where(VexDocument.name == payload.name, VexDocument.id != vex_id)
    )
    if clash is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail="A VEX document with that name exists."
        )
    _validate_vex_content(payload.content)
    doc.name = payload.name
    doc.format = payload.format
    doc.content = payload.content
    doc.enabled = payload.enabled
    record_audit(
        db,
        action="trivy.vex_updated",
        actor=auth.user,
        ip=client_ip(request),
        target_type="vex_document",
        target_id=str(doc.id),
        details={"name": doc.name},
    )
    db.commit()
    return VexDocumentOut.model_validate(doc)


@router.delete("/vex-documents/{vex_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_vex_document(
    vex_id: int,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> Response:
    """Delete a VEX document."""
    doc = _get_vex_or_404(db, vex_id)
    record_audit(
        db,
        action="trivy.vex_deleted",
        actor=auth.user,
        ip=client_ip(request),
        target_type="vex_document",
        target_id=str(doc.id),
        details={"name": doc.name},
    )
    db.delete(doc)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Ignore rules ------------------------------------------------------------


class IgnoreRuleOut(BaseModel):
    """Read view of a structured Trivy ignore rule."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    vuln_id: str
    reason: str | None
    expires_at: UtcDatetime | None
    enabled: bool
    created_by_username: str | None
    created_at: UtcDatetime
    updated_at: UtcDatetime


class IgnoreRuleIn(BaseModel):
    """Payload to create or replace a Trivy ignore rule."""

    vuln_id: str = Field(min_length=1, max_length=128)
    reason: str | None = Field(default=None, max_length=512)
    expires_at: datetime | None = None
    enabled: bool = True

    @field_validator("expires_at")
    @classmethod
    def _normalize_expires_at(cls, value: datetime | None) -> datetime | None:
        """Store ``expires_at`` as naive UTC so a client offset isn't dropped.

        The ``DateTime`` column is naive-UTC (``core/timeutil``); without this an
        aware timestamp like ``2026-08-01T00:00:00+09:00`` would persist its
        wall-clock fields verbatim, expiring the rule 9 hours late.
        """
        return to_naive_utc(value)


def _get_rule_or_404(db: Session, rule_id: int) -> TrivyIgnoreRule:
    """Fetch an ignore rule by id or raise 404."""
    rule = db.get(TrivyIgnoreRule, rule_id)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Ignore rule not found.")
    return rule


@router.get("/ignore-rules", response_model=list[IgnoreRuleOut])
def list_ignore_rules(
    _: AuthContext = Depends(_viewer),
    db: Session = Depends(get_db),
) -> list[IgnoreRuleOut]:
    """List structured Trivy ignore rules."""
    rows = db.scalars(select(TrivyIgnoreRule).order_by(TrivyIgnoreRule.vuln_id)).all()
    return [IgnoreRuleOut.model_validate(r) for r in rows]


@router.post("/ignore-rules", response_model=IgnoreRuleOut, status_code=status.HTTP_201_CREATED)
def create_ignore_rule(
    payload: IgnoreRuleIn,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> IgnoreRuleOut:
    """Create a Trivy ignore rule applied to scans when enabled and unexpired."""
    rule = TrivyIgnoreRule(
        vuln_id=payload.vuln_id.strip(),
        reason=payload.reason,
        expires_at=payload.expires_at,
        enabled=payload.enabled,
        created_by_id=auth.user.id,
        created_by_username=auth.user.username,
    )
    db.add(rule)
    db.flush()
    record_audit(
        db,
        action="trivy.ignore_created",
        actor=auth.user,
        ip=client_ip(request),
        target_type="trivy_ignore_rule",
        target_id=str(rule.id),
        details={"vuln_id": rule.vuln_id},
    )
    db.commit()
    return IgnoreRuleOut.model_validate(rule)


@router.put("/ignore-rules/{rule_id}", response_model=IgnoreRuleOut)
def update_ignore_rule(
    rule_id: int,
    payload: IgnoreRuleIn,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> IgnoreRuleOut:
    """Replace a Trivy ignore rule's definition."""
    rule = _get_rule_or_404(db, rule_id)
    rule.vuln_id = payload.vuln_id.strip()
    rule.reason = payload.reason
    rule.expires_at = payload.expires_at
    rule.enabled = payload.enabled
    record_audit(
        db,
        action="trivy.ignore_updated",
        actor=auth.user,
        ip=client_ip(request),
        target_type="trivy_ignore_rule",
        target_id=str(rule.id),
        details={"vuln_id": rule.vuln_id},
    )
    db.commit()
    return IgnoreRuleOut.model_validate(rule)


@router.delete("/ignore-rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_ignore_rule(
    rule_id: int,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> Response:
    """Delete a Trivy ignore rule."""
    rule = _get_rule_or_404(db, rule_id)
    record_audit(
        db,
        action="trivy.ignore_deleted",
        actor=auth.user,
        ip=client_ip(request),
        target_type="trivy_ignore_rule",
        target_id=str(rule.id),
        details={"vuln_id": rule.vuln_id},
    )
    db.delete(rule)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
