"""Audit-log listing (RBAC: admin only)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.schema_types import UtcDatetime
from app.auth.deps import AuthContext, require_role
from app.db.models import AuditLog, Role
from app.db.session import get_db

router = APIRouter(prefix="/audit", tags=["audit"])

_admin = require_role(Role.ADMIN)


class AuditEntryOut(BaseModel):
    """One audit-log entry."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: UtcDatetime
    actor_id: int | None
    actor_username: str | None
    action: str
    target_type: str | None
    target_id: str | None
    ip: str | None
    details: dict[str, Any] | None


class AuditPageOut(BaseModel):
    """A page of audit entries, newest first."""

    total: int
    entries: list[AuditEntryOut]


@router.get("", response_model=AuditPageOut)
def list_audit_entries(
    auth: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> AuditPageOut:
    """Return audit entries newest-first with a total count."""
    total = db.scalar(select(func.count()).select_from(AuditLog)) or 0
    rows = db.scalars(
        select(AuditLog)
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return AuditPageOut(total=total, entries=[AuditEntryOut.model_validate(r) for r in rows])
