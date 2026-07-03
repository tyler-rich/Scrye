"""ORM models. Import every model module here so ``Base.metadata`` is complete."""

from app.db.models.audit import AuditLog
from app.db.models.auth_session import AuthSession
from app.db.models.scan import (
    SEVERITY_RANK,
    Artifact,
    ArtifactKind,
    Finding,
    FindingClass,
    Scan,
    Scanner,
    ScanStatus,
    Severity,
    TargetType,
)
from app.db.models.user import ROLE_RANK, Role, User

__all__ = [
    "ROLE_RANK",
    "SEVERITY_RANK",
    "Artifact",
    "ArtifactKind",
    "AuditLog",
    "AuthSession",
    "Finding",
    "FindingClass",
    "Role",
    "Scan",
    "ScanStatus",
    "Scanner",
    "Severity",
    "TargetType",
    "User",
]
