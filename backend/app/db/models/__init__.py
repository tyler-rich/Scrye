"""ORM models. Import every model module here so ``Base.metadata`` is complete."""

from app.db.models.audit import AuditLog
from app.db.models.auth_session import AuthSession
from app.db.models.docker_environment import DockerEnvironment
from app.db.models.git_credential import GitCredential, GitProvider
from app.db.models.registry import (
    CREDENTIAL_HELPERS,
    SECRET_BEARING_AUTH_TYPES,
    Registry,
    RegistryAuthType,
)
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
    "CREDENTIAL_HELPERS",
    "ROLE_RANK",
    "SECRET_BEARING_AUTH_TYPES",
    "SEVERITY_RANK",
    "Artifact",
    "ArtifactKind",
    "AuditLog",
    "AuthSession",
    "DockerEnvironment",
    "Finding",
    "FindingClass",
    "GitCredential",
    "GitProvider",
    "Registry",
    "RegistryAuthType",
    "Role",
    "Scan",
    "ScanStatus",
    "Scanner",
    "Severity",
    "TargetType",
    "User",
]
