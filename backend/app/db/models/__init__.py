"""ORM models. Import every model module here so ``Base.metadata`` is complete."""

from app.db.models.api_token import ApiToken
from app.db.models.app_setting import AppSetting
from app.db.models.audit import AuditLog
from app.db.models.auth_session import AuthSession
from app.db.models.backup import BACKUP_SCHEDULE_ID, Backup, BackupKind, BackupSchedule
from app.db.models.docker_environment import DockerEnvironment
from app.db.models.filter_preset import FilterPreset
from app.db.models.git_credential import GitCredential, GitProvider
from app.db.models.notification import (
    SECRET_OPTIONAL_TYPES,
    NotificationChannel,
    NotificationType,
)
from app.db.models.oidc import OIDC_CONFIG_ID, OidcConfig, OidcIdentity, OidcLoginFlow
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
    ScanTag,
    Severity,
    TargetType,
)
from app.db.models.user import ROLE_RANK, Role, User

__all__ = [
    "BACKUP_SCHEDULE_ID",
    "CREDENTIAL_HELPERS",
    "OIDC_CONFIG_ID",
    "ROLE_RANK",
    "SECRET_BEARING_AUTH_TYPES",
    "SECRET_OPTIONAL_TYPES",
    "SEVERITY_RANK",
    "ApiToken",
    "AppSetting",
    "Artifact",
    "ArtifactKind",
    "AuditLog",
    "AuthSession",
    "Backup",
    "BackupKind",
    "BackupSchedule",
    "DockerEnvironment",
    "FilterPreset",
    "Finding",
    "FindingClass",
    "GitCredential",
    "GitProvider",
    "NotificationChannel",
    "NotificationType",
    "OidcConfig",
    "OidcIdentity",
    "OidcLoginFlow",
    "Registry",
    "RegistryAuthType",
    "Role",
    "Scan",
    "ScanStatus",
    "ScanTag",
    "Scanner",
    "Severity",
    "TargetType",
    "User",
]
