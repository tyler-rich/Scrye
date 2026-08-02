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
    NotificationEvent,
    NotificationType,
)
from app.db.models.oidc import (
    FLOW_PURPOSE_LINK,
    FLOW_PURPOSE_LOGIN,
    OIDC_CONFIG_ID,
    OidcConfig,
    OidcIdentity,
    OidcLoginFlow,
)
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
from app.db.models.scan_schedule import ScanSchedule
from app.db.models.trivy_policy import (
    VEX_FILE_SUFFIX,
    TrivyIgnoreRule,
    VexDocument,
    VexFormat,
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
    "VEX_FILE_SUFFIX",
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
    "NotificationEvent",
    "NotificationType",
    "OidcConfig",
    "OidcIdentity",
    "OidcLoginFlow",
    "FLOW_PURPOSE_LOGIN",
    "FLOW_PURPOSE_LINK",
    "Registry",
    "RegistryAuthType",
    "Role",
    "Scan",
    "ScanSchedule",
    "ScanStatus",
    "ScanTag",
    "Scanner",
    "Severity",
    "TargetType",
    "TrivyIgnoreRule",
    "User",
    "VexDocument",
    "VexFormat",
]
