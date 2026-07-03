"""General, authentication, and scanner settings, plus About/health (§4.5).

Reading settings is available to any authenticated user (so the SPA can reflect
the instance name and policy); mutating them is admin-only and CSRF-guarded.
Disabling local login is refused unless OIDC is enabled, so an admin cannot lock
everyone out. The About endpoint reports app/scanner versions and basic health
without exposing any secret configuration.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import __version__
from app.api.health import healthz
from app.auth.deps import AuthContext, client_ip, require_auth, require_csrf, require_role
from app.core.app_settings import (
    AuthSettings,
    GeneralSettings,
    RetentionSettings,
    ScannerSettings,
    SettingsService,
)
from app.core.audit import record_audit
from app.core.system_info import host_info, scanner_versions
from app.db.models import OIDC_CONFIG_ID, OidcConfig, Role, Scan, User
from app.db.session import get_db

router = APIRouter(prefix="/settings", tags=["settings"])

_any_user = require_auth
_admin = require_role(Role.ADMIN)


class ScannerInfoOut(BaseModel):
    """Availability/version of one bundled scanner."""

    name: str
    available: bool
    version: str | None
    detail: str | None = None


class AboutOut(BaseModel):
    """About/health summary shown on the settings About tab."""

    app_name: str
    version: str
    status: str
    database: str
    python_version: str
    platform: str
    user_count: int
    scan_count: int
    oidc_enabled: bool
    scanners: list[ScannerInfoOut]


@router.get("/general", response_model=GeneralSettings)
def get_general(
    _: AuthContext = Depends(_any_user),
    db: Session = Depends(get_db),
) -> GeneralSettings:
    """Return general instance settings."""
    return SettingsService(db).general()


@router.put("/general", response_model=GeneralSettings)
def update_general(
    payload: GeneralSettings,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> GeneralSettings:
    """Update general instance settings (admin)."""
    value = SettingsService(db).set_general(payload, username=auth.user.username)
    record_audit(db, action="settings.general_updated", actor=auth.user, ip=client_ip(request))
    db.commit()
    return value


@router.get("/authentication", response_model=AuthSettings)
def get_authentication(
    _: AuthContext = Depends(_any_user),
    db: Session = Depends(get_db),
) -> AuthSettings:
    """Return the authentication policy settings."""
    return SettingsService(db).auth()


@router.put("/authentication", response_model=AuthSettings)
def update_authentication(
    payload: AuthSettings,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> AuthSettings:
    """Update the authentication policy (admin).

    Disabling local login requires OIDC to be enabled, so the instance always
    retains at least one working sign-in path.
    """
    if not payload.local_login_enabled:
        oidc = db.get(OidcConfig, OIDC_CONFIG_ID)
        if oidc is None or not oidc.enabled:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail="Cannot disable local login while OIDC is not enabled.",
            )
    value = SettingsService(db).set_auth(payload, username=auth.user.username)
    record_audit(
        db,
        action="settings.authentication_updated",
        actor=auth.user,
        ip=client_ip(request),
        details={
            "local_login_enabled": value.local_login_enabled,
            "mfa_policy": value.mfa_policy.value,
        },
    )
    db.commit()
    return value


@router.get("/scanners", response_model=ScannerSettings)
def get_scanners(
    _: AuthContext = Depends(_any_user),
    db: Session = Depends(get_db),
) -> ScannerSettings:
    """Return the scanner default settings."""
    return SettingsService(db).scanners()


@router.put("/scanners", response_model=ScannerSettings)
def update_scanners(
    payload: ScannerSettings,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> ScannerSettings:
    """Update the scanner default options, thresholds, and ignore rules (admin)."""
    value = SettingsService(db).set_scanners(payload, username=auth.user.username)
    record_audit(db, action="settings.scanners_updated", actor=auth.user, ip=client_ip(request))
    db.commit()
    return value


@router.get("/retention", response_model=RetentionSettings)
def get_retention(
    _: AuthContext = Depends(_any_user),
    db: Session = Depends(get_db),
) -> RetentionSettings:
    """Return the result-retention policy settings."""
    return SettingsService(db).retention()


@router.put("/retention", response_model=RetentionSettings)
def update_retention(
    payload: RetentionSettings,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> RetentionSettings:
    """Update the result-retention policy (admin).

    When enabled, raw scan artifacts (scanner JSON + SBOMs) of scans older than
    ``max_age_days`` are pruned by the maintenance scheduler; the scan rows and
    their normalized findings are kept.
    """
    value = SettingsService(db).set_retention(payload, username=auth.user.username)
    record_audit(
        db,
        action="settings.retention_updated",
        actor=auth.user,
        ip=client_ip(request),
        details={"enabled": value.enabled, "max_age_days": value.max_age_days},
    )
    db.commit()
    return value


@router.get("/about", response_model=AboutOut)
async def get_about(
    _: AuthContext = Depends(_any_user),
    db: Session = Depends(get_db),
) -> AboutOut:
    """Return the About/health summary (app + scanner versions, basic counts)."""
    health = healthz(db)
    general = SettingsService(db).general()
    oidc = db.get(OidcConfig, OIDC_CONFIG_ID)
    user_count = db.scalar(select(func.count()).select_from(User)) or 0
    scan_count = db.scalar(select(func.count()).select_from(Scan)) or 0
    scanners = [ScannerInfoOut(**info.__dict__) for info in await scanner_versions()]
    host = host_info()
    return AboutOut(
        app_name=general.instance_name,
        version=__version__,
        status=health.status,
        database=health.database,
        python_version=host["python_version"],
        platform=host["platform"],
        user_count=user_count,
        scan_count=scan_count,
        oidc_enabled=bool(oidc and oidc.enabled),
        scanners=scanners,
    )
