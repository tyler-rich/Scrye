"""Typed runtime settings backed by the ``settings`` table (docs/PLAN.md §4.5).

Admins edit a handful of grouped, **non-secret** settings at runtime: general
instance options, the authentication policy (local-login toggle, MFA policy),
and scanner defaults/thresholds/ignore rules. Each group is one row in the
``settings`` table whose JSON value is validated against a Pydantic model here,
so the defaults and the persisted shape can never drift.

These are the single source of truth for the group defaults; the API layer is a
thin read/update wrapper. Secret-bearing configuration lives in its own
field-encrypted columns, never in this store.
"""

from __future__ import annotations

import enum

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.timeutil import utcnow
from app.db.models import AppSetting

#: Canonical severity ladder Trivy/Grype understand, used as the scan default.
ALL_SEVERITIES: tuple[str, ...] = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")


class MfaPolicy(enum.StrEnum):
    """How strictly TOTP MFA is required across accounts."""

    OPTIONAL = "optional"
    REQUIRED_ADMIN = "required_admin"
    REQUIRED_ALL = "required_all"


class GeneralSettings(BaseModel):
    """General instance settings."""

    instance_name: str = Field(default="Scrye", min_length=1, max_length=64)
    #: Free-form note shown on the About tab (e.g. environment label).
    admin_note: str = Field(default="", max_length=500)


class AuthSettings(BaseModel):
    """Authentication policy settings."""

    #: When false, username/password login is refused (OIDC only). Guarded so it
    #: cannot be disabled unless OIDC is enabled (see the settings API).
    local_login_enabled: bool = True
    mfa_policy: MfaPolicy = MfaPolicy.OPTIONAL


class ScannerSettings(BaseModel):
    """Scanner default options, thresholds, and ignore rules."""

    default_severities: list[str] = Field(default_factory=lambda: list(ALL_SEVERITIES))
    default_ignore_unfixed: bool = False
    #: Global ``.trivyignore`` rules applied to Trivy scans (CVE ids / paths).
    trivyignore: str = Field(default="", max_length=20000)
    #: Global Grype ignore rules (YAML) applied to Grype scans.
    grype_ignore: str = Field(default="", max_length=20000)
    #: Whether the scanner vulnerability DBs are refreshed on a schedule.
    auto_update_db: bool = True
    db_update_interval_hours: int = Field(default=24, ge=1, le=720)


class RetentionSettings(BaseModel):
    """Result-retention policy for pruning old raw scan artifacts (Phase 6).

    Retention prunes the large **raw** artifacts (scanner JSON + SBOMs) of scans
    older than ``max_age_days`` while keeping the scan row and its normalized
    findings, so history and trends stay intact but disk usage is bounded.
    """

    enabled: bool = False
    #: Prune raw artifacts of scans older than this many days (min 1).
    max_age_days: int = Field(default=90, ge=1, le=3650)


#: Setting group keys used as ``settings.key`` values.
_KEY_GENERAL = "general"
_KEY_AUTH = "authentication"
_KEY_SCANNERS = "scanners"
_KEY_RETENTION = "retention"


class SettingsService:
    """Read/update the grouped runtime settings with validation and defaults."""

    def __init__(self, db: Session) -> None:
        """Bind the service to a database session."""
        self._db = db

    def _read(self, key: str) -> dict:
        """Return the stored JSON object for a group, or an empty dict."""
        row = self._db.get(AppSetting, key)
        if row is None or not isinstance(row.value, dict):
            return {}
        return row.value

    def _write(self, key: str, value: dict, *, username: str | None) -> None:
        """Upsert the JSON object for a group (caller commits)."""
        row = self._db.get(AppSetting, key)
        if row is None:
            row = AppSetting(key=key)
            self._db.add(row)
        row.value = value
        row.updated_at = utcnow()
        row.updated_by_username = username

    def general(self) -> GeneralSettings:
        """Return the general settings (defaults merged over stored values)."""
        return GeneralSettings.model_validate(self._read(_KEY_GENERAL))

    def auth(self) -> AuthSettings:
        """Return the authentication policy settings."""
        return AuthSettings.model_validate(self._read(_KEY_AUTH))

    def scanners(self) -> ScannerSettings:
        """Return the scanner default settings."""
        return ScannerSettings.model_validate(self._read(_KEY_SCANNERS))

    def retention(self) -> RetentionSettings:
        """Return the result-retention policy settings."""
        return RetentionSettings.model_validate(self._read(_KEY_RETENTION))

    def set_general(self, value: GeneralSettings, *, username: str | None) -> GeneralSettings:
        """Persist general settings and return the stored value."""
        self._write(_KEY_GENERAL, value.model_dump(mode="json"), username=username)
        return value

    def set_auth(self, value: AuthSettings, *, username: str | None) -> AuthSettings:
        """Persist authentication settings and return the stored value."""
        self._write(_KEY_AUTH, value.model_dump(mode="json"), username=username)
        return value

    def set_scanners(self, value: ScannerSettings, *, username: str | None) -> ScannerSettings:
        """Persist scanner settings and return the stored value."""
        self._write(_KEY_SCANNERS, value.model_dump(mode="json"), username=username)
        return value

    def set_retention(self, value: RetentionSettings, *, username: str | None) -> RetentionSettings:
        """Persist result-retention settings and return the stored value."""
        self._write(_KEY_RETENTION, value.model_dump(mode="json"), username=username)
        return value
