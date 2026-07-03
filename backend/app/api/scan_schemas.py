"""API schemas for scans, findings, and artifacts.

Image references and options only — these carry no secret material. Registry
credentials for private images arrive in Phase 3 and are handled separately
(write-only, field-encrypted).
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.db.models import (
    ArtifactKind,
    FindingClass,
    Scanner,
    ScanStatus,
    Severity,
    TargetType,
)

#: Trivy scanner tokens a caller may select (default: all).
TrivyScannerName = Literal["vuln", "misconfig", "secret", "license"]
#: Trivy severity tokens a caller may filter to (default: all).
TrivySeverity = Literal["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


class ScanCreateIn(BaseModel):
    """Request payload to launch a scan.

    Phase 2 supports ``image`` targets for both scanners. Trivy honors scanner
    selection, severity filtering, and ``ignore_unfixed``; Grype (vulnerabilities
    only) ignores those knobs.
    """

    scanner: Scanner
    target_type: TargetType = TargetType.IMAGE
    target: str = Field(min_length=1, max_length=512, description="Image reference to scan.")
    trivy_scanners: list[TrivyScannerName] | None = Field(
        default=None, description="Trivy scanner selection; null means all."
    )
    trivy_severity: list[TrivySeverity] | None = Field(
        default=None, description="Trivy severity filter; null means all."
    )
    ignore_unfixed: bool = Field(
        default=False, description="Trivy: report only vulnerabilities with a known fix."
    )

    @field_validator("target")
    @classmethod
    def _strip_target(cls, value: str) -> str:
        """Trim surrounding whitespace and reject an empty reference."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("Target must not be empty.")
        return stripped

    def to_options(self) -> dict[str, object]:
        """Build the stored ``options`` dict relevant to the chosen scanner."""
        if self.scanner is Scanner.TRIVY:
            return {
                "scanners": self.trivy_scanners,
                "severity": self.trivy_severity,
                "ignore_unfixed": self.ignore_unfixed,
            }
        return {}


class ScanOut(BaseModel):
    """Read view of a scan (summary and detail share this shape)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    scanner: Scanner
    target_type: TargetType
    target: str
    status: ScanStatus
    options: dict
    severity_counts: dict[str, int]
    highest_severity: Severity | None
    findings_count: int
    scanner_version: str | None
    error: str | None
    created_by_username: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class FindingOut(BaseModel):
    """Read view of a single normalized finding."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    finding_class: FindingClass
    severity: Severity
    vuln_id: str | None
    pkg_name: str | None
    installed_version: str | None
    fixed_version: str | None
    title: str | None
    description: str | None
    location: str | None
    primary_url: str | None


class FindingsPage(BaseModel):
    """A page of findings for a scan."""

    total: int
    items: list[FindingOut]


class ArtifactOut(BaseModel):
    """Read view of a stored artifact (metadata only; bytes via download)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    kind: ArtifactKind
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    created_at: datetime
