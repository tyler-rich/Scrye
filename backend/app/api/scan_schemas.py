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
#: Syft SBOM output formats a caller may request.
SbomFormat = Literal["cyclonedx-json", "spdx-json", "syft-json"]


class ScanCreateIn(BaseModel):
    """Request payload to launch an image, repository, or filesystem scan.

    Target support (docs/PLAN.md §4): ``image`` (Trivy or Grype), ``repository``
    (Trivy), and ``filesystem`` (Grype). ``sbom`` targets are launched via the
    dedicated upload endpoint, not this JSON body. Trivy honors scanner
    selection, severity filtering, and ``ignore_unfixed``; Grype (vulnerabilities
    only) ignores those knobs. A registry / git credential is referenced by id
    and resolved (and decrypted) only at scan time.
    """

    scanner: Scanner
    target_type: TargetType = TargetType.IMAGE
    target: str = Field(
        min_length=1, max_length=512, description="Image ref, repo URL, or filesystem path."
    )
    trivy_scanners: list[TrivyScannerName] | None = Field(
        default=None, description="Trivy scanner selection; null means all."
    )
    trivy_severity: list[TrivySeverity] | None = Field(
        default=None, description="Trivy severity filter; null means all."
    )
    ignore_unfixed: bool = Field(
        default=False, description="Trivy: report only vulnerabilities with a known fix."
    )
    registry_id: int | None = Field(
        default=None, description="Registry credential for a private image (image targets)."
    )
    git_credential_id: int | None = Field(
        default=None, description="Git credential for a private repo (repository targets)."
    )
    branch: str | None = Field(
        default=None, max_length=255, description="Repo branch to check out."
    )
    commit: str | None = Field(
        default=None, max_length=128, description="Repo commit to check out."
    )
    tag: str | None = Field(default=None, max_length=255, description="Repo tag to check out.")
    generate_sbom: bool = Field(
        default=False, description="Also generate a Syft SBOM artifact (image/filesystem)."
    )
    sbom_format: SbomFormat | None = Field(
        default=None, description="SBOM format when generate_sbom is set; null means default."
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
        """Build the stored ``options`` dict for the scanner and target type."""
        options: dict[str, object] = {}
        if self.scanner is Scanner.TRIVY:
            options["scanners"] = self.trivy_scanners
            options["severity"] = self.trivy_severity
            options["ignore_unfixed"] = self.ignore_unfixed

        if self.target_type is TargetType.IMAGE:
            if self.registry_id is not None:
                options["registry_id"] = self.registry_id
            options["generate_sbom"] = self.generate_sbom
            if self.generate_sbom and self.sbom_format:
                options["sbom_format"] = self.sbom_format
        elif self.target_type is TargetType.REPOSITORY:
            if self.git_credential_id is not None:
                options["git_credential_id"] = self.git_credential_id
            for key, value in (("branch", self.branch), ("commit", self.commit), ("tag", self.tag)):
                if value:
                    options[key] = value.strip()
        elif self.target_type is TargetType.FILESYSTEM:
            options["generate_sbom"] = self.generate_sbom
            if self.generate_sbom and self.sbom_format:
                options["sbom_format"] = self.sbom_format
        return options


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
    tags: list[str] = []
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
