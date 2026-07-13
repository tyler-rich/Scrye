"""Scan, finding, and artifact models (docs/ARCHIVE.md §7).

A ``Scan`` is one orchestrated run of a scanner (Trivy or Grype) against a
target. Its raw scanner output is persisted verbatim as an :class:`Artifact`
(the source of truth), and parsed into normalized :class:`Finding` rows for
uniform display across scanners. No secret material is stored on any of these
tables — image references and options only.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.timeutil import utcnow
from app.db.base import Base


class Scanner(enum.StrEnum):
    """Supported scanner engines."""

    TRIVY = "trivy"
    GRYPE = "grype"


class TargetType(enum.StrEnum):
    """Kinds of scan targets.

    Phase 2 implements ``IMAGE`` only; repository/filesystem/SBOM targets are
    added in Phase 3 (docs/ARCHIVE.md §12).
    """

    IMAGE = "image"
    REPOSITORY = "repository"
    FILESYSTEM = "filesystem"
    SBOM = "sbom"


class ScanStatus(enum.StrEnum):
    """Lifecycle states of a scan."""

    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELED = "canceled"


class FindingClass(enum.StrEnum):
    """The category a normalized finding belongs to."""

    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    SECRET = "secret"
    LICENSE = "license"


class Severity(enum.StrEnum):
    """Normalized severity, shared across Trivy and Grype (highest → lowest)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"
    UNKNOWN = "unknown"


#: Ordering used to compute the highest severity of a scan (higher = worse).
SEVERITY_RANK: dict[Severity, int] = {
    Severity.UNKNOWN: 0,
    Severity.NEGLIGIBLE: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}


def _enum_column(enum_cls: type[enum.Enum], length: int) -> Enum:
    """Build a stored-as-string SQLAlchemy Enum column type for ``enum_cls``."""
    return Enum(
        enum_cls,
        native_enum=False,
        length=length,
        values_callable=lambda e: [m.value for m in e],
    )


class Scan(Base):
    """One scanner run against a single target."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    scanner: Mapped[Scanner] = mapped_column(_enum_column(Scanner, 16))
    target_type: Mapped[TargetType] = mapped_column(_enum_column(TargetType, 16))
    target: Mapped[str] = mapped_column(String(512))
    status: Mapped[ScanStatus] = mapped_column(
        _enum_column(ScanStatus, 16), default=ScanStatus.QUEUED, index=True
    )
    #: Scan-time options (scanner selection, severity filter, ignore-unfixed, ...).
    options: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    #: Aggregate per-severity finding counts, e.g. {"critical": 3, "high": 7}.
    severity_counts: Mapped[dict[str, int]] = mapped_column(JSON, default=dict)
    highest_severity: Mapped[Severity | None] = mapped_column(
        _enum_column(Severity, 16), nullable=True
    )
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    scanner_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    #: Failure detail when ``status == FAILED`` (never contains secret material).
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    #: Denormalized initiator username so history stays meaningful after deletion.
    created_by_username: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    findings: Mapped[list[Finding]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    artifacts: Mapped[list[Artifact]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    tag_rows: Mapped[list[ScanTag]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )

    __table_args__ = (Index("ix_scans_scanner_status_created", "scanner", "status", "created_at"),)

    @property
    def tags(self) -> list[str]:
        """Return this scan's labels as a sorted list of strings (history filter)."""
        return sorted(row.tag for row in self.tag_rows)

    @property
    def has_error(self) -> bool:
        """Whether this scan recorded an error message.

        Lets list/summary views signal a failure without shipping the unbounded
        ``error`` text they never render (APIR-9).
        """
        return bool(self.error)


class ScanTag(Base):
    """A free-form label attached to a scan for history filtering (docs/ARCHIVE.md §4.4).

    Tags live in their own table (rather than a JSON column on ``scans``) so the
    history view can filter by tag with an indexed SQL predicate and enumerate
    the distinct tag set for the filter UI.
    """

    __tablename__ = "scan_tags"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    tag: Mapped[str] = mapped_column(String(64))

    scan: Mapped[Scan] = relationship(back_populates="tag_rows")

    __table_args__ = (
        UniqueConstraint("scan_id", "tag", name="uq_scan_tags_scan_tag"),
        Index("ix_scan_tags_tag", "tag"),
    )


class Finding(Base):
    """One normalized finding parsed from a scanner's raw output."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    finding_class: Mapped[FindingClass] = mapped_column(_enum_column(FindingClass, 20))
    severity: Mapped[Severity] = mapped_column(_enum_column(Severity, 16))
    #: Vulnerability/rule identifier (CVE, GHSA, Trivy check ID, secret rule ID).
    vuln_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    pkg_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    installed_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    fixed_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    title: Mapped[str | None] = mapped_column(String(512), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: Where the finding lives (image target/class, file path, code location).
    location: Mapped[str | None] = mapped_column(String(512), nullable=True)
    primary_url: Mapped[str | None] = mapped_column(String(512), nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="findings")

    __table_args__ = (Index("ix_findings_scan_severity_vuln", "scan_id", "severity", "vuln_id"),)


class ArtifactKind(enum.StrEnum):
    """Kinds of stored scan artifacts."""

    RAW_TRIVY_JSON = "raw_trivy_json"
    RAW_GRYPE_JSON = "raw_grype_json"
    SBOM = "sbom"


class Artifact(Base):
    """A file produced by a scan (raw scanner JSON, SBOM), stored on disk.

    The database keeps metadata + a checksum; the bytes live under the
    configured artifacts directory so SQLite stays small.
    """

    __tablename__ = "artifacts"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    kind: Mapped[ArtifactKind] = mapped_column(_enum_column(ArtifactKind, 24))
    filename: Mapped[str] = mapped_column(String(255))
    content_type: Mapped[str] = mapped_column(String(128), default="application/json")
    #: Path relative to the configured artifacts directory.
    relative_path: Mapped[str] = mapped_column(String(512))
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    scan: Mapped[Scan] = relationship(back_populates="artifacts")
