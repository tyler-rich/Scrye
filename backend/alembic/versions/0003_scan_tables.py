"""scan tables: scans, findings, artifacts

Phase 2 — core scanning. A scan is one run of Trivy or Grype against a target;
its raw output is stored as an artifact (source of truth) and parsed into
normalized findings. No secret material is stored on these tables.

Revision ID: 0003_scan_tables
Revises: 0002_auth_tables
Create Date: 2026-07-03
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003_scan_tables"
down_revision: str | None = "0002_auth_tables"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SCANNER = sa.Enum("trivy", "grype", name="scanner", native_enum=False, length=16)
_TARGET_TYPE = sa.Enum(
    "image", "repository", "filesystem", "sbom", name="target_type", native_enum=False, length=16
)
_SCAN_STATUS = sa.Enum(
    "queued",
    "running",
    "succeeded",
    "failed",
    "canceled",
    name="scan_status",
    native_enum=False,
    length=16,
)
_SEVERITY = sa.Enum(
    "critical",
    "high",
    "medium",
    "low",
    "negligible",
    "unknown",
    name="severity",
    native_enum=False,
    length=16,
)
_FINDING_CLASS = sa.Enum(
    "vulnerability",
    "misconfiguration",
    "secret",
    "license",
    name="finding_class",
    native_enum=False,
    length=20,
)
_ARTIFACT_KIND = sa.Enum(
    "raw_trivy_json",
    "raw_grype_json",
    "sbom",
    name="artifact_kind",
    native_enum=False,
    length=24,
)


def upgrade() -> None:
    """Create the scans, findings, and artifacts tables."""
    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scanner", _SCANNER, nullable=False),
        sa.Column("target_type", _TARGET_TYPE, nullable=False),
        sa.Column("target", sa.String(length=512), nullable=False),
        sa.Column("status", _SCAN_STATUS, nullable=False),
        sa.Column("options", sa.JSON(), nullable=False),
        sa.Column("severity_counts", sa.JSON(), nullable=False),
        sa.Column("highest_severity", _SEVERITY, nullable=True),
        sa.Column("findings_count", sa.Integer(), nullable=False),
        sa.Column("scanner_version", sa.String(length=32), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column(
            "created_by_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_by_username", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
    )
    op.create_index(op.f("ix_scans_status"), "scans", ["status"], unique=False)
    op.create_index(op.f("ix_scans_created_at"), "scans", ["created_at"], unique=False)
    op.create_index(
        "ix_scans_scanner_status_created",
        "scans",
        ["scanner", "status", "created_at"],
        unique=False,
    )

    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "scan_id",
            sa.Integer(),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("finding_class", _FINDING_CLASS, nullable=False),
        sa.Column("severity", _SEVERITY, nullable=False),
        sa.Column("vuln_id", sa.String(length=128), nullable=True),
        sa.Column("pkg_name", sa.String(length=255), nullable=True),
        sa.Column("installed_version", sa.String(length=128), nullable=True),
        sa.Column("fixed_version", sa.String(length=128), nullable=True),
        sa.Column("title", sa.String(length=512), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("location", sa.String(length=512), nullable=True),
        sa.Column("primary_url", sa.String(length=512), nullable=True),
    )
    op.create_index(op.f("ix_findings_scan_id"), "findings", ["scan_id"], unique=False)
    op.create_index(
        "ix_findings_scan_severity_vuln",
        "findings",
        ["scan_id", "severity", "vuln_id"],
        unique=False,
    )

    op.create_table(
        "artifacts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "scan_id",
            sa.Integer(),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", _ARTIFACT_KIND, nullable=False),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("content_type", sa.String(length=128), nullable=False),
        sa.Column("relative_path", sa.String(length=512), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index(op.f("ix_artifacts_scan_id"), "artifacts", ["scan_id"], unique=False)


def downgrade() -> None:
    """Drop the Phase 2 scan tables."""
    op.drop_index(op.f("ix_artifacts_scan_id"), table_name="artifacts")
    op.drop_table("artifacts")
    op.drop_index("ix_findings_scan_severity_vuln", table_name="findings")
    op.drop_index(op.f("ix_findings_scan_id"), table_name="findings")
    op.drop_table("findings")
    op.drop_index("ix_scans_scanner_status_created", table_name="scans")
    op.drop_index(op.f("ix_scans_created_at"), table_name="scans")
    op.drop_index(op.f("ix_scans_status"), table_name="scans")
    op.drop_table("scans")
