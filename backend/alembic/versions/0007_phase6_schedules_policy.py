"""phase 6: scan schedules, trivy vex/ignore policy, notification events

Phase 6 — dashboard, notifications, scheduled scans, and Trivy policy. Adds the
recurring-scan schedule table, Trivy VEX documents and ignore rules, and a
per-channel ``events`` subscription column on notification channels. No secret
material is introduced by this schema (schedules reference credentials by id;
VEX/ignore rules are non-secret policy data).

Revision ID: 0007_phase6_schedules_policy
Revises: 0006_settings_oidc_backup
Create Date: 2026-07-03
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0007_phase6_schedules_policy"
down_revision: str | None = "0006_settings_oidc_backup"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SCANNER_ENUM = sa.Enum("trivy", "grype", native_enum=False, length=16, name="scanner")
_TARGET_TYPE_ENUM = sa.Enum(
    "image", "repository", "filesystem", "sbom", native_enum=False, length=16, name="targettype"
)
_VEX_FORMAT_ENUM = sa.Enum(
    "openvex", "cyclonedx", "csaf", native_enum=False, length=16, name="vexformat"
)


def upgrade() -> None:
    """Create the Phase 6 schedule/policy tables and notification events column."""
    op.create_table(
        "scan_schedules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("cron", sa.String(length=128), nullable=False),
        sa.Column("scanner", _SCANNER_ENUM, nullable=False),
        sa.Column("target_type", _TARGET_TYPE_ENUM, nullable=False),
        sa.Column("target", sa.String(length=512), nullable=False),
        sa.Column("options", sa.JSON(), nullable=False),
        sa.Column(
            "registry_id",
            sa.Integer(),
            sa.ForeignKey("registries.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "git_credential_id",
            sa.Integer(),
            sa.ForeignKey("git_credentials.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("last_run_at", sa.DateTime(), nullable=True),
        sa.Column("last_scan_id", sa.Integer(), nullable=True),
        sa.Column("last_status", sa.String(length=255), nullable=True),
        sa.Column(
            "created_by_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_by_username", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index(op.f("ix_scan_schedules_name"), "scan_schedules", ["name"], unique=True)

    op.create_table(
        "vex_documents",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("format", _VEX_FORMAT_ENUM, nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column(
            "created_by_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_by_username", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index(op.f("ix_vex_documents_name"), "vex_documents", ["name"], unique=True)

    op.create_table(
        "trivy_ignore_rules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("vuln_id", sa.String(length=128), nullable=False),
        sa.Column("reason", sa.String(length=512), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column(
            "created_by_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_by_username", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index(op.f("ix_trivy_ignore_rules_vuln_id"), "trivy_ignore_rules", ["vuln_id"])

    # Per-channel event subscriptions; default to an empty list for existing rows.
    with op.batch_alter_table("notification_channels") as batch:
        batch.add_column(sa.Column("events", sa.JSON(), nullable=False, server_default="[]"))


def downgrade() -> None:
    """Drop the Phase 6 schedule/policy tables and notification events column."""
    with op.batch_alter_table("notification_channels") as batch:
        batch.drop_column("events")

    op.drop_index(op.f("ix_trivy_ignore_rules_vuln_id"), table_name="trivy_ignore_rules")
    op.drop_table("trivy_ignore_rules")
    op.drop_index(op.f("ix_vex_documents_name"), table_name="vex_documents")
    op.drop_table("vex_documents")
    op.drop_index(op.f("ix_scan_schedules_name"), table_name="scan_schedules")
    op.drop_table("scan_schedules")
