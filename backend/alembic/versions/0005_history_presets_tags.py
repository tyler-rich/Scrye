"""history, presets & tags: scan_tags, filter_presets

Phase 4 — history, reports & exports. Adds free-form scan tags (indexed for the
history filter) and owner-scoped saved filter presets. Both carry only
non-sensitive metadata: labels and filter selections, no secret material.

Revision ID: 0005_history_presets_tags
Revises: 0004_targets_registries
Create Date: 2026-07-03
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0005_history_presets_tags"
down_revision: str | None = "0004_targets_registries"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the scan_tags and filter_presets tables."""
    op.create_table(
        "scan_tags",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "scan_id",
            sa.Integer(),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("tag", sa.String(length=64), nullable=False),
        sa.UniqueConstraint("scan_id", "tag", name="uq_scan_tags_scan_tag"),
    )
    op.create_index(op.f("ix_scan_tags_scan_id"), "scan_tags", ["scan_id"])
    op.create_index("ix_scan_tags_tag", "scan_tags", ["tag"])

    op.create_table(
        "filter_presets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "owner_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("filters", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("owner_id", "name", name="uq_filter_presets_owner_name"),
    )
    op.create_index(op.f("ix_filter_presets_owner_id"), "filter_presets", ["owner_id"])


def downgrade() -> None:
    """Drop the Phase 4 history tables."""
    op.drop_index(op.f("ix_filter_presets_owner_id"), table_name="filter_presets")
    op.drop_table("filter_presets")
    op.drop_index("ix_scan_tags_tag", table_name="scan_tags")
    op.drop_index(op.f("ix_scan_tags_scan_id"), table_name="scan_tags")
    op.drop_table("scan_tags")
