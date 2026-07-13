"""initial baseline

Establishes the Alembic migration chain for Scrye. Phase 0 introduces no domain
tables (per docs/ARCHIVE.md §7 those arrive in later phases); this revision exists
so the database is migration-managed from the very first deploy and later
revisions have a stable base to build on.

Revision ID: 0001_initial_baseline
Revises:
Create Date: 2026-06-30
"""

from __future__ import annotations

from collections.abc import Sequence

# revision identifiers, used by Alembic.
revision: str = "0001_initial_baseline"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """No-op baseline: domain tables are added in later phases."""
    pass


def downgrade() -> None:
    """No-op baseline."""
    pass
