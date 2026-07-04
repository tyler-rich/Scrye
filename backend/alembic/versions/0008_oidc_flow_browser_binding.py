"""security audit: bind OIDC login flows to the initiating browser

Adds a nullable ``browser_binding`` column to ``oidc_login_flows`` holding the
SHA-256 hash of a per-flow token that also lives in an HttpOnly cookie on the
browser that started the login. The callback must present the matching cookie,
so an authorization-code flow cannot be completed in a different browser (OIDC
login-CSRF / session fixation). The column is non-secret (a hash) and nullable,
so no data migration is required for in-flight rows.

Revision ID: 0008_oidc_flow_browser_binding
Revises: 0007_phase6_schedules_policy
Create Date: 2026-07-04
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0008_oidc_flow_browser_binding"
down_revision: str | None = "0007_phase6_schedules_policy"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add the browser-binding column to the OIDC login-flow table."""
    op.add_column(
        "oidc_login_flows",
        sa.Column("browser_binding", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    """Drop the browser-binding column."""
    op.drop_column("oidc_login_flows", "browser_binding")
