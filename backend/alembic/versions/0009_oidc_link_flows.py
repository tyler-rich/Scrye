"""oidc account linking: flow purpose and owning user

Adds two nullable columns to ``oidc_login_flows`` so the one authorization-code
handshake can serve a second terminal action:

- ``purpose`` — ``'login'`` (the existing sign-in) or ``'link'`` (bind the
  verified subject to an already-authenticated account). ``NULL`` reads as
  ``'login'``, so rows written before this migration keep their meaning and no
  data migration is required for in-flight flows.
- ``user_id`` — set only on link flows, to the account the callback may bind an
  identity to. Captured server-side from the initiating session; the callback
  also requires a live session for that same user before it will act.

Both columns are nullable and non-secret, and the change is backward compatible:
downgrading drops them and every remaining row is a login flow again.

Revision ID: 0009_oidc_link_flows
Revises: 0008_oidc_flow_browser_binding
Create Date: 2026-08-02
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0009_oidc_link_flows"
down_revision: str | None = "0008_oidc_flow_browser_binding"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


#: Explicit constraint name so the copy-and-move batch below (and its reversal)
#: can address the foreign key on SQLite, which has no ``ALTER … ADD CONSTRAINT``.
_FK_NAME = "fk_oidc_login_flows_user_id_users"


def upgrade() -> None:
    """Add the flow purpose and owning-user columns.

    Runs inside ``batch_alter_table`` because ``user_id`` carries a foreign key
    and SQLite cannot ALTER a constraint onto an existing table — batch mode
    recreates it copy-and-move. Safe here regardless: ``oidc_login_flows`` is a
    transient table of in-flight handshakes with a 10-minute TTL, excluded from
    backup bundles, so at most a few short-lived rows are ever copied.
    """
    with op.batch_alter_table("oidc_login_flows") as batch_op:
        batch_op.add_column(sa.Column("purpose", sa.String(length=16), nullable=True))
        batch_op.add_column(sa.Column("user_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(_FK_NAME, "users", ["user_id"], ["id"], ondelete="CASCADE")


def downgrade() -> None:
    """Drop the flow purpose and owning-user columns (every row is a login flow again)."""
    with op.batch_alter_table("oidc_login_flows") as batch_op:
        batch_op.drop_constraint(_FK_NAME, type_="foreignkey")
        batch_op.drop_column("user_id")
        batch_op.drop_column("purpose")
