"""targets & registries: registries, git_credentials, docker_environments

Phase 3 — targets & registries. Adds credential storage for private container
registries and git providers, plus read-only Docker-environment endpoints for
image enumeration. Secret columns hold ciphertext only (field-encrypted, per
docs/ARCHIVE.md §6); usernames/hosts/proxy URLs are non-sensitive metadata.

Revision ID: 0004_targets_registries
Revises: 0003_scan_tables
Create Date: 2026-07-03
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004_targets_registries"
down_revision: str | None = "0003_scan_tables"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_REGISTRY_AUTH_TYPE = sa.Enum(
    "username_password",
    "token",
    "aws_ecr",
    "google_gcr",
    "azure_acr",
    name="registry_auth_type",
    native_enum=False,
    length=24,
)
_GIT_PROVIDER = sa.Enum(
    "github",
    "gitlab",
    "generic",
    name="git_provider",
    native_enum=False,
    length=16,
)


def upgrade() -> None:
    """Create the registries, git_credentials, and docker_environments tables."""
    op.create_table(
        "registries",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("registry_host", sa.String(length=255), nullable=False),
        sa.Column("auth_type", _REGISTRY_AUTH_TYPE, nullable=False),
        sa.Column("username", sa.String(length=255), nullable=True),
        sa.Column("secret_ciphertext", sa.String(length=1024), nullable=True),
        sa.Column("secret_updated_at", sa.DateTime(), nullable=True),
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
    op.create_index(op.f("ix_registries_name"), "registries", ["name"], unique=True)

    op.create_table(
        "git_credentials",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("provider", _GIT_PROVIDER, nullable=False),
        sa.Column("host", sa.String(length=255), nullable=True),
        sa.Column("username", sa.String(length=255), nullable=True),
        sa.Column("token_ciphertext", sa.String(length=1024), nullable=True),
        sa.Column("secret_updated_at", sa.DateTime(), nullable=True),
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
    op.create_index(op.f("ix_git_credentials_name"), "git_credentials", ["name"], unique=True)

    op.create_table(
        "docker_environments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("proxy_url", sa.String(length=512), nullable=False),
        sa.Column("risk_acknowledged", sa.Boolean(), nullable=False),
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
    op.create_index(
        op.f("ix_docker_environments_name"), "docker_environments", ["name"], unique=True
    )


def downgrade() -> None:
    """Drop the Phase 3 targets-and-registries tables."""
    op.drop_index(op.f("ix_docker_environments_name"), table_name="docker_environments")
    op.drop_table("docker_environments")
    op.drop_index(op.f("ix_git_credentials_name"), table_name="git_credentials")
    op.drop_table("git_credentials")
    op.drop_index(op.f("ix_registries_name"), table_name="registries")
    op.drop_table("registries")
