"""settings, oidc, mfa, api tokens, notifications & backups

Phase 5 — settings, OIDC, MFA, and backup/restore. Adds the runtime settings
store, OIDC configuration/identities, per-user TOTP MFA columns, personal API
tokens, notification channels, and backup bookkeeping. Every stored secret
(OIDC client secret, notification secret, MFA secret, backup passphrase) is a
field-encrypted ciphertext column — no plaintext is introduced by this schema.

Revision ID: 0006_settings_oidc_backup
Revises: 0005_history_presets_tags
Create Date: 2026-07-03
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0006_settings_oidc_backup"
down_revision: str | None = "0005_history_presets_tags"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ROLE_ENUM = sa.Enum("viewer", "operator", "admin", native_enum=False, length=16, name="role")


def upgrade() -> None:
    """Create the Phase 5 settings/auth/backup tables and MFA columns."""
    op.create_table(
        "settings",
        sa.Column("key", sa.String(length=128), primary_key=True),
        sa.Column("value", sa.JSON(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("updated_by_username", sa.String(length=64), nullable=True),
    )

    op.create_table(
        "oidc_config",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("display_name", sa.String(length=64), nullable=False),
        sa.Column("issuer", sa.String(length=512), nullable=True),
        sa.Column("client_id", sa.String(length=255), nullable=True),
        sa.Column("client_secret_ciphertext", sa.String(length=1024), nullable=True),
        sa.Column("secret_updated_at", sa.DateTime(), nullable=True),
        sa.Column("scopes", sa.String(length=255), nullable=False),
        sa.Column("username_claim", sa.String(length=64), nullable=False),
        sa.Column("email_claim", sa.String(length=64), nullable=False),
        sa.Column("groups_claim", sa.String(length=64), nullable=True),
        sa.Column("admin_group", sa.String(length=128), nullable=True),
        sa.Column("auto_provision", sa.Boolean(), nullable=False),
        sa.Column("default_role", _ROLE_ENUM, nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("updated_by_username", sa.String(length=64), nullable=True),
    )

    op.create_table(
        "oidc_identities",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("issuer", sa.String(length=512), nullable=False),
        sa.Column("subject", sa.String(length=255), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_login_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("issuer", "subject", name="uq_oidc_identity_iss_sub"),
    )
    op.create_index(op.f("ix_oidc_identities_user_id"), "oidc_identities", ["user_id"])

    op.create_table(
        "oidc_login_flows",
        sa.Column("state", sa.String(length=64), primary_key=True),
        sa.Column("nonce", sa.String(length=64), nullable=False),
        sa.Column("code_verifier", sa.String(length=128), nullable=False),
        sa.Column("redirect_uri", sa.String(length=512), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index(op.f("ix_oidc_login_flows_created_at"), "oidc_login_flows", ["created_at"])

    op.create_table(
        "notification_channels",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column(
            "type",
            sa.Enum(
                "webhook",
                "discord",
                "smtp",
                "matrix",
                native_enum=False,
                length=16,
                name="notificationtype",
            ),
            nullable=False,
        ),
        sa.Column("config", sa.JSON(), nullable=False),
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
    op.create_index(
        op.f("ix_notification_channels_name"), "notification_channels", ["name"], unique=True
    )

    op.create_table(
        "api_tokens",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("token_prefix", sa.String(length=16), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "owner_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("owner_username", sa.String(length=64), nullable=True),
        sa.Column("role", _ROLE_ENUM, nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
    )
    op.create_index(op.f("ix_api_tokens_token_prefix"), "api_tokens", ["token_prefix"])
    op.create_index(op.f("ix_api_tokens_token_hash"), "api_tokens", ["token_hash"], unique=True)
    op.create_index(op.f("ix_api_tokens_owner_id"), "api_tokens", ["owner_id"])

    op.create_table(
        "backups",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("checksum_sha256", sa.String(length=64), nullable=False),
        sa.Column(
            "kind",
            sa.Enum(
                "manual",
                "scheduled",
                native_enum=False,
                length=16,
                name="backupkind",
            ),
            nullable=False,
        ),
        sa.Column("app_version", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("created_by_username", sa.String(length=64), nullable=True),
        sa.Column("note", sa.String(length=255), nullable=True),
        sa.UniqueConstraint("filename", name="uq_backups_filename"),
    )
    op.create_index(op.f("ix_backups_created_at"), "backups", ["created_at"])

    op.create_table(
        "backup_schedules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("interval_hours", sa.Integer(), nullable=False),
        sa.Column("retention_count", sa.Integer(), nullable=False),
        sa.Column("passphrase_ciphertext", sa.String(length=1024), nullable=True),
        sa.Column("secret_updated_at", sa.DateTime(), nullable=True),
        sa.Column("last_run_at", sa.DateTime(), nullable=True),
        sa.Column("last_status", sa.String(length=255), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )

    with op.batch_alter_table("users") as batch:
        batch.add_column(
            sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.false())
        )
        batch.add_column(sa.Column("mfa_secret_ciphertext", sa.String(length=1024), nullable=True))


def downgrade() -> None:
    """Drop the Phase 5 tables and MFA columns."""
    with op.batch_alter_table("users") as batch:
        batch.drop_column("mfa_secret_ciphertext")
        batch.drop_column("mfa_enabled")

    op.drop_table("backup_schedules")
    op.drop_index(op.f("ix_backups_created_at"), table_name="backups")
    op.drop_table("backups")
    op.drop_index(op.f("ix_api_tokens_owner_id"), table_name="api_tokens")
    op.drop_index(op.f("ix_api_tokens_token_hash"), table_name="api_tokens")
    op.drop_index(op.f("ix_api_tokens_token_prefix"), table_name="api_tokens")
    op.drop_table("api_tokens")
    op.drop_index(op.f("ix_notification_channels_name"), table_name="notification_channels")
    op.drop_table("notification_channels")
    op.drop_index(op.f("ix_oidc_login_flows_created_at"), table_name="oidc_login_flows")
    op.drop_table("oidc_login_flows")
    op.drop_index(op.f("ix_oidc_identities_user_id"), table_name="oidc_identities")
    op.drop_table("oidc_identities")
    op.drop_table("oidc_config")
    op.drop_table("settings")
