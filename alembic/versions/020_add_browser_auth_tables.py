"""Add browser auth account/session/token tables.

Revision ID: 020
Revises: 019
Create Date: 2026-04-24
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "020"
down_revision: str | None = "019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "accounts",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("email_normalized", sa.Text(), nullable=False),
        sa.Column("email_display", sa.Text(), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=True),
        sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.Text(), server_default="active", nullable=False),
        sa.Column("session_version", sa.Integer(), server_default="1", nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("tos_accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("tos_version", sa.Text(), nullable=True),
        sa.Column("tos_ip", sa.Text(), nullable=True),
        sa.Column("tos_user_agent", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('active', 'password_unset', 'disabled')",
            name="ck_account_status",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email_normalized"),
    )
    op.create_index("idx_accounts_email_normalized", "accounts", ["email_normalized"])

    op.add_column(
        "users",
        sa.Column("account_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_users_account_id_accounts",
        "users",
        "accounts",
        ["account_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("idx_users_account_id", "users", ["account_id"])
    op.create_unique_constraint(
        "uq_user_account_tenant",
        "users",
        ["id", "account_id", "tenant_id"],
    )
    op.create_index(
        "uq_users_active_tenant_account",
        "users",
        ["tenant_id", "account_id"],
        unique=True,
        postgresql_where=sa.text("removed_at IS NULL AND account_id IS NOT NULL"),
    )

    op.create_table(
        "user_sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("account_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("session_nonce", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ip_address", sa.Text(), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["account_id"], ["accounts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["user_id", "account_id", "tenant_id"],
            ["users.id", "users.account_id", "users.tenant_id"],
            name="fk_user_sessions_user_account_tenant",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_user_sessions_account", "user_sessions", ["account_id"])
    op.create_index("idx_user_sessions_user", "user_sessions", ["user_id"])
    op.create_index(
        "idx_user_sessions_active",
        "user_sessions",
        ["account_id", "tenant_id"],
        postgresql_where=sa.text("revoked_at IS NULL"),
    )

    op.create_table(
        "auth_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("account_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("email_normalized", sa.Text(), nullable=False),
        sa.Column("purpose", sa.Text(), nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("sent_to", sa.Text(), nullable=False),
        sa.Column("metadata_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "purpose IN ('email_verify', 'password_reset', 'email_change')",
            name="ck_auth_token_purpose",
        ),
        sa.ForeignKeyConstraint(["account_id"], ["accounts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index(
        "idx_auth_tokens_account_purpose", "auth_tokens", ["account_id", "purpose"]
    )
    op.create_index(
        "idx_auth_tokens_email_purpose", "auth_tokens", ["email_normalized", "purpose"]
    )


def downgrade() -> None:
    op.drop_index("idx_auth_tokens_email_purpose", table_name="auth_tokens")
    op.drop_index("idx_auth_tokens_account_purpose", table_name="auth_tokens")
    op.drop_table("auth_tokens")

    op.drop_index("idx_user_sessions_active", table_name="user_sessions")
    op.drop_index("idx_user_sessions_user", table_name="user_sessions")
    op.drop_index("idx_user_sessions_account", table_name="user_sessions")
    op.drop_table("user_sessions")

    op.drop_index("uq_users_active_tenant_account", table_name="users")
    op.drop_constraint("uq_user_account_tenant", "users", type_="unique")
    op.drop_index("idx_users_account_id", table_name="users")
    op.drop_constraint("fk_users_account_id_accounts", "users", type_="foreignkey")
    op.drop_column("users", "account_id")

    op.drop_index("idx_accounts_email_normalized", table_name="accounts")
    op.drop_table("accounts")
