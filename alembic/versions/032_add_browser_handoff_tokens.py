"""Add one-time browser handoff tokens.

Revision ID: 032
Revises: 031
Create Date: 2026-05-05
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "032"
down_revision: str | None = "031"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "browser_handoff_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("account_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("api_key_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_path", sa.Text(), nullable=False),
        sa.Column("device_id", sa.Text(), nullable=True),
        sa.Column("device_name", sa.Text(), nullable=True),
        sa.Column("created_ip_hash", sa.Text(), nullable=True),
        sa.Column("consumed_ip_hash", sa.Text(), nullable=True),
        sa.Column("user_agent_hash", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "target_path = '/cloud' OR target_path LIKE '/cloud/%'",
            name="ck_browser_handoff_target_path",
        ),
        sa.ForeignKeyConstraint(
            ["account_id"], ["accounts.id"],
            name="fk_browser_handoff_account",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["api_key_id"], ["api_keys.id"],
            name="fk_browser_handoff_api_key",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"],
            name="fk_browser_handoff_tenant",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id", "account_id", "tenant_id"],
            ["users.id", "users.account_id", "users.tenant_id"],
            name="fk_browser_handoff_user_account_tenant",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash", name="uq_browser_handoff_token_hash"),
    )
    op.create_index(
        "idx_browser_handoff_tokens_account",
        "browser_handoff_tokens",
        ["account_id", "created_at"],
    )
    op.create_index(
        "idx_browser_handoff_tokens_expires",
        "browser_handoff_tokens",
        ["expires_at"],
    )
    op.create_index(
        "idx_browser_handoff_tokens_active",
        "browser_handoff_tokens",
        ["account_id", "expires_at"],
        postgresql_where=sa.text("consumed_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("idx_browser_handoff_tokens_active", table_name="browser_handoff_tokens")
    op.drop_index("idx_browser_handoff_tokens_expires", table_name="browser_handoff_tokens")
    op.drop_index("idx_browser_handoff_tokens_account", table_name="browser_handoff_tokens")
    op.drop_table("browser_handoff_tokens")
