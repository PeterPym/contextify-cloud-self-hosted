"""Add internal support audit log.

Revision ID: 029
Revises: 028
Create Date: 2026-04-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "029"
down_revision: str | None = "028"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "internal_support_audit_log",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("operator_id", sa.Text(), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("target_account_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("target_tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("target_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("resource_type", sa.Text(), nullable=False),
        sa.Column("resource_id", sa.Text(), nullable=True),
        sa.Column("detail", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("ip_address", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["target_account_id"],
            ["accounts.id"],
            name="fk_internal_support_audit_account",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["target_tenant_id"],
            ["tenants.id"],
            name="fk_internal_support_audit_tenant",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["target_user_id"],
            ["users.id"],
            name="fk_internal_support_audit_user",
            ondelete="SET NULL",
        ),
    )
    op.create_index(
        "idx_internal_support_audit_created",
        "internal_support_audit_log",
        ["created_at"],
    )
    op.create_index(
        "idx_internal_support_audit_operator_created",
        "internal_support_audit_log",
        ["operator_id", "created_at"],
    )
    op.create_index(
        "idx_internal_support_audit_account_created",
        "internal_support_audit_log",
        ["target_account_id", "created_at"],
    )
    op.create_index(
        "idx_internal_support_audit_tenant_created",
        "internal_support_audit_log",
        ["target_tenant_id", "created_at"],
    )


def downgrade() -> None:
    table_name = "internal_support_audit_log"
    op.drop_index("idx_internal_support_audit_tenant_created", table_name=table_name)
    op.drop_index("idx_internal_support_audit_account_created", table_name=table_name)
    op.drop_index("idx_internal_support_audit_operator_created", table_name=table_name)
    op.drop_index("idx_internal_support_audit_created", table_name=table_name)
    op.drop_table("internal_support_audit_log")
