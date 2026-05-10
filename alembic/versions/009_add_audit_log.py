"""Add audit_log table for recording all state-changing operations.

Tracks who did what, when, and to which resource. Append-only table
in the public schema (shared across all tenants, keyed by tenant_id).

Revision ID: 009
Revises: 008
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "009"
down_revision = "008"


def upgrade() -> None:
    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("action", sa.Text, nullable=False),
        sa.Column("resource_type", sa.Text, nullable=False),
        sa.Column("resource_id", sa.Text, nullable=True),
        sa.Column("detail", postgresql.JSONB, nullable=True),
        sa.Column("ip_address", sa.Text, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index(
        "idx_audit_log_tenant_created",
        "audit_log",
        ["tenant_id", sa.text("created_at DESC")],
    )
    op.create_index(
        "idx_audit_log_tenant_action",
        "audit_log",
        ["tenant_id", "action"],
    )
    op.create_index(
        "idx_audit_log_tenant_user_created",
        "audit_log",
        ["tenant_id", "user_id", sa.text("created_at DESC")],
    )


def downgrade() -> None:
    op.drop_index("idx_audit_log_tenant_user_created", table_name="audit_log")
    op.drop_index("idx_audit_log_tenant_action", table_name="audit_log")
    op.drop_index("idx_audit_log_tenant_created", table_name="audit_log")
    op.drop_table("audit_log")
