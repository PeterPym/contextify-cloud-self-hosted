"""Add sync_sessions table for tracking multi-batch sync progress.

Tracks each sync session (multi-batch upload) from start to completion.
Supports resume after interruption by persisting the session ID across
batches. Stale sessions (inactive > 24h) are cleaned up opportunistically.

Revision ID: 010
Revises: 009
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "010"
down_revision = "009"


def upgrade() -> None:
    op.create_table(
        "sync_sessions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("device_id", sa.Text, nullable=True),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "status",
            sa.Text,
            nullable=False,
            server_default=sa.text("'in_progress'"),
        ),
        sa.Column("total_batches", sa.Integer, nullable=True),
        sa.Column(
            "completed_batches",
            sa.Integer,
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("last_batch_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('in_progress', 'completed', 'abandoned')",
            name="ck_sync_session_status",
        ),
    )
    op.create_index(
        "idx_sync_sessions_tenant_status",
        "sync_sessions",
        ["tenant_id", "status"],
    )
    op.create_index(
        "idx_sync_sessions_tenant_user",
        "sync_sessions",
        ["tenant_id", "user_id"],
    )


def downgrade() -> None:
    op.drop_index("idx_sync_sessions_tenant_user", table_name="sync_sessions")
    op.drop_index("idx_sync_sessions_tenant_status", table_name="sync_sessions")
    op.drop_table("sync_sessions")
