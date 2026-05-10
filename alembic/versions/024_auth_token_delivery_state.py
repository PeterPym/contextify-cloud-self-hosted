"""Add auth token delivery state.

Revision ID: 024
Revises: 023
Create Date: 2026-04-26
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "024"
down_revision: str | None = "023"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "auth_tokens",
        sa.Column("delivery_status", sa.Text(), server_default="sent", nullable=False),
    )
    op.add_column(
        "auth_tokens",
        sa.Column("delivery_attempts", sa.Integer(), server_default="0", nullable=False),
    )
    op.add_column(
        "auth_tokens",
        sa.Column("delivery_next_attempt_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "auth_tokens",
        sa.Column("delivery_last_error", sa.Text(), nullable=True),
    )
    op.add_column(
        "auth_tokens",
        sa.Column("delivery_sent_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_check_constraint(
        "ck_auth_token_delivery_status",
        "auth_tokens",
        "delivery_status IN ('pending', 'sent', 'failed', 'exhausted')",
    )
    op.create_index(
        "idx_auth_tokens_delivery_retry",
        "auth_tokens",
        ["delivery_status", "delivery_next_attempt_at"],
        postgresql_where=sa.text("consumed_at IS NULL"),
    )
    op.execute(
        "UPDATE auth_tokens "
        "SET delivery_sent_at = created_at "
        "WHERE delivery_status = 'sent' AND delivery_sent_at IS NULL"
    )


def downgrade() -> None:
    op.drop_index("idx_auth_tokens_delivery_retry", table_name="auth_tokens")
    op.drop_constraint("ck_auth_token_delivery_status", "auth_tokens", type_="check")
    op.drop_column("auth_tokens", "delivery_sent_at")
    op.drop_column("auth_tokens", "delivery_last_error")
    op.drop_column("auth_tokens", "delivery_next_attempt_at")
    op.drop_column("auth_tokens", "delivery_attempts")
    op.drop_column("auth_tokens", "delivery_status")
