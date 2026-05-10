"""Add subscription period tracking columns to tenants.

Revision ID: 014
Revises: 013
"""

import sqlalchemy as sa

from alembic import op

revision = "014"
down_revision = "013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "tenants",
        sa.Column("current_period_start", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "tenants",
        sa.Column("current_period_end", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "tenants",
        sa.Column(
            "cancel_at_period_end",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )


def downgrade() -> None:
    op.drop_column("tenants", "cancel_at_period_end")
    op.drop_column("tenants", "current_period_end")
    op.drop_column("tenants", "current_period_start")
