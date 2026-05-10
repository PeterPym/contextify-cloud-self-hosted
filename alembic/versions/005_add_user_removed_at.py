"""Add removed_at column to users table for soft-removal.

Revision ID: 005
Revises: 004
"""

import sqlalchemy as sa

from alembic import op

revision = "005"
down_revision = "004"


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("users", "removed_at")
