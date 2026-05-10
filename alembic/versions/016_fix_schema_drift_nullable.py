"""Fix schema drift: make usage_events.entry_count NOT NULL.

The initial migration (001) created entry_count without nullable=False,
leaving the column nullable in PostgreSQL. The SQLAlchemy model declares
Mapped[int] (not Optional), which means NOT NULL. This migration aligns
the database with the model by backfilling NULLs to 0 and setting
NOT NULL.

The companion drift issue (missing idx_invitation_tenant_status_created
index) is resolved by adding the index to the model definition rather
than creating a migration, since the index already exists in the DB
from migration 004.

Revision ID: 016
Revises: 015
"""

import sqlalchemy as sa

from alembic import op

revision = "016"
down_revision = "015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Backfill any existing NULL values before adding the constraint
    op.execute("UPDATE usage_events SET entry_count = 0 WHERE entry_count IS NULL")
    op.alter_column(
        "usage_events",
        "entry_count",
        existing_type=sa.Integer(),
        nullable=False,
        existing_server_default=sa.text("0"),
    )


def downgrade() -> None:
    op.alter_column(
        "usage_events",
        "entry_count",
        existing_type=sa.Integer(),
        nullable=True,
        existing_server_default=sa.text("0"),
    )
