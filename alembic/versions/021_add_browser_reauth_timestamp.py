"""Add browser session reauthentication timestamp.

Revision ID: 021
Revises: 020
Create Date: 2026-04-25
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "021"
down_revision: str | None = "020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "user_sessions",
        sa.Column("last_reauthenticated_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("user_sessions", "last_reauthenticated_at")
