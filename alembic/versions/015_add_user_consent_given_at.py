"""Add consent_given_at column to users.

Records when a team member explicitly consented to data visibility
during the invitation acceptance flow. Set at invite-accept time.

Revision ID: 015
Revises: 014
"""

import sqlalchemy as sa

from alembic import op

revision = "015"
down_revision = "014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("consent_given_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("users", "consent_given_at")
