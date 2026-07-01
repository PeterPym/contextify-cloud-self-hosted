"""Add tenant acquisition attribution columns (ct-2448).

Revision ID: 039
Revises: 038
Create Date: 2026-06-28
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "039"
down_revision: str | None = "038"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("tenants", sa.Column("acquisition_token", sa.Text(), nullable=True))
    op.add_column("tenants", sa.Column("acquisition_source", sa.Text(), nullable=True))
    op.add_column("tenants", sa.Column("acquisition_medium", sa.Text(), nullable=True))
    op.add_column("tenants", sa.Column("acquisition_campaign", sa.Text(), nullable=True))
    op.add_column("tenants", sa.Column("acquisition_content", sa.Text(), nullable=True))
    op.add_column("tenants", sa.Column("acquisition_landing_path", sa.Text(), nullable=True))
    op.add_column(
        "tenants",
        sa.Column("acquisition_captured_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("tenants", "acquisition_captured_at")
    op.drop_column("tenants", "acquisition_landing_path")
    op.drop_column("tenants", "acquisition_content")
    op.drop_column("tenants", "acquisition_campaign")
    op.drop_column("tenants", "acquisition_medium")
    op.drop_column("tenants", "acquisition_source")
    op.drop_column("tenants", "acquisition_token")
