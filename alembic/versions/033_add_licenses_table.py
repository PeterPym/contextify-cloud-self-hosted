"""Add the licenses table (Local Commercial purchases, ct-1966).

Revision ID: 033
Revises: 032
Create Date: 2026-06-07
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "033"
down_revision: str | None = "032"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "licenses",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("license_id", sa.Text(), nullable=False),
        sa.Column(
            "product", sa.Text(), nullable=False, server_default="local_commercial"
        ),
        sa.Column("customer_email", sa.Text(), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("stripe_customer_id", sa.Text(), nullable=True),
        sa.Column("stripe_subscription_id", sa.Text(), nullable=False),
        sa.Column("kid", sa.Text(), nullable=False),
        sa.Column("seats", sa.Integer(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default="active"),
        sa.Column("token", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint("seats >= 1", name="ck_licenses_seats_positive"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("license_id", name="uq_licenses_license_id"),
        sa.UniqueConstraint(
            "stripe_subscription_id", name="uq_licenses_stripe_subscription_id"
        ),
    )
    op.create_index(
        "idx_licenses_customer_email_lower",
        "licenses",
        [sa.text("lower(customer_email)")],
    )
    op.create_index("idx_licenses_tenant", "licenses", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("idx_licenses_tenant", table_name="licenses")
    op.drop_index("idx_licenses_customer_email_lower", table_name="licenses")
    op.drop_table("licenses")
