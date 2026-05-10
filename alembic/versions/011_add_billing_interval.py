"""Add billing_interval column to tenants table.

Tracks whether a paid tenant is billed monthly or annually so annual pricing
can be displayed correctly in APIs and UI.

Revision ID: 011
Revises: 010
"""

import sqlalchemy as sa

from alembic import op

revision = "011"
down_revision = "010"


def upgrade() -> None:
    op.add_column(
        "tenants",
        sa.Column(
            "billing_interval",
            sa.Text,
            nullable=False,
            server_default=sa.text("'month'"),
        ),
    )
    op.create_check_constraint(
        "ck_tenant_billing_interval",
        "tenants",
        "billing_interval IN ('month','year')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_tenant_billing_interval", "tenants", type_="check"
    )
    op.drop_column("tenants", "billing_interval")
