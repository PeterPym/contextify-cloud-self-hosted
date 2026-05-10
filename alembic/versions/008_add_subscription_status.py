"""Add subscription_status column to tenants table.

Tracks the billing state machine for each tenant:
  - trialing: subscription in trial period
  - active: subscription is current and paid
  - past_due: payment failed, in grace period
  - unpaid: past grace period, sync disabled
  - canceled: subscription canceled by user or system
  - archived: tenant data preserved but all access disabled

Revision ID: 008
Revises: 007
"""

import sqlalchemy as sa

from alembic import op

revision = "008"
down_revision = "007"


def upgrade() -> None:
    op.add_column(
        "tenants",
        sa.Column(
            "subscription_status",
            sa.Text,
            nullable=False,
            server_default="active",
        ),
    )
    op.create_check_constraint(
        "ck_tenant_subscription_status",
        "tenants",
        "subscription_status IN ("
        "'trialing','active','past_due','unpaid','canceled','archived')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_tenant_subscription_status", "tenants", type_="check"
    )
    op.drop_column("tenants", "subscription_status")
