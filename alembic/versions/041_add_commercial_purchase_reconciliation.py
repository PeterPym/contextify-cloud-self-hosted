"""Add commercial purchase reconciliation evidence (ct-3813).

Revision ID: 041
Revises: 040
Create Date: 2026-08-12
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "041"
down_revision: str | None = "040"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "licenses",
        sa.Column("delivery_provider_message_id", sa.Text(), nullable=True),
    )
    op.create_table(
        "commercial_purchase_reconciliation",
        sa.Column("stripe_checkout_session_id", sa.Text(), nullable=False),
        sa.Column("stripe_subscription_id", sa.Text(), nullable=False),
        sa.Column("checkout_session_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("paid_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("amount_total", sa.BigInteger(), nullable=False),
        sa.Column("currency", sa.Text(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("fulfillment_stage", sa.Text(), server_default="pending", nullable=False),
        sa.Column("fulfilled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("incident_first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("incident_reported_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("operator_alert_status", sa.Text(), server_default="pending", nullable=False),
        sa.Column("operator_alert_attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("operator_alert_next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("operator_alert_last_error", sa.Text(), nullable=True),
        sa.Column("operator_alert_sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("operator_alert_provider_message_id", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "fulfillment_stage IN ('pending', 'missing', 'delivery_pending', "
            "'delivery_failed', 'delivery_exhausted', 'fulfilled')",
            name="ck_commercial_purchase_reconciliation_stage",
        ),
        sa.CheckConstraint(
            "operator_alert_status IN "
            "('pending', 'failed', 'exhausted', 'sent', 'historical')",
            name="ck_commercial_purchase_reconciliation_alert_status",
        ),
        sa.PrimaryKeyConstraint("stripe_checkout_session_id"),
        sa.UniqueConstraint("stripe_subscription_id"),
    )
    op.create_index(
        "idx_commercial_purchase_reconciliation_alert",
        "commercial_purchase_reconciliation",
        ["operator_alert_status", "operator_alert_next_attempt_at"],
    )
    op.create_index(
        "idx_commercial_purchase_reconciliation_checkout_created_at",
        "commercial_purchase_reconciliation",
        ["checkout_session_created_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "idx_commercial_purchase_reconciliation_checkout_created_at",
        table_name="commercial_purchase_reconciliation",
    )
    op.drop_index(
        "idx_commercial_purchase_reconciliation_alert",
        table_name="commercial_purchase_reconciliation",
    )
    op.drop_table("commercial_purchase_reconciliation")
    op.drop_column("licenses", "delivery_provider_message_id")
