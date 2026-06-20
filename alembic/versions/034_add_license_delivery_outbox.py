"""Add delivery-outbox columns to the licenses table (ct-1966 Slice 5, ct-2015).

Makes the initial Local Commercial license-token email retryable instead of
best-effort. Mirrors the AuthToken delivery columns. Existing rows backfill to
delivery_status='sent' (server_default), so pre-ct-2015 purchases are never
re-emailed.

Revision ID: 034
Revises: 033
Create Date: 2026-06-07
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "034"
down_revision: str | None = "033"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "licenses",
        sa.Column(
            "delivery_status",
            sa.Text(),
            nullable=False,
            server_default="sent",
        ),
    )
    op.add_column(
        "licenses",
        sa.Column(
            "delivery_attempts",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
    )
    op.add_column(
        "licenses",
        sa.Column("delivery_next_attempt_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "licenses",
        sa.Column("delivery_last_error", sa.Text(), nullable=True),
    )
    op.add_column(
        "licenses",
        sa.Column("delivery_sent_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_check_constraint(
        "ck_licenses_delivery_status",
        "licenses",
        "delivery_status IN ('pending', 'sent', 'failed', 'exhausted')",
    )
    op.create_index(
        "idx_licenses_delivery_retry",
        "licenses",
        ["delivery_status", "delivery_next_attempt_at"],
    )


def downgrade() -> None:
    op.drop_index("idx_licenses_delivery_retry", table_name="licenses")
    op.drop_constraint("ck_licenses_delivery_status", "licenses", type_="check")
    op.drop_column("licenses", "delivery_sent_at")
    op.drop_column("licenses", "delivery_last_error")
    op.drop_column("licenses", "delivery_next_attempt_at")
    op.drop_column("licenses", "delivery_attempts")
    op.drop_column("licenses", "delivery_status")
