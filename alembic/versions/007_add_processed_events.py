"""Add processed_events table for webhook idempotency.

Tracks Stripe webhook events that have been processed to prevent
duplicate handling on retries. Uses Stripe's event.id as primary key.

This is a public-schema table (not per-tenant) since Stripe events
are global and not scoped to a single tenant.

Revision ID: 007
Revises: 006
"""

import sqlalchemy as sa

from alembic import op

revision = "007"
down_revision = "006"


def upgrade() -> None:
    op.create_table(
        "processed_events",
        sa.Column("event_id", sa.Text, primary_key=True),
        sa.Column("event_type", sa.Text, nullable=False),
        sa.Column(
            "processed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("outcome", sa.Text, nullable=False),
    )


def downgrade() -> None:
    op.drop_table("processed_events")
