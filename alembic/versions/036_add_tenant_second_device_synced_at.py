"""Add tenants.second_device_synced_at activation marker (ct-2107).

Fire-once marker for the second_device_sync activation North-Star (ct-1460 /
ct-2106). Persisted so concurrent first-syncs claim the activation exactly once,
paired with a per-tenant advisory lock in the sync router. Nullable, go-forward
only, no backfill: historical tenants stay NULL and never retro-emit.

Revision ID: 036
Revises: 035
Create Date: 2026-06-14
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "036"
down_revision: str | None = "035"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "tenants",
        sa.Column("second_device_synced_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("tenants", "second_device_synced_at")
