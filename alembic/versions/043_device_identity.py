"""Add copy-safe device identity without changing existing IDs or names.

Revision ID: 043
Revises: 042
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "043"
down_revision: str | None = "042"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("last_unattributed_sync_at", sa.DateTime(timezone=True)))
    op.add_column(
        "users",
        sa.Column(
            "identity_observation_started_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    for name in ("display_name", "hardware_fingerprint_hash", "fingerprint_kind"):
        op.add_column("devices", sa.Column(name, sa.Text()))
    for name in ("identity_instance_id", "merged_into_device_id"):
        op.add_column("devices", sa.Column(name, postgresql.UUID(as_uuid=True)))
    op.create_foreign_key(
        "fk_devices_merged_into",
        "devices",
        "devices",
        ["merged_into_device_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    for name in ("last_seen_at", "retired_at", "removed_at"):
        op.add_column("devices", sa.Column(name, sa.DateTime(timezone=True)))
    op.add_column(
        "devices",
        sa.Column("legacy_writes_fenced", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    for family in ("identity", "merge", "lifecycle"):
        op.add_column(
            "devices",
            sa.Column(f"{family}_revision", sa.BigInteger(), nullable=False, server_default="0"),
        )
        op.add_column(
            "devices", sa.Column(f"{family}_last_request_id", postgresql.UUID(as_uuid=True))
        )
        op.add_column("devices", sa.Column(f"{family}_last_request_kind", sa.Text()))
        op.add_column("devices", sa.Column(f"{family}_last_payload_hash", sa.Text()))


def downgrade() -> None:
    # Identity fences must survive a code rollback. Dropping them would allow
    # a transferred installation to write again. Restore a backup explicitly.
    raise RuntimeError("Device identity migration is forward-only; retain identity fences.")
