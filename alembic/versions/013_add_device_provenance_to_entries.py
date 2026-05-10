"""Add uploaded_by_device_id and uploaded_by_device_name to transcript_entries.

Stores the originating device's stable machine ID and human-readable name on
each pushed entry. Enables clients to stamp source_device_name on pulled entries
for multi-machine `contextify search --device` filtering.

Revision ID: 013
Revises: 012
"""

import sqlalchemy as sa

from alembic import op

revision = "013"
down_revision = "012"


def upgrade() -> None:
    # Add per-entry device provenance columns to all tenant schemas.
    # Use a schema-aware approach consistent with the rest of the codebase.
    connection = op.get_bind()
    schemas = connection.execute(
        sa.text(
            "SELECT schema_name FROM information_schema.schemata "
            "WHERE schema_name LIKE 'tenant_%'"
        )
    ).fetchall()

    for (schema,) in schemas:
        op.execute(
            sa.text(
                f"ALTER TABLE {schema}.transcript_entries "
                f"ADD COLUMN IF NOT EXISTS uploaded_by_device_id TEXT"
            )
        )
        op.execute(
            sa.text(
                f"ALTER TABLE {schema}.transcript_entries "
                f"ADD COLUMN IF NOT EXISTS uploaded_by_device_name TEXT"
            )
        )


def downgrade() -> None:
    connection = op.get_bind()
    schemas = connection.execute(
        sa.text(
            "SELECT schema_name FROM information_schema.schemata "
            "WHERE schema_name LIKE 'tenant_%'"
        )
    ).fetchall()

    for (schema,) in schemas:
        op.execute(
            sa.text(
                f"ALTER TABLE {schema}.transcript_entries "
                f"DROP COLUMN IF EXISTS uploaded_by_device_id"
            )
        )
        op.execute(
            sa.text(
                f"ALTER TABLE {schema}.transcript_entries "
                f"DROP COLUMN IF EXISTS uploaded_by_device_name"
            )
        )
