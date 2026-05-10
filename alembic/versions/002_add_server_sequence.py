"""Add server_sequence to transcript_entries for cursor-based sync pull.

Revision ID: 002
Revises: 001
Create Date: 2026-02-21
"""

import re
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

_SCHEMA_NAME_RE = re.compile(r"^tenant_[a-z0-9_]+$")

revision: str = "002"
down_revision: str = "001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Find all tenant schemas
    conn = op.get_bind()
    result = conn.execute(
        sa.text(
            "SELECT schema_name FROM information_schema.schemata "
            "WHERE schema_name LIKE 'tenant_%'"
        )
    )
    schemas = [row[0] for row in result.fetchall()]

    for schema in schemas:
        # Validate schema name
        if not _SCHEMA_NAME_RE.match(schema):
            continue

        # Create sequence
        op.execute(f"CREATE SEQUENCE IF NOT EXISTS {schema}.entry_server_seq")

        # Add column WITHOUT default. If we add with DEFAULT nextval(...),
        # Postgres populates existing rows immediately (in heap order),
        # defeating our ordered backfill below.
        op.execute(
            f"ALTER TABLE {schema}.transcript_entries "
            f"ADD COLUMN IF NOT EXISTS server_sequence BIGINT"
        )

        # Backfill existing rows ordered by timestamp
        op.execute(
            f"WITH ordered AS ("
            f"  SELECT id, ROW_NUMBER() OVER (ORDER BY timestamp, id) AS seq "
            f"  FROM {schema}.transcript_entries "
            f"  WHERE server_sequence IS NULL"
            f") "
            f"UPDATE {schema}.transcript_entries e "
            f"SET server_sequence = o.seq "
            f"FROM ordered o WHERE e.id = o.id"
        )

        # Advance the sequence past the highest assigned value
        op.execute(
            f"SELECT setval('{schema}.entry_server_seq', "
            f"COALESCE((SELECT MAX(server_sequence) FROM {schema}.transcript_entries), 0))"
        )

        # Set default for new rows AFTER backfill + setval
        op.execute(
            f"ALTER TABLE {schema}.transcript_entries "
            f"ALTER COLUMN server_sequence SET DEFAULT nextval('{schema}.entry_server_seq')"
        )

        # Enforce NOT NULL now that all existing rows are backfilled
        op.execute(
            f"ALTER TABLE {schema}.transcript_entries "
            f"ALTER COLUMN server_sequence SET NOT NULL"
        )

        # Create index
        op.execute(
            f"CREATE INDEX IF NOT EXISTS idx_entries_server_seq "
            f"ON {schema}.transcript_entries(server_sequence)"
        )


def downgrade() -> None:
    conn = op.get_bind()
    result = conn.execute(
        sa.text(
            "SELECT schema_name FROM information_schema.schemata "
            "WHERE schema_name LIKE 'tenant_%'"
        )
    )
    schemas = [row[0] for row in result.fetchall()]

    for schema in schemas:
        if not _SCHEMA_NAME_RE.match(schema):
            continue
        op.execute(f"DROP INDEX IF EXISTS {schema}.idx_entries_server_seq")
        op.execute(
            f"ALTER TABLE {schema}.transcript_entries "
            f"DROP COLUMN IF EXISTS server_sequence"
        )
        op.execute(f"DROP SEQUENCE IF EXISTS {schema}.entry_server_seq")
