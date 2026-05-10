"""Add search_vector tsvector column and GIN index to transcript_entries.

Revision ID: 003
Revises: 002
Create Date: 2026-02-22

Adds PostgreSQL full-text search support to existing tenant schemas:
- search_vector TSVECTOR column (GENERATED ALWAYS AS for auto-population)
- GIN index on search_vector for fast ts_rank/tsquery lookups

New tenant schemas already include these via the schema template (tenant.py).
This migration backfills existing tenants created before the template update.
"""

import re
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

_SCHEMA_NAME_RE = re.compile(r"^tenant_[a-z0-9_]+$")

revision: str = "003"
down_revision: str = "002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
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

        # Check if column already exists (idempotent for schemas created after
        # the template was updated to include search_vector).
        col_check = conn.execute(
            sa.text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = :schema "
                "AND table_name = 'transcript_entries' "
                "AND column_name = 'search_vector'"
            ),
            {"schema": schema},
        )
        if col_check.fetchone():
            # Column exists; ensure GIN index exists too, then skip.
            op.execute(
                f"CREATE INDEX IF NOT EXISTS idx_entries_search "
                f"ON {schema}.transcript_entries USING GIN(search_vector)"
            )
            continue

        # Add generated tsvector column. PostgreSQL 12+ supports GENERATED
        # ALWAYS AS ... STORED, which auto-populates from existing content
        # and auto-updates on future INSERT/UPDATE -- no trigger needed.
        op.execute(
            f"ALTER TABLE {schema}.transcript_entries "
            f"ADD COLUMN search_vector TSVECTOR GENERATED ALWAYS AS ("
            f"to_tsvector('english', coalesce(content, ''))"
            f") STORED"
        )

        # Create GIN index for fast full-text search queries.
        op.execute(
            f"CREATE INDEX IF NOT EXISTS idx_entries_search "
            f"ON {schema}.transcript_entries USING GIN(search_vector)"
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
        op.execute(f"DROP INDEX IF EXISTS {schema}.idx_entries_search")
        op.execute(
            f"ALTER TABLE {schema}.transcript_entries "
            f"DROP COLUMN IF EXISTS search_vector"
        )
