"""ct-5459: versioned repository evidence in every tenant schema.

Adds, per tenant schema: projects.lane_name, transcript_entries.source_project_id,
the repo_evidence_seq sequence and the repo_evidence table. Every statement is
additive and metadata-only (nullable columns without defaults, new objects), so
it is fast on large tenants and idempotent. The request-time compatibility path
in services/tenant.py applies the same statements to schemas created later.

Revision ID: 045
Revises: 044
"""

import re

import sqlalchemy as sa

from alembic import op

revision = "045"
down_revision = "044"
branch_labels = None
depends_on = None

_SCHEMA_RE = re.compile(r"^tenant_[a-z0-9_]+$")

_UPGRADE = (
    "ALTER TABLE {s}.projects ADD COLUMN IF NOT EXISTS lane_name TEXT",
    "ALTER TABLE {s}.transcript_entries ADD COLUMN IF NOT EXISTS source_project_id TEXT",
    "CREATE SEQUENCE IF NOT EXISTS {s}.repo_evidence_seq",
    """CREATE TABLE IF NOT EXISTS {s}.repo_evidence (
        source_project_id TEXT NOT NULL,
        source_machine_id TEXT NOT NULL,
        uploaded_by_user_id UUID NOT NULL,
        evidence_hash TEXT NOT NULL,
        project_id TEXT NOT NULL REFERENCES {s}.projects(id) ON DELETE CASCADE,
        device_id UUID,
        key_version INTEGER,
        origin_key TEXT,
        common_dir_key TEXT,
        legacy_repo_group_key TEXT,
        lane_root TEXT,
        checkout_root TEXT,
        first_seq BIGINT NOT NULL,
        last_seq BIGINT NOT NULL,
        first_seen_at BIGINT NOT NULL,
        last_seen_at BIGINT NOT NULL,
        PRIMARY KEY (source_project_id, source_machine_id, uploaded_by_user_id, evidence_hash)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_repo_evidence_project ON {s}.repo_evidence(project_id)",
)


def _tenant_schemas() -> list[str]:
    rows = (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT schema_name FROM information_schema.schemata "
                "WHERE schema_name LIKE 'tenant\\_%'"
            )
        )
        .fetchall()
    )
    schemas = [row[0] for row in rows]
    for schema in schemas:
        if not _SCHEMA_RE.fullmatch(schema):
            raise ValueError(f"Invalid tenant schema name: {schema!r}")
    return schemas


def _has_table(schema: str, table: str) -> bool:
    return bool(
        op.get_bind()
        .execute(
            sa.text(
                "SELECT 1 FROM information_schema.tables "
                "WHERE table_schema = :s AND table_name = :t"
            ),
            {"s": schema, "t": table},
        )
        .scalar()
    )


def upgrade() -> None:
    for schema in _tenant_schemas():
        # Skip half-provisioned schemas; request-time compat covers them later.
        if not (_has_table(schema, "projects") and _has_table(schema, "transcript_entries")):
            continue
        for statement in _UPGRADE:
            op.execute(sa.text(statement.replace("{s}", schema)))


def downgrade() -> None:
    for schema in _tenant_schemas():
        op.execute(sa.text(f"DROP TABLE IF EXISTS {schema}.repo_evidence"))
        op.execute(sa.text(f"DROP SEQUENCE IF EXISTS {schema}.repo_evidence_seq"))
        op.execute(
            sa.text(
                f"ALTER TABLE {schema}.transcript_entries DROP COLUMN IF EXISTS source_project_id"
            )
        )
        op.execute(sa.text(f"ALTER TABLE {schema}.projects DROP COLUMN IF EXISTS lane_name"))
