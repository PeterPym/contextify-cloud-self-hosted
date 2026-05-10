"""Enforce unique active auth tokens per workflow.

Revision ID: 026
Revises: 025
Create Date: 2026-04-26
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "026"
down_revision: str | None = "025"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _consume_duplicate_active_tokens(partition_column: str, null_predicate: str) -> None:
    op.execute(
        sa.text(
            f"""
            WITH ranked AS (
                SELECT
                    id,
                    row_number() OVER (
                        PARTITION BY {partition_column}, purpose
                        ORDER BY created_at DESC, id DESC
                    ) AS rn
                FROM auth_tokens
                WHERE consumed_at IS NULL
                  AND {null_predicate}
            )
            UPDATE auth_tokens
            SET consumed_at = now()
            FROM ranked
            WHERE auth_tokens.id = ranked.id
              AND ranked.rn > 1
            """
        )
    )


def upgrade() -> None:
    _consume_duplicate_active_tokens("account_id", "account_id IS NOT NULL")
    _consume_duplicate_active_tokens("email_normalized", "account_id IS NULL")
    op.create_index(
        "uq_auth_tokens_active_account_purpose",
        "auth_tokens",
        ["account_id", "purpose"],
        unique=True,
        postgresql_where=sa.text("consumed_at IS NULL AND account_id IS NOT NULL"),
    )
    op.create_index(
        "uq_auth_tokens_active_email_purpose_no_account",
        "auth_tokens",
        ["email_normalized", "purpose"],
        unique=True,
        postgresql_where=sa.text("consumed_at IS NULL AND account_id IS NULL"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_auth_tokens_active_email_purpose_no_account",
        table_name="auth_tokens",
    )
    op.drop_index("uq_auth_tokens_active_account_purpose", table_name="auth_tokens")
