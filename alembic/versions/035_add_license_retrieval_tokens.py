"""Add the license_retrieval_tokens table (anonymous retrieval, ct-1966 Slice 5).

Short-lived, single-use tokens that let an account-less buyer retrieve their
Local Commercial license by purchase email via an emailed magic link.

Revision ID: 035
Revises: 034
Create Date: 2026-06-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "035"
down_revision: str | None = "034"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "license_retrieval_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("email_normalized", sa.Text(), nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash", name="uq_license_retrieval_tokens_token_hash"),
    )
    op.create_index(
        "idx_license_retrieval_tokens_email",
        "license_retrieval_tokens",
        [sa.text("lower(email_normalized)")],
    )
    op.create_index(
        "idx_license_retrieval_tokens_expires",
        "license_retrieval_tokens",
        ["expires_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "idx_license_retrieval_tokens_expires", table_name="license_retrieval_tokens"
    )
    op.drop_index(
        "idx_license_retrieval_tokens_email", table_name="license_retrieval_tokens"
    )
    op.drop_table("license_retrieval_tokens")
