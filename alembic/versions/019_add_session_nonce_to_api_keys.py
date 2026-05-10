"""Add session_nonce column to api_keys for server-side session revocation.

The nonce is embedded in JWTs and validated on each request. Rotating the
nonce (on login, logout, or key rotation) instantly invalidates all
previously issued JWTs for that API key.

Revision ID: 019
Revises: 018
"""

import secrets

import sqlalchemy as sa

from alembic import op

revision = "019"
down_revision = "018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add column with empty-string server_default so NOT NULL works on existing rows
    op.add_column(
        "api_keys",
        sa.Column("session_nonce", sa.Text(), nullable=False, server_default=""),
    )

    # Backfill existing rows with unique Python-generated nonces (no pgcrypto needed)
    conn = op.get_bind()
    result = conn.execute(
        sa.text("SELECT id FROM api_keys WHERE session_nonce = ''")
    )
    for row in result:
        nonce = secrets.token_hex(16)
        conn.execute(
            sa.text("UPDATE api_keys SET session_nonce = :nonce WHERE id = :id"),
            {"nonce": nonce, "id": row[0]},
        )

    # Remove the server_default so new rows must provide a nonce via the app
    op.alter_column("api_keys", "session_nonce", server_default=None)


def downgrade() -> None:
    op.drop_column("api_keys", "session_nonce")
