"""Store invitation tokens as keyed hashes.

Revision ID: 023
Revises: 022
Create Date: 2026-04-26
"""

import hashlib
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op
from contextify_cloud.config import settings

revision: str = "023"
down_revision: str = "022"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _hash_token(raw_token: str) -> str:
    payload = f"{settings.api_secret_key}:{raw_token}".encode()
    return hashlib.sha256(payload).hexdigest()


def upgrade() -> None:
    op.add_column("invitations", sa.Column("token_hash", sa.Text(), nullable=True))

    bind = op.get_bind()
    rows = bind.execute(sa.text("SELECT id, token FROM invitations")).mappings()
    for row in rows:
        bind.execute(
            sa.text(
                "UPDATE invitations SET token_hash = :token_hash WHERE id = :id"
            ),
            {"token_hash": _hash_token(str(row["token"])), "id": row["id"]},
        )

    op.alter_column("invitations", "token_hash", nullable=False)
    op.create_index(
        "idx_invitation_token_hash",
        "invitations",
        ["token_hash"],
        unique=True,
    )
    op.drop_index("idx_invitation_token", table_name="invitations")
    op.drop_constraint("invitations_token_key", "invitations", type_="unique")
    op.drop_column("invitations", "token")


def downgrade() -> None:
    op.add_column(
        "invitations",
        sa.Column("token", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_index("idx_invitation_token", "invitations", ["token"], unique=False)
    op.create_unique_constraint("invitations_token_key", "invitations", ["token"])
    op.drop_index("idx_invitation_token_hash", table_name="invitations")
    op.drop_column("invitations", "token_hash")
