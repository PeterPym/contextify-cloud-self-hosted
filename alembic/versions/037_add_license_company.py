"""Add licenses.company for Self-Hosted Pro named-licensee (ct-2313).

Self-Hosted Pro is a named-licensee commercial license: the company (the
Licensee named at checkout) is collected and embedded as the minted token's
``customer`` claim. Nullable, go-forward only: existing Local Commercial rows
stay NULL (they are email-only, not named-licensee).

Revision ID: 037
Revises: 036
Create Date: 2026-06-22
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "037"
down_revision: str | None = "036"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("licenses", sa.Column("company", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("licenses", "company")
