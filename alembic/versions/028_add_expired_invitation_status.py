"""Add explicit expired invitation status.

Revision ID: 028
Revises: 027
Create Date: 2026-04-26
"""

from collections.abc import Sequence

from alembic import op

revision: str = "028"
down_revision: str = "027"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint("ck_invitation_status", "invitations", type_="check")
    op.create_check_constraint(
        "ck_invitation_status",
        "invitations",
        "status IN ('pending', 'accepted', 'revoked', 'expired')",
    )


def downgrade() -> None:
    op.execute("UPDATE invitations SET status = 'revoked' WHERE status = 'expired'")
    op.drop_constraint("ck_invitation_status", "invitations", type_="check")
    op.create_check_constraint(
        "ck_invitation_status",
        "invitations",
        "status IN ('pending', 'accepted', 'revoked')",
    )
