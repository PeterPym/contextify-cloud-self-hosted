"""Add is_internal flag to tenants table.

Adds a boolean is_internal column so downstream analytics/billing code can
exclude QA/test/developer accounts. Marks the qa_linux_ci tenant as
internal in a data migration step.

Revision ID: 018
Revises: 017
"""

import sqlalchemy as sa

from alembic import op

revision = "018"
down_revision = "017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "tenants",
        sa.Column(
            "is_internal",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )

    # Mark known internal tenants.
    op.execute(
        sa.text("UPDATE tenants SET is_internal = true WHERE slug = 'qa_linux_ci'")
    )


def downgrade() -> None:
    op.drop_column("tenants", "is_internal")
