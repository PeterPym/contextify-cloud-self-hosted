"""Add project_allowlist column to tenants table.

Supports per-tenant project filtering:
  - NULL: no restriction (allow all projects)
  - Empty array: block all projects
  - Non-empty array: only allow listed project names

Revision ID: 006
Revises: 005
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY

from alembic import op

revision = "006"
down_revision = "005"


def upgrade() -> None:
    op.add_column(
        "tenants",
        sa.Column(
            "project_allowlist",
            ARRAY(sa.String),
            nullable=True,
            server_default=None,
        ),
    )


def downgrade() -> None:
    op.drop_column("tenants", "project_allowlist")
