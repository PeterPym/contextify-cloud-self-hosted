"""Add invitations table to the public schema.

Revision ID: 004
Revises: 003
Create Date: 2026-02-22

Adds the invitations table for team member onboarding. The table lives in
the public schema (alongside users, tenants, api_keys) since invitations
reference users.id and are scoped by tenant_id.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "004"
down_revision: str = "003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "invitations",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "token",
            sa.dialects.postgresql.UUID(as_uuid=True),
            unique=True,
            nullable=False,
        ),
        sa.Column("email", sa.Text, nullable=False),
        sa.Column("role", sa.Text, nullable=False, server_default="member"),
        sa.Column(
            "invited_by",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.Text, nullable=False, server_default="pending"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "accepted_by_user_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.CheckConstraint(
            "role IN ('owner', 'admin', 'member', 'viewer')",
            name="ck_invitation_role",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'accepted', 'revoked')",
            name="ck_invitation_status",
        ),
    )

    # Indexes for common queries
    op.create_index(
        "idx_invitation_tenant_email",
        "invitations",
        ["tenant_id", "email"],
    )
    op.create_index(
        "idx_invitation_token",
        "invitations",
        ["token"],
    )
    # Partial unique index: prevent duplicate pending invites under concurrency
    op.create_index(
        "uq_invitation_pending_tenant_email",
        "invitations",
        ["tenant_id", "email"],
        unique=True,
        postgresql_where=sa.text("status = 'pending'"),
    )
    # Index for list_pending query pattern: WHERE (tenant_id, status) ORDER BY created_at
    op.create_index(
        "idx_invitation_tenant_status_created",
        "invitations",
        ["tenant_id", "status", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("idx_invitation_tenant_status_created", table_name="invitations")
    op.drop_index("uq_invitation_pending_tenant_email", table_name="invitations")
    op.drop_index("idx_invitation_token", table_name="invitations")
    op.drop_index("idx_invitation_tenant_email", table_name="invitations")
    op.drop_table("invitations")
