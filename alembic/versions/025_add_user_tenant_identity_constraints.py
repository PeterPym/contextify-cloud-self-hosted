"""Add tenant-scoped user identity constraints.

Revision ID: 025
Revises: 024
Create Date: 2026-04-26
"""

from collections.abc import Sequence

from alembic import op

revision: str = "025"
down_revision: str | None = "024"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_unique_constraint("uq_user_id_tenant", "users", ["id", "tenant_id"])
    op.create_check_constraint(
        "ck_device_auth_user_tenant_pair",
        "device_authorizations",
        "(user_id IS NULL AND tenant_id IS NULL) "
        "OR (user_id IS NOT NULL AND tenant_id IS NOT NULL)",
    )
    op.create_foreign_key(
        "fk_api_keys_user_tenant",
        "api_keys",
        "users",
        ["user_id", "tenant_id"],
        ["id", "tenant_id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "fk_invitations_invited_by_tenant",
        "invitations",
        "users",
        ["invited_by", "tenant_id"],
        ["id", "tenant_id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "fk_invitations_accepted_by_tenant",
        "invitations",
        "users",
        ["accepted_by_user_id", "tenant_id"],
        ["id", "tenant_id"],
    )
    op.create_foreign_key(
        "fk_device_authorizations_user_tenant",
        "device_authorizations",
        "users",
        ["user_id", "tenant_id"],
        ["id", "tenant_id"],
        ondelete="CASCADE",
    )


def downgrade() -> None:
    op.drop_constraint(
        "fk_device_authorizations_user_tenant",
        "device_authorizations",
        type_="foreignkey",
    )
    op.drop_constraint(
        "fk_invitations_accepted_by_tenant",
        "invitations",
        type_="foreignkey",
    )
    op.drop_constraint(
        "fk_invitations_invited_by_tenant",
        "invitations",
        type_="foreignkey",
    )
    op.drop_constraint("fk_api_keys_user_tenant", "api_keys", type_="foreignkey")
    op.drop_constraint(
        "ck_device_auth_user_tenant_pair",
        "device_authorizations",
        type_="check",
    )
    op.drop_constraint("uq_user_id_tenant", "users", type_="unique")
