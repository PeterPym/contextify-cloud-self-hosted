"""Reconcile auth schema drift detected by alembic check.

Migration 025 added composite tenant-scoped FKs (`fk_api_keys_user_tenant`,
`fk_invitations_invited_by_tenant`, `fk_device_authorizations_user_tenant`)
but did NOT drop the original single-column FKs from earlier migrations
(`api_keys_user_id_fkey`, `invitations_invited_by_fkey`,
`device_authorizations_user_id_fkey`). The model layer only declares the
composite FKs, so alembic check reports drift on every CI run.

Migration 029 created the four `internal_support_audit_log` indexes with
plain `created_at`, but the model layer declares them as `created_at DESC`
(matching the actual query pattern: most-recent-first scans).

This migration:
  - Drops the superseded single-column FKs.
  - Recreates the four audit-log indexes with `created_at DESC`.

Revision ID: 030
Revises: 029
Create Date: 2026-04-26
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "030"
down_revision: str | None = "029"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_AUDIT_TABLE = "internal_support_audit_log"


def upgrade() -> None:
    # Drop single-column FKs superseded by composite tenant-scoped FKs in 025.
    # These were left behind during the auth pivot; the model layer no longer
    # declares them, so alembic check reports drift until they are gone.
    op.drop_constraint("api_keys_user_id_fkey", "api_keys", type_="foreignkey")
    op.drop_constraint(
        "device_authorizations_user_id_fkey",
        "device_authorizations",
        type_="foreignkey",
    )
    op.drop_constraint(
        "invitations_invited_by_fkey",
        "invitations",
        type_="foreignkey",
    )

    # Reconcile internal_support_audit_log indexes to match the model
    # layer's `created_at DESC` ordering (most-recent-first scans).
    op.drop_index("idx_internal_support_audit_tenant_created", table_name=_AUDIT_TABLE)
    op.drop_index("idx_internal_support_audit_account_created", table_name=_AUDIT_TABLE)
    op.drop_index("idx_internal_support_audit_operator_created", table_name=_AUDIT_TABLE)
    op.drop_index("idx_internal_support_audit_created", table_name=_AUDIT_TABLE)

    op.create_index(
        "idx_internal_support_audit_created",
        _AUDIT_TABLE,
        [sa.text("created_at DESC")],
    )
    op.create_index(
        "idx_internal_support_audit_operator_created",
        _AUDIT_TABLE,
        ["operator_id", sa.text("created_at DESC")],
    )
    op.create_index(
        "idx_internal_support_audit_account_created",
        _AUDIT_TABLE,
        ["target_account_id", sa.text("created_at DESC")],
    )
    op.create_index(
        "idx_internal_support_audit_tenant_created",
        _AUDIT_TABLE,
        ["target_tenant_id", sa.text("created_at DESC")],
    )


def downgrade() -> None:
    op.drop_index("idx_internal_support_audit_tenant_created", table_name=_AUDIT_TABLE)
    op.drop_index("idx_internal_support_audit_account_created", table_name=_AUDIT_TABLE)
    op.drop_index("idx_internal_support_audit_operator_created", table_name=_AUDIT_TABLE)
    op.drop_index("idx_internal_support_audit_created", table_name=_AUDIT_TABLE)

    op.create_index(
        "idx_internal_support_audit_created",
        _AUDIT_TABLE,
        ["created_at"],
    )
    op.create_index(
        "idx_internal_support_audit_operator_created",
        _AUDIT_TABLE,
        ["operator_id", "created_at"],
    )
    op.create_index(
        "idx_internal_support_audit_account_created",
        _AUDIT_TABLE,
        ["target_account_id", "created_at"],
    )
    op.create_index(
        "idx_internal_support_audit_tenant_created",
        _AUDIT_TABLE,
        ["target_tenant_id", "created_at"],
    )

    op.create_foreign_key(
        "invitations_invited_by_fkey",
        "invitations",
        "users",
        ["invited_by"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "device_authorizations_user_id_fkey",
        "device_authorizations",
        "users",
        ["user_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "api_keys_user_id_fkey",
        "api_keys",
        "users",
        ["user_id"],
        ["id"],
        ondelete="CASCADE",
    )
