"""Add purge infrastructure: tenant status/purge columns and deleted_tenants tombstone table.

Adds lifecycle status tracking to tenants (status, purge_due_at, deletion_trigger)
and creates the deleted_tenants tombstone table for retaining minimal legal/accounting
records after tenant data is purged.

Revision ID: 017
Revises: 016
"""

import sqlalchemy as sa

from alembic import op

revision = "017"
down_revision = "016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- Tenant table: add purge-related columns ---
    op.add_column(
        "tenants",
        sa.Column(
            "status",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'active'"),
        ),
    )
    op.add_column(
        "tenants",
        sa.Column("purge_due_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "tenants",
        sa.Column("deletion_trigger", sa.Text(), nullable=True),
    )

    # Check constraints for new columns
    op.create_check_constraint(
        "ck_tenant_status",
        "tenants",
        "status IN ('active', 'deletion_scheduled', 'purge_in_progress')",
    )
    op.create_check_constraint(
        "ck_tenant_deletion_trigger",
        "tenants",
        "deletion_trigger IS NULL OR "
        "deletion_trigger IN ('explicit_delete', 'subscription_end')",
    )

    # Partial index for efficient purge candidate lookup
    op.create_index(
        "idx_tenant_purge_due",
        "tenants",
        ["purge_due_at"],
        postgresql_where=sa.text("status = 'deletion_scheduled'"),
    )

    # --- Create deleted_tenants tombstone table ---
    op.create_table(
        "deleted_tenants",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "tenant_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            nullable=False,
            unique=True,
        ),
        sa.Column("slug", sa.Text, nullable=False),
        sa.Column("owner_email", sa.Text, nullable=False),
        sa.Column("plan", sa.Text, nullable=False),
        sa.Column("stripe_customer_id", sa.Text, nullable=True),
        sa.Column("stripe_subscription_id", sa.Text, nullable=True),
        sa.Column("billing_interval", sa.Text, nullable=True),
        sa.Column("deletion_trigger", sa.Text, nullable=False),
        sa.Column(
            "deletion_requested_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "purge_due_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("purged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "tombstone_expires_at", sa.DateTime(timezone=True), nullable=True
        ),
        sa.Column(
            "requested_by_user_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(
            "deletion_trigger IN ('explicit_delete', 'subscription_end')",
            name="ck_deleted_tenant_trigger",
        ),
    )
    op.create_index(
        "idx_deleted_tenant_tombstone_expires",
        "deleted_tenants",
        ["tombstone_expires_at"],
        postgresql_where=sa.text("purged_at IS NOT NULL"),
    )
    op.create_index(
        "idx_deleted_tenant_stripe_customer",
        "deleted_tenants",
        ["stripe_customer_id"],
    )


def downgrade() -> None:
    # Drop deleted_tenants indexes and table
    op.drop_index(
        "idx_deleted_tenant_stripe_customer", table_name="deleted_tenants"
    )
    op.drop_index(
        "idx_deleted_tenant_tombstone_expires", table_name="deleted_tenants"
    )
    op.drop_table("deleted_tenants")

    # Drop tenant purge columns, constraints, and index
    op.drop_index("idx_tenant_purge_due", table_name="tenants")
    op.drop_constraint("ck_tenant_deletion_trigger", "tenants", type_="check")
    op.drop_constraint("ck_tenant_status", "tenants", type_="check")
    op.drop_column("tenants", "deletion_trigger")
    op.drop_column("tenants", "purge_due_at")
    op.drop_column("tenants", "status")
