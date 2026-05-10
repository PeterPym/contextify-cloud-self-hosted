"""Initial schema - public tables for tenants, users, devices, api_keys, usage_events.

Revision ID: 001
Revises:
Create Date: 2026-02-19

Per-tenant schemas are created dynamically by the tenant provisioning service.
This migration only creates the shared public schema tables.

Key design decisions reflected in this migration:
- API keys use split key_id/secret pattern: key_id for O(1) lookup,
  bcrypt hash of secret for verification. Prevents enumeration attacks.
- Soft-delete for API key revocation (revoked_at) preserves audit trail.
- Tenant deletion_requested_at supports GDPR/CCPA data subject requests.
- data_retention_days enables per-tenant retention policy overrides.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY, UUID

from alembic import op

revision: str = "001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Enable pgcrypto for gen_random_uuid() used in server_default expressions
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    # Tenants
    op.create_table(
        "tenants",
        sa.Column(
            "id", UUID(as_uuid=True), primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("slug", sa.Text(), unique=True, nullable=False),
        sa.Column("plan", sa.Text(), nullable=False, server_default="free"),
        sa.Column("stripe_customer_id", sa.Text(), unique=True),
        sa.Column("stripe_subscription_id", sa.Text()),
        sa.Column("max_seats", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("deletion_requested_at", sa.DateTime(timezone=True)),
        sa.Column("data_retention_days", sa.Integer(), nullable=False, server_default="0"),
        sa.CheckConstraint("plan IN ('free', 'pro', 'team', 'enterprise')", name="ck_tenant_plan"),
    )

    # Users
    op.create_table(
        "users",
        sa.Column(
            "id", UUID(as_uuid=True), primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "tenant_id", UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("email", sa.Text(), nullable=False),
        sa.Column("name", sa.Text()),
        sa.Column("role", sa.Text(), nullable=False, server_default="member"),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint("tenant_id", "email", name="uq_user_tenant_email"),
        sa.CheckConstraint("role IN ('owner', 'admin', 'member', 'viewer')", name="ck_user_role"),
    )

    # Devices
    op.create_table(
        "devices",
        sa.Column(
            "id", UUID(as_uuid=True), primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "user_id", UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("machine_name", sa.Text(), nullable=False),
        sa.Column("machine_id", sa.Text(), nullable=False),
        sa.Column("os", sa.Text()),
        sa.Column("app_version", sa.Text()),
        sa.Column("last_sync_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint("user_id", "machine_id", name="uq_device_user_machine"),
    )

    # API Keys - split key_id/secret pattern
    op.create_table(
        "api_keys",
        sa.Column(
            "id", UUID(as_uuid=True), primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "user_id", UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "tenant_id", UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("key_id", sa.Text(), unique=True, nullable=False),
        sa.Column("key_hash", sa.Text(), nullable=False),
        sa.Column("key_prefix", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False, server_default="Default"),
        sa.Column("scopes", ARRAY(sa.String), nullable=False, server_default="{}"),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False,
            server_default=sa.text("now()"),
        ),
    )

    # Usage Events
    op.create_table(
        "usage_events",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "tenant_id", UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("entry_count", sa.Integer(), server_default="0"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False,
            server_default=sa.text("now()"),
        ),
    )

    op.create_index("idx_usage_tenant_date", "usage_events", ["tenant_id", "created_at"])

    # Sync Idempotency - prevents duplicate request processing on retries
    op.create_table(
        "sync_idempotency",
        sa.Column(
            "id", UUID(as_uuid=True), primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "tenant_id", UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("key_id", sa.Text(), nullable=False),
        sa.Column("idempotency_key", sa.Text(), nullable=False),
        sa.Column("request_sha256", sa.Text(), nullable=False),
        sa.Column("response_json", sa.Text()),
        sa.Column("is_complete", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "key_id", "idempotency_key", name="uq_idempotency_key"),
    )
    op.create_index("idx_idempotency_expires", "sync_idempotency", ["expires_at"])


def downgrade() -> None:
    op.drop_table("sync_idempotency")
    op.drop_table("usage_events")
    op.drop_table("api_keys")
    op.drop_table("devices")
    op.drop_table("users")
    op.drop_table("tenants")
