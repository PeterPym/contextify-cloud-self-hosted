"""Add device_authorizations table for RFC 8628 device flow auth.

Stores pending device authorization requests. The CLI initiates a request,
the user authorizes in the browser, and the CLI polls until completion.

Revision ID: 012
Revises: 011
"""

import sqlalchemy as sa

from alembic import op

revision = "012"
down_revision = "011"


def upgrade() -> None:
    op.create_table(
        "device_authorizations",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("device_code", sa.Text, nullable=False, unique=True),
        sa.Column("user_code", sa.Text, nullable=False, unique=True),
        sa.Column("verification_uri", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False, server_default=sa.text("'pending'")),
        sa.Column("user_id", sa.dialects.postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=True),
        sa.Column("tenant_id", sa.dialects.postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True),
        sa.Column("issued_api_key_id", sa.dialects.postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("api_keys.id", ondelete="SET NULL"), nullable=True),
        sa.Column("client_name", sa.Text, nullable=True),
        sa.Column("client_ip", sa.Text, nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("poll_interval", sa.Integer, nullable=False, server_default=sa.text("5")),
        sa.Column("last_polled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.CheckConstraint(
            "status IN ('pending', 'authorized', 'completed', 'expired', 'denied')",
            name="ck_device_auth_status",
        ),
    )
    op.create_index("idx_device_auth_user_code", "device_authorizations", ["user_code"])
    op.create_index("idx_device_auth_device_code", "device_authorizations", ["device_code"])
    op.create_index("idx_device_auth_expires", "device_authorizations", ["expires_at"])


def downgrade() -> None:
    op.drop_index("idx_device_auth_expires", table_name="device_authorizations")
    op.drop_index("idx_device_auth_device_code", table_name="device_authorizations")
    op.drop_index("idx_device_auth_user_code", table_name="device_authorizations")
    op.drop_table("device_authorizations")
