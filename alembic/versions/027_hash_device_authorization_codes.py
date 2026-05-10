"""Store device authorization lookup codes as keyed hashes.

Revision ID: 027
Revises: 026
Create Date: 2026-04-26
"""

import hashlib
import hmac
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op
from contextify_cloud.config import settings

revision: str = "027"
down_revision: str | None = "026"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _hash_code(kind: str, code: str) -> str:
    payload = f"contextify-device-auth:{kind}:{code}".encode()
    return hmac.new(
        settings.api_secret_key.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).hexdigest()


def upgrade() -> None:
    op.add_column(
        "device_authorizations",
        sa.Column("device_code_hash", sa.Text(), nullable=True),
    )
    op.add_column(
        "device_authorizations",
        sa.Column("user_code_hash", sa.Text(), nullable=True),
    )

    conn = op.get_bind()
    rows = conn.execute(
        sa.text("SELECT id, device_code, user_code FROM device_authorizations")
    ).mappings()
    for row in rows:
        values: dict[str, str] = {}
        if row["device_code"] is not None:
            values["device_code_hash"] = _hash_code("device", row["device_code"])
        if row["user_code"] is not None:
            values["user_code_hash"] = _hash_code("user", row["user_code"].strip().upper())
        if values:
            conn.execute(
                sa.text(
                    """
                    UPDATE device_authorizations
                    SET device_code_hash = :device_code_hash,
                        user_code_hash = :user_code_hash
                    WHERE id = :id
                    """
                ),
                {
                    "id": row["id"],
                    "device_code_hash": values.get("device_code_hash"),
                    "user_code_hash": values.get("user_code_hash"),
                },
            )

    op.alter_column("device_authorizations", "device_code", nullable=True)
    op.alter_column("device_authorizations", "user_code", nullable=True)
    op.create_index(
        "idx_device_auth_device_code_hash",
        "device_authorizations",
        ["device_code_hash"],
        unique=True,
    )
    op.create_index(
        "idx_device_auth_user_code_hash",
        "device_authorizations",
        ["user_code_hash"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("idx_device_auth_user_code_hash", table_name="device_authorizations")
    op.drop_index("idx_device_auth_device_code_hash", table_name="device_authorizations")
    op.execute(
        "DELETE FROM device_authorizations "
        "WHERE device_code IS NULL OR user_code IS NULL"
    )
    op.alter_column("device_authorizations", "user_code", nullable=False)
    op.alter_column("device_authorizations", "device_code", nullable=False)
    op.drop_column("device_authorizations", "user_code_hash")
    op.drop_column("device_authorizations", "device_code_hash")
