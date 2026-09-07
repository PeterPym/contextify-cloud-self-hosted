"""Add disposable hosted-QA run lifecycle (ct-4134).

Revision ID: 042
Revises: 041
Create Date: 2026-08-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "042"
down_revision: str | None = "041"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "qa_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("account_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("state", sa.Text(), server_default="active", nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("failure_class", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "state IN ('active', 'tearing_down', 'teardown_failed')",
            name="ck_qa_runs_state",
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["account_id"], ["accounts.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["user_id", "account_id", "tenant_id"],
            ["users.id", "users.account_id", "users.tenant_id"],
            name="fk_qa_runs_user_account_tenant",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id"),
        sa.UniqueConstraint("account_id"),
        sa.UniqueConstraint("user_id"),
    )
    op.create_index("idx_qa_runs_expiry", "qa_runs", ["state", "expires_at"])
    op.create_table(
        "qa_identity_slots",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("identity_slot", sa.Text(), nullable=False),
        sa.Column("device_authorization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("issued_api_key_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(identity_slot) BETWEEN 1 AND 32", name="ck_qa_identity_slot_name"
        ),
        sa.ForeignKeyConstraint(["run_id"], ["qa_runs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["device_authorization_id"], ["device_authorizations.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(["issued_api_key_id"], ["api_keys.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("device_authorization_id"),
        sa.UniqueConstraint("issued_api_key_id"),
        sa.UniqueConstraint("run_id", "identity_slot", name="uq_qa_identity_slot_run_name"),
    )
    op.create_table(
        "qa_run_tombstones",
        sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_slug", sa.Text(), nullable=False),
        sa.Column("account_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_commit", sa.Text(), nullable=False),
        sa.CheckConstraint(
            "length(tenant_slug) BETWEEN 1 AND 63", name="ck_qa_tombstone_tenant_slug"
        ),
        sa.CheckConstraint("length(source_commit) = 40", name="ck_qa_tombstone_source_commit"),
        sa.PrimaryKeyConstraint("run_id"),
        sa.UniqueConstraint("tenant_id"),
        sa.UniqueConstraint("tenant_slug"),
        sa.UniqueConstraint("account_id"),
        sa.UniqueConstraint("user_id"),
    )


def downgrade() -> None:
    op.drop_table("qa_run_tombstones")
    op.drop_table("qa_identity_slots")
    op.drop_index("idx_qa_runs_expiry", table_name="qa_runs")
    op.drop_table("qa_runs")
