"""Machine groups, historical membership and join-only enrollment tokens.

Revision ID: 044
Revises: 043
"""

from alembic import op

revision = "044"
down_revision = "043"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""CREATE TABLE machine_groups (
	id UUID NOT NULL,
	tenant_id UUID NOT NULL,
	owner_user_id UUID NOT NULL,
	visibility TEXT NOT NULL,
	name TEXT NOT NULL,
	normalized_name TEXT NOT NULL,
	project_selector JSONB,
	revision BIGINT DEFAULT '0' NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	PRIMARY KEY (id),
	CONSTRAINT ck_machine_group_visibility CHECK (visibility IN ('private', 'team')),
	FOREIGN KEY(tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
	FOREIGN KEY(owner_user_id) REFERENCES users (id) ON DELETE CASCADE
)""")
    op.execute(
        """CREATE UNIQUE INDEX uq_machine_group_private
        ON machine_groups (owner_user_id, normalized_name) WHERE visibility = 'private'"""
    )
    op.execute(
        """CREATE UNIQUE INDEX uq_machine_group_team
        ON machine_groups (tenant_id, normalized_name) WHERE visibility = 'team'"""
    )
    op.execute("""CREATE TABLE machine_group_devices (
	group_id UUID NOT NULL,
	device_record_id UUID NOT NULL,
	state TEXT DEFAULT 'active' NOT NULL,
	joined_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	retired_at TIMESTAMP WITH TIME ZONE,
	PRIMARY KEY (group_id, device_record_id),
	CONSTRAINT ck_machine_group_device_state CHECK (state IN ('active', 'retired')),
	FOREIGN KEY(group_id) REFERENCES machine_groups (id) ON DELETE CASCADE,
	FOREIGN KEY(device_record_id) REFERENCES devices (id) ON DELETE CASCADE
)""")
    op.execute(
        """CREATE INDEX idx_machine_group_device ON machine_group_devices (device_record_id)"""
    )
    op.execute("""CREATE TABLE machine_group_join_tokens (
	id UUID NOT NULL,
	group_id UUID NOT NULL,
	issuer_user_id UUID NOT NULL,
	create_request_id UUID NOT NULL,
	secret_hash TEXT NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
	revoked_at TIMESTAMP WITH TIME ZONE,
	max_uses INTEGER NOT NULL,
	uses INTEGER DEFAULT '0' NOT NULL,
	delivery_acknowledged_at TIMESTAMP WITH TIME ZONE,
	PRIMARY KEY (id),
	CONSTRAINT uq_machine_group_token_request UNIQUE (group_id, issuer_user_id, create_request_id),
	CONSTRAINT ck_machine_group_token_uses
        CHECK (max_uses BETWEEN 1 AND 100 AND uses BETWEEN 0 AND max_uses),
	FOREIGN KEY(group_id) REFERENCES machine_groups (id) ON DELETE CASCADE,
	FOREIGN KEY(issuer_user_id) REFERENCES users (id) ON DELETE CASCADE
)""")
    op.execute("""CREATE TABLE machine_group_token_redemptions (
	token_id UUID NOT NULL,
	device_record_id UUID NOT NULL,
	redeemed_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
	PRIMARY KEY (token_id, device_record_id),
	FOREIGN KEY(token_id) REFERENCES machine_group_join_tokens (id) ON DELETE CASCADE,
	FOREIGN KEY(device_record_id) REFERENCES devices (id) ON DELETE CASCADE
)""")


def downgrade() -> None:
    raise RuntimeError("Retain group history on code rollback; migration is forward-only")
