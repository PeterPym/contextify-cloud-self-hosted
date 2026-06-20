"""SQLAlchemy models for the public schema (shared across all tenants)."""

import enum
import secrets
import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class TenantStatus(enum.StrEnum):
    """Lifecycle status for a tenant account."""

    active = "active"
    deletion_scheduled = "deletion_scheduled"
    purge_in_progress = "purge_in_progress"


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    slug: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    plan: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="free",
    )
    billing_interval: Mapped[str] = mapped_column(
        Text, nullable=False, default="month"
    )
    stripe_customer_id: Mapped[str | None] = mapped_column(Text, unique=True)
    stripe_subscription_id: Mapped[str | None] = mapped_column(Text)
    max_seats: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    subscription_status: Mapped[str] = mapped_column(
        Text, nullable=False, default="active"
    )
    current_period_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    current_period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancel_at_period_end: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.now, onupdate=datetime.now
    )
    # Data privacy: supports GDPR/CCPA deletion requests.
    # When set, background job should purge tenant data within retention window.
    deletion_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Retention policy in days (0 = use system default). Per-tenant override.
    data_retention_days: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Tenant lifecycle status. Controls API access gating.
    status: Mapped[str] = mapped_column(
        Text, nullable=False, default="active", server_default="active",
    )
    # Purge scheduling: computed deadline for data destruction.
    purge_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Tracks why deletion was triggered (explicit user action vs subscription end).
    deletion_trigger: Mapped[str | None] = mapped_column(Text)
    # Project allow-list: NULL = allow all, [] = block all, [...] = only listed names.
    project_allowlist: Mapped[list[str] | None] = mapped_column(
        ARRAY(String), nullable=True
    )
    # Internal flag for downstream analytics/billing exclusion logic.
    # Used for QA, test, and developer accounts.
    is_internal: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false"),
    )
    # ct-2107: fire-once marker for the second_device_sync activation North-Star.
    # Set exactly once (NULL -> timestamp) when a tenant's 2nd distinct device
    # completes its first sync, claimed atomically under a per-tenant advisory lock
    # in the sync router so concurrent first-syncs neither double-fire nor miss.
    second_device_synced_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )

    users: Mapped[list["User"]] = relationship(
        back_populates="tenant", cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint("plan IN ('free', 'pro', 'team', 'enterprise')", name="ck_tenant_plan"),
        CheckConstraint(
            "billing_interval IN ('month', 'year')",
            name="ck_tenant_billing_interval",
        ),
        CheckConstraint(
            "subscription_status IN ("
            "'trialing', 'active', 'past_due', 'unpaid', 'canceled', "
            "'archived', 'incomplete', 'incomplete_expired', 'paused')",
            name="ck_tenant_subscription_status",
        ),
        CheckConstraint(
            "status IN ('active', 'deletion_scheduled', 'purge_in_progress')",
            name="ck_tenant_status",
        ),
        CheckConstraint(
            "deletion_trigger IS NULL OR "
            "deletion_trigger IN ('explicit_delete', 'subscription_end')",
            name="ck_tenant_deletion_trigger",
        ),
        Index(
            "idx_tenant_purge_due",
            "purge_due_at",
            postgresql_where=text("status = 'deletion_scheduled'"),
        ),
    )


class DeletedTenant(Base):
    """Tombstone record for purged tenants.

    Retains minimal legal/accounting fields for 12 months per
    Privacy Policy section 5. Hard-deleted by the purge service
    after tombstone_expires_at.
    """

    __tablename__ = "deleted_tenants"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, unique=True
    )
    slug: Mapped[str] = mapped_column(Text, nullable=False)
    owner_email: Mapped[str] = mapped_column(Text, nullable=False)
    plan: Mapped[str] = mapped_column(Text, nullable=False)
    stripe_customer_id: Mapped[str | None] = mapped_column(Text)
    stripe_subscription_id: Mapped[str | None] = mapped_column(Text)
    billing_interval: Mapped[str | None] = mapped_column(Text)
    deletion_trigger: Mapped[str] = mapped_column(Text, nullable=False)
    deletion_requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    purge_due_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    purged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    tombstone_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True)
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    __table_args__ = (
        CheckConstraint(
            "deletion_trigger IN ('explicit_delete', 'subscription_end')",
            name="ck_deleted_tenant_trigger",
        ),
        Index(
            "idx_deleted_tenant_tombstone_expires",
            "tombstone_expires_at",
            postgresql_where=text("purged_at IS NOT NULL"),
        ),
        Index("idx_deleted_tenant_stripe_customer", "stripe_customer_id"),
    )


class Account(Base):
    """Global human login identity for browser authentication."""

    __tablename__ = "accounts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email_normalized: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    email_display: Mapped[str] = mapped_column(Text, nullable=False)
    password_hash: Mapped[str | None] = mapped_column(Text)
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(
        Text, nullable=False, default="active", server_default="active"
    )
    session_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default=text("1")
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    tos_accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    tos_version: Mapped[str | None] = mapped_column(Text)
    tos_ip: Mapped[str | None] = mapped_column(Text)
    tos_user_agent: Mapped[str | None] = mapped_column(Text)
    password_prompt_dismissed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    users: Mapped[list["User"]] = relationship(back_populates="account")
    sessions: Mapped[list["UserSession"]] = relationship(
        back_populates="account", cascade="all, delete-orphan"
    )
    auth_tokens: Mapped[list["AuthToken"]] = relationship(
        back_populates="account", cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('active', 'password_unset', 'disabled')",
            name="ck_account_status",
        ),
        Index("idx_accounts_email_normalized", "email_normalized"),
    )


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    account_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("accounts.id", ondelete="SET NULL"), nullable=True
    )
    email: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str | None] = mapped_column(Text)
    role: Mapped[str] = mapped_column(Text, nullable=False, default="member")
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    consent_given_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.now
    )

    tenant: Mapped["Tenant"] = relationship(back_populates="users")
    account: Mapped["Account | None"] = relationship(back_populates="users")
    devices: Mapped[list["Device"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    api_keys: Mapped[list["ApiKey"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "email", name="uq_user_tenant_email"),
        UniqueConstraint("id", "tenant_id", name="uq_user_id_tenant"),
        UniqueConstraint("id", "account_id", "tenant_id", name="uq_user_account_tenant"),
        CheckConstraint(
            "role IN ('owner', 'admin', 'member', 'viewer')", name="ck_user_role"
        ),
        Index("idx_users_account_id", "account_id"),
        Index(
            "uq_users_active_tenant_account",
            "tenant_id",
            "account_id",
            unique=True,
            postgresql_where=text("removed_at IS NULL AND account_id IS NOT NULL"),
        ),
    )


class UserSession(Base):
    """Server-side browser session record for dashboard auth."""

    __tablename__ = "user_sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    account_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    session_nonce: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_reauthenticated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ip_address: Mapped[str | None] = mapped_column(Text)
    user_agent: Mapped[str | None] = mapped_column(Text)

    account: Mapped["Account"] = relationship(back_populates="sessions")
    tenant: Mapped["Tenant"] = relationship()
    user: Mapped["User"] = relationship(viewonly=True)

    __table_args__ = (
        ForeignKeyConstraint(
            ["user_id", "account_id", "tenant_id"],
            ["users.id", "users.account_id", "users.tenant_id"],
            name="fk_user_sessions_user_account_tenant",
            ondelete="CASCADE",
        ),
        Index("idx_user_sessions_account", "account_id"),
        Index("idx_user_sessions_user", "user_id"),
        Index(
            "idx_user_sessions_active",
            "account_id",
            "tenant_id",
            postgresql_where=text("revoked_at IS NULL"),
        ),
    )


class AuthToken(Base):
    """Hashed one-time tokens for auth email workflows."""

    __tablename__ = "auth_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    account_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("accounts.id", ondelete="CASCADE")
    )
    email_normalized: Mapped[str] = mapped_column(Text, nullable=False)
    purpose: Mapped[str] = mapped_column(Text, nullable=False)
    token_hash: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    sent_to: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_json: Mapped[dict[str, object] | None] = mapped_column(JSONB)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    delivery_status: Mapped[str] = mapped_column(
        Text, nullable=False, default="sent", server_default="sent"
    )
    delivery_attempts: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    delivery_next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    delivery_last_error: Mapped[str | None] = mapped_column(Text)
    delivery_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    account: Mapped["Account | None"] = relationship(back_populates="auth_tokens")

    __table_args__ = (
        CheckConstraint(
            "purpose IN ("
            "'email_verify', 'password_reset', 'email_change', "
            "'device_login_existing_user', 'device_signup_new_user', "
            "'login_magic_link'"
            ")",
            name="ck_auth_token_purpose",
        ),
        CheckConstraint(
            "(purpose <> 'device_signup_new_user' OR account_id IS NULL)"
            " AND "
            "(purpose NOT IN ('device_login_existing_user', 'login_magic_link')"
            " OR account_id IS NOT NULL)",
            name="ck_auth_token_account_id_purpose_pairing",
        ),
        CheckConstraint(
            "delivery_status IN ('pending', 'sent', 'failed', 'exhausted')",
            name="ck_auth_token_delivery_status",
        ),
        Index("idx_auth_tokens_account_purpose", "account_id", "purpose"),
        Index("idx_auth_tokens_email_purpose", "email_normalized", "purpose"),
        Index(
            "uq_auth_tokens_active_account_purpose",
            "account_id",
            "purpose",
            unique=True,
            postgresql_where=text("consumed_at IS NULL AND account_id IS NOT NULL"),
        ),
        Index(
            "uq_auth_tokens_active_email_purpose_no_account",
            "email_normalized",
            "purpose",
            unique=True,
            postgresql_where=text("consumed_at IS NULL AND account_id IS NULL"),
        ),
        Index(
            "uq_auth_tokens_active_signup_email",
            text("lower(btrim(metadata_json->>'signup_email'))"),
            unique=True,
            postgresql_where=text(
                "purpose = 'device_signup_new_user' AND consumed_at IS NULL"
            ),
        ),
        Index(
            "idx_auth_tokens_delivery_retry",
            "delivery_status",
            "delivery_next_attempt_at",
            postgresql_where=text("consumed_at IS NULL"),
        ),
    )


class BrowserHandoffToken(Base):
    """Hashed one-time tokens for native app to browser dashboard handoff."""

    __tablename__ = "browser_handoff_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    token_hash: Mapped[str] = mapped_column(Text, nullable=False)
    account_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    api_key_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("api_keys.id", ondelete="CASCADE"), nullable=False
    )
    target_path: Mapped[str] = mapped_column(Text, nullable=False)
    device_id: Mapped[str | None] = mapped_column(Text)
    device_name: Mapped[str | None] = mapped_column(Text)
    created_ip_hash: Mapped[str | None] = mapped_column(Text)
    consumed_ip_hash: Mapped[str | None] = mapped_column(Text)
    user_agent_hash: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    account: Mapped["Account"] = relationship()
    tenant: Mapped["Tenant"] = relationship()
    user: Mapped["User"] = relationship(viewonly=True)
    api_key: Mapped["ApiKey"] = relationship()

    __table_args__ = (
        ForeignKeyConstraint(
            ["user_id", "account_id", "tenant_id"],
            ["users.id", "users.account_id", "users.tenant_id"],
            name="fk_browser_handoff_user_account_tenant",
            ondelete="CASCADE",
        ),
        CheckConstraint(
            "target_path = '/cloud' OR target_path LIKE '/cloud/%'",
            name="ck_browser_handoff_target_path",
        ),
        UniqueConstraint("token_hash", name="uq_browser_handoff_token_hash"),
        Index("idx_browser_handoff_tokens_account", "account_id", "created_at"),
        Index("idx_browser_handoff_tokens_expires", "expires_at"),
        Index(
            "idx_browser_handoff_tokens_active",
            "account_id",
            "expires_at",
            postgresql_where=text("consumed_at IS NULL"),
        ),
    )


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    machine_name: Mapped[str] = mapped_column(Text, nullable=False)
    machine_id: Mapped[str] = mapped_column(Text, nullable=False)
    os: Mapped[str | None] = mapped_column(Text)
    app_version: Mapped[str | None] = mapped_column(Text)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.now
    )

    user: Mapped["User"] = relationship(back_populates="devices")

    __table_args__ = (
        UniqueConstraint("user_id", "machine_id", name="uq_device_user_machine"),
    )


class ApiKey(Base):
    """API key for authenticating requests.

    Key format: ctx_<key_id>_<secret>
      - key_id: 16 hex chars (64 bits), stored in plain text for O(1) lookup
      - secret: 24 hex chars, stored as bcrypt hash for verification
      - key_prefix: display-safe prefix shown in UI (e.g., "ctx_a1b2c3d4e5f6g7h8...")

    Supports revocation via revoked_at timestamp (soft delete, preserves
    audit trail). Keys with revoked_at set are rejected at auth time.
    """

    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    key_id: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    key_hash: Mapped[str] = mapped_column(Text, nullable=False)
    key_prefix: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False, default="Default")
    scopes: Mapped[list[str]] = mapped_column(
        ARRAY(String), nullable=False, default=["sync", "search"]
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    session_nonce: Mapped[str] = mapped_column(
        Text, nullable=False, default=lambda: secrets.token_hex(16),
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.now
    )

    user: Mapped["User"] = relationship(back_populates="api_keys", overlaps="tenant")
    tenant: Mapped["Tenant"] = relationship(overlaps="api_keys,user")

    __table_args__ = (
        ForeignKeyConstraint(
            ["user_id", "tenant_id"],
            ["users.id", "users.tenant_id"],
            name="fk_api_keys_user_tenant",
            ondelete="CASCADE",
        ),
    )


class Invitation(Base):
    """Team invitation for adding new users to a tenant.

    Flow:
    1. Owner/admin creates invitation with email + role.
    2. System generates a unique token, stores only its hash, and sends email.
    3. Invitee clicks link with token, which creates their User + API key.
    4. Invitation is marked accepted with accepted_by_user_id.

    Tokens expire after 7 days (configurable). Expired and revoked invitations
    cannot be accepted. Duplicate pending invitations for the same email are rejected.
    """

    __tablename__ = "invitations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(Text, nullable=False)
    email: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(Text, nullable=False, default="member")
    invited_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="pending")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.now
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    accepted_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    inviter: Mapped["User"] = relationship(foreign_keys=[invited_by])
    accepted_by: Mapped["User | None"] = relationship(foreign_keys=[accepted_by_user_id])
    tenant: Mapped["Tenant"] = relationship()

    __table_args__ = (
        CheckConstraint(
            "role IN ('owner', 'admin', 'member', 'viewer')",
            name="ck_invitation_role",
        ),
        CheckConstraint(
            "status IN ('pending', 'accepted', 'revoked', 'expired')",
            name="ck_invitation_status",
        ),
        ForeignKeyConstraint(
            ["invited_by", "tenant_id"],
            ["users.id", "users.tenant_id"],
            name="fk_invitations_invited_by_tenant",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["accepted_by_user_id", "tenant_id"],
            ["users.id", "users.tenant_id"],
            name="fk_invitations_accepted_by_tenant",
        ),
        Index("idx_invitation_tenant_email", "tenant_id", "email"),
        Index("idx_invitation_token_hash", "token_hash", unique=True),
        Index(
            "uq_invitation_pending_tenant_email",
            "tenant_id",
            "email",
            unique=True,
            postgresql_where=text("status = 'pending'"),
        ),
        Index("idx_invitation_tenant_status_created", "tenant_id", "status", "created_at"),
    )


class UsageEvent(Base):
    __tablename__ = "usage_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    entry_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.now
    )

    __table_args__ = (
        Index("idx_usage_tenant_date", "tenant_id", "created_at"),
    )


class ProcessedEvent(Base):
    """Idempotency tracking for Stripe webhook events.

    Prevents duplicate processing when Stripe retries delivery of the same
    event (at-least-once guarantee). Keyed on Stripe's event.id which is
    globally unique.

    This is a public-schema table (not per-tenant) since Stripe events
    are global.
    """

    __tablename__ = "processed_events"

    event_id: Mapped[str] = mapped_column(Text, primary_key=True)
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    processed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.now
    )
    outcome: Mapped[str] = mapped_column(Text, nullable=False)


class SyncIdempotency(Base):
    """Idempotency tracking for sync push requests.

    Prevents duplicate processing when clients retry requests. The flow is:
    1. Client sends request with idempotency_key.
    2. Server inserts row with status='in_progress' and request_sha256.
    3. If unique constraint violated, load existing row:
       - If request_sha256 differs: 409 (key reuse with different payload).
       - If complete: return cached response.
       - If in_progress: 409/retry signal.
    4. Process batch, store response, mark complete.

    Rows expire after ttl_hours (default 24h). A background job should
    periodically clean expired rows.
    """

    __tablename__ = "sync_idempotency"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    key_id: Mapped[str] = mapped_column(Text, nullable=False)  # API key_id that made the request
    idempotency_key: Mapped[str] = mapped_column(Text, nullable=False)
    request_sha256: Mapped[str] = mapped_column(Text, nullable=False)
    response_json: Mapped[str | None] = mapped_column(Text)
    is_complete: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.now
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
    )

    __table_args__ = (
        UniqueConstraint("tenant_id", "key_id", "idempotency_key", name="uq_idempotency_key"),
        Index("idx_idempotency_expires", "expires_at"),
    )


class SyncSession(Base):
    """Tracks multi-batch sync upload sessions.

    Each sync session represents a logical upload operation that may span
    multiple batches. The client receives the session ID in the first push
    response and echoes it back on subsequent batches to resume the session.

    Statuses:
      - in_progress: session is active, batches still being uploaded
      - completed: client explicitly marked the session as done
      - abandoned: stale session cleaned up after inactivity (24h default)
    """

    __tablename__ = "sync_sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    device_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.now
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    status: Mapped[str] = mapped_column(
        Text, nullable=False, default="in_progress"
    )
    total_batches: Mapped[int | None] = mapped_column(Integer, nullable=True)
    completed_batches: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_batch_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('in_progress', 'completed', 'abandoned')",
            name="ck_sync_session_status",
        ),
        Index("idx_sync_sessions_tenant_status", "tenant_id", "status"),
        Index("idx_sync_sessions_tenant_user", "tenant_id", "user_id"),
    )


class AuditLog(Base):
    """Append-only audit log for recording all state-changing operations.

    Tracks who performed an action, when, on which resource, with what
    detail. Stored in the public schema (shared across all tenants,
    keyed by tenant_id).

    Actions:
      - sync.push, team.invite, invitation.accept, invitation.revoke
      - member.role_change, member.remove, key.create, key.revoke
      - admin.retention, admin.allowlist
    """

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    action: Mapped[str] = mapped_column(Text, nullable=False)
    resource_type: Mapped[str] = mapped_column(Text, nullable=False)
    resource_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    detail: Mapped[dict[str, object] | None] = mapped_column(JSONB, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.now
    )

    __table_args__ = (
        Index("idx_audit_log_tenant_created", "tenant_id", created_at.desc()),
        Index("idx_audit_log_tenant_action", "tenant_id", "action"),
        Index("idx_audit_log_tenant_user_created", "tenant_id", "user_id", created_at.desc()),
    )


class InternalSupportAuditLog(Base):
    """Global audit log for internal support operator reads and writes."""

    __tablename__ = "internal_support_audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    operator_id: Mapped[str] = mapped_column(Text, nullable=False)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    target_account_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("accounts.id", ondelete="SET NULL")
    )
    target_tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="SET NULL")
    )
    target_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    resource_type: Mapped[str] = mapped_column(Text, nullable=False)
    resource_id: Mapped[str | None] = mapped_column(Text)
    detail: Mapped[dict[str, object] | None] = mapped_column(JSONB)
    ip_address: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    __table_args__ = (
        Index("idx_internal_support_audit_created", created_at.desc()),
        Index("idx_internal_support_audit_operator_created", "operator_id", created_at.desc()),
        Index("idx_internal_support_audit_account_created", "target_account_id", created_at.desc()),
        Index("idx_internal_support_audit_tenant_created", "target_tenant_id", created_at.desc()),
    )


class DeviceAuthorization(Base):
    """Pending device authorization for the device flow (RFC 8628).

    Lifecycle:
    1. CLI calls POST /auth/device/code, server creates row with status='pending'.
    2. User opens verification_uri in browser, enters user_code, submits.
    3. Server sets status='authorized', links user_id and tenant_id.
    4. CLI polls POST /auth/device/token, detects authorized status.
    5. Server generates API key, returns it, sets status='completed'.

    Expired rows are cleaned up by a periodic background task.
    """

    __tablename__ = "device_authorizations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # Legacy plaintext columns are nullable for rows created before 027. New
    # rows store only keyed HMAC digests in *_hash lookup columns.
    device_code: Mapped[str | None] = mapped_column(Text, unique=True)
    user_code: Mapped[str | None] = mapped_column(Text, unique=True)
    device_code_hash: Mapped[str | None] = mapped_column(Text)
    user_code_hash: Mapped[str | None] = mapped_column(Text)
    verification_uri: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="pending")
    # Linked after user authorizes in browser
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True)
    )
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE")
    )
    # The API key issued on completion (stored to allow lookup if CLI re-polls)
    issued_api_key_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("api_keys.id", ondelete="SET NULL")
    )
    client_name: Mapped[str | None] = mapped_column(Text)
    client_ip: Mapped[str | None] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    poll_interval: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.now
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'authorized', 'completed', 'expired', 'denied')",
            name="ck_device_auth_status",
        ),
        CheckConstraint(
            "(user_id IS NULL AND tenant_id IS NULL) "
            "OR (user_id IS NOT NULL AND tenant_id IS NOT NULL)",
            name="ck_device_auth_user_tenant_pair",
        ),
        ForeignKeyConstraint(
            ["user_id", "tenant_id"],
            ["users.id", "users.tenant_id"],
            name="fk_device_authorizations_user_tenant",
            ondelete="CASCADE",
        ),
        Index("idx_device_auth_user_code", "user_code"),
        Index("idx_device_auth_device_code", "device_code"),
        Index("idx_device_auth_user_code_hash", "user_code_hash", unique=True),
        Index("idx_device_auth_device_code_hash", "device_code_hash", unique=True),
        Index("idx_device_auth_expires", "expires_at"),
    )


class License(Base):
    """A purchased Local Commercial license (ct-1966).

    One row per Stripe subscription. Holds the minted offline token so the buyer
    can re-retrieve it, the optional association to a Cloud tenant when the buyer
    was logged in at checkout (NULL for an anonymous, email-only purchase), and
    the seats/expiry/status the purchase webhook keeps in sync with Stripe. The
    token is verified offline by the native clients; this row is the record of
    sale and the retrieval source, not an access gate.
    """

    __tablename__ = "licenses"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # The license_id claim embedded in the signed token; the stable external id.
    license_id: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    product: Mapped[str] = mapped_column(
        Text, nullable=False, default="local_commercial",
        server_default="local_commercial",
    )
    customer_email: Mapped[str] = mapped_column(Text, nullable=False)
    # Optional association to a Cloud tenant when the buyer logged in at checkout;
    # NULL for an anonymous, email-only purchase. Unconstrained on purpose so a
    # license outlives any tenant lifecycle change.
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    stripe_customer_id: Mapped[str | None] = mapped_column(Text)
    # The Stripe subscription is the one-row-per-purchase idempotency key, so it
    # is required (a NULL would not be deduped by the unique constraint).
    stripe_subscription_id: Mapped[str] = mapped_column(
        Text, nullable=False, unique=True
    )
    # Signing key id the token was minted with (e.g. "lc1").
    kid: Mapped[str] = mapped_column(Text, nullable=False)
    seats: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    status: Mapped[str] = mapped_column(
        Text, nullable=False, default="active", server_default="active",
    )
    # The signed offline token blob; re-minted on each invoice.paid renewal.
    token: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Delivery-outbox state for the initial purchase-fulfillment email (ct-2015).
    # Mirrors AuthToken's delivery columns. The fulfillment webhook enqueues a row
    # with status 'pending' in the same transaction as the insert; a post-commit
    # fast-path send marks it 'sent', and a background worker retries any row left
    # 'pending'/'failed'. server_default 'sent' so pre-ct-2015 rows are never re-sent.
    delivery_status: Mapped[str] = mapped_column(
        Text, nullable=False, default="sent", server_default="sent"
    )
    delivery_attempts: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    delivery_next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    delivery_last_error: Mapped[str | None] = mapped_column(Text)
    delivery_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(UTC), server_default=text("now()"),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC),
        server_default=text("now()"),
    )

    __table_args__ = (
        CheckConstraint("seats >= 1", name="ck_licenses_seats_positive"),
        CheckConstraint(
            "delivery_status IN ('pending', 'sent', 'failed', 'exhausted')",
            name="ck_licenses_delivery_status",
        ),
        # Case-insensitive retrieval by email (buyers may re-enter a different case).
        Index("idx_licenses_customer_email_lower", text("lower(customer_email)")),
        Index("idx_licenses_tenant", "tenant_id"),
        # Retry sweep: due deliveries by status + next-attempt time.
        Index(
            "idx_licenses_delivery_retry",
            "delivery_status",
            "delivery_next_attempt_at",
        ),
    )


class LicenseRetrievalToken(Base):
    """Short-lived, single-use token for anonymous license retrieval (ct-2015).

    A buyer with no Cloud account requests retrieval by their purchase email; if a
    license exists, this hashed token is minted and a link is emailed. The token
    is keyed only to the normalized email, expires quickly, and is consumed on
    reveal. It grants nothing but a view of the license(s) for that exact email.
    """

    __tablename__ = "license_retrieval_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email_normalized: Mapped[str] = mapped_column(Text, nullable=False)
    # sha256 of the raw token; the raw value lives only in the emailed link.
    token_hash: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        server_default=text("now()"),
    )

    __table_args__ = (
        # Cooldown lookup (recent unconsumed token for an email) + cleanup.
        Index("idx_license_retrieval_tokens_email", text("lower(email_normalized)")),
        Index("idx_license_retrieval_tokens_expires", "expires_at"),
    )
