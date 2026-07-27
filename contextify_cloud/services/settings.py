"""Account settings service for the web dashboard.

Manages API key listing, creation, and revocation for the settings page.
Respects role-based visibility: owners see all tenant keys, members see only their own.
"""

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from contextify_cloud.middleware.auth import AuthContext, generate_api_key, hash_api_key
from contextify_cloud.models import ApiKey, Tenant, User
from contextify_cloud.services.audit import log_event
from contextify_cloud.services.funnel_events import emit_funnel_event_after_commit

logger = logging.getLogger(__name__)


@dataclass
class ApiKeyInfo:
    """Display-safe API key information for the settings UI."""

    id: uuid.UUID
    key_id: str
    key_prefix: str
    name: str
    scopes: list[str]
    status: str  # "active", "revoked", or "expired"
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime | None
    revoked_at: datetime | None


@dataclass
class UserProfile:
    """User profile information for the settings page."""

    user_id: uuid.UUID
    email: str
    name: str | None
    role: str
    created_at: datetime


@dataclass
class TenantInfo:
    """Tenant/team information for the settings page."""

    tenant_id: uuid.UUID
    name: str
    slug: str
    plan: str
    created_at: datetime


def _key_status(key: ApiKey) -> str:
    """Determine the display status of an API key."""
    if key.revoked_at is not None:
        return "revoked"
    if key.expires_at and key.expires_at < datetime.now(UTC):
        return "expired"
    return "active"


async def get_user_profile(
    auth: AuthContext,
    db: AsyncSession,
) -> UserProfile | None:
    """Fetch the authenticated user's profile information."""
    result = await db.execute(
        select(User).where(User.id == auth.user_id)
    )
    user = result.scalar_one_or_none()
    if not user:
        return None

    return UserProfile(
        user_id=user.id,
        email=user.email,
        name=user.name,
        role=user.role,
        created_at=user.created_at,
    )


async def get_tenant_info(
    auth: AuthContext,
    db: AsyncSession,
) -> TenantInfo | None:
    """Fetch the tenant/team information for the settings page."""
    result = await db.execute(
        select(Tenant).where(Tenant.id == auth.tenant_id)
    )
    tenant = result.scalar_one_or_none()
    if not tenant:
        return None

    return TenantInfo(
        tenant_id=tenant.id,
        name=tenant.name,
        slug=tenant.slug,
        plan=tenant.plan,
        created_at=tenant.created_at,
    )


async def get_user_api_keys(
    auth: AuthContext,
    db: AsyncSession,
) -> list[ApiKeyInfo]:
    """Fetch API keys visible to the authenticated user.

    Role-based visibility:
      - owner/admin: see all keys for the tenant
      - member/viewer: see only their own keys
    """
    query = select(ApiKey).where(ApiKey.tenant_id == auth.tenant_id)

    if not auth.has_full_access:
        query = query.where(ApiKey.user_id == auth.user_id)

    query = query.order_by(ApiKey.created_at.desc())

    result = await db.execute(query)
    keys = result.scalars().all()

    return [
        ApiKeyInfo(
            id=key.id,
            key_id=key.key_id,
            key_prefix=key.key_prefix,
            name=key.name,
            scopes=key.scopes,
            status=_key_status(key),
            created_at=key.created_at,
            last_used_at=key.last_used_at,
            expires_at=key.expires_at,
            revoked_at=key.revoked_at,
        )
        for key in keys
    ]


async def _queue_sync_credential_issued(db: AsyncSession, tenant_id: uuid.UUID) -> None:
    """ct-3286: register the credential-issued emit for THIS transaction's commit.

    Registered before the commit and fired by it, so a rollback emits nothing
    rather than a phantom activation. The tenant lookup supplies the coarse
    `plan` property and the internal-tenant suppression the emit seam expects.
    """
    try:
        tenant = await db.get(Tenant, tenant_id)
        if tenant is None:
            return
        emit_funnel_event_after_commit(
            db,
            "sync_credential_issued",
            distinct_id=str(tenant.id),
            properties={"plan": tenant.plan},
            is_internal=bool(getattr(tenant, "is_internal", False)),
        )
    except Exception:  # noqa: BLE001 - analytics must never break key issuance
        logger.exception("event=sync_credential_issued_queue_failed tenant_id=%s", tenant_id)


async def create_user_api_key(
    auth: AuthContext,
    db: AsyncSession,
    *,
    name: str = "Dashboard Key",
) -> tuple[ApiKeyInfo, str]:
    """Create a new API key for the authenticated user.

    Returns (ApiKeyInfo, raw_key). The raw_key must be shown to the user
    exactly once, as it cannot be retrieved later.
    """
    api_key: ApiKey | None = None
    raw_key = ""
    key_id = ""
    for attempt in range(3):
        raw_key, key_id, secret = generate_api_key()
        key_hash = hash_api_key(secret)

        api_key = ApiKey(
            user_id=auth.user_id,
            tenant_id=auth.tenant_id,
            key_id=key_id,
            key_hash=key_hash,
            key_prefix=f"ctx_{key_id}...",
            name=name,
        )
        db.add(api_key)
        try:
            await db.flush()
            break
        except IntegrityError:
            logger.warning(
                "API key_id collision on create (attempt=%d)", attempt + 1
            )
            await db.rollback()
            try:
                db.expunge(api_key)
            except Exception:
                pass
            api_key = None
            continue

    if api_key is None:
        raise RuntimeError("Failed to generate unique API key. Please retry.")

    await log_event(
        db,
        tenant_id=auth.tenant_id,
        user_id=auth.user_id,
        action="key.create",
        resource_type="api_key",
        resource_id=str(api_key.id),
        detail={"key_id": key_id, "name": name},
    )

    logger.info(
        "API key created: key_id=%s user=%s tenant=%s",
        key_id, auth.user_id, auth.tenant_id,
    )

    info = ApiKeyInfo(
        id=api_key.id,
        key_id=api_key.key_id,
        key_prefix=api_key.key_prefix,
        name=api_key.name,
        scopes=api_key.scopes,
        status="active",
        created_at=api_key.created_at,
        last_used_at=None,
        expires_at=None,
        revoked_at=None,
    )

    await _queue_sync_credential_issued(db, auth.tenant_id)
    await db.commit()
    return info, raw_key


async def revoke_api_key(
    auth: AuthContext,
    db: AsyncSession,
    *,
    key_id: uuid.UUID,
) -> ApiKeyInfo | None:
    """Revoke an API key by setting its revoked_at timestamp.

    Role-based access:
      - owner/admin: can revoke any key in the tenant
      - member/viewer: can only revoke their own keys

    Returns the updated ApiKeyInfo, or None if the key was not found
    or the user lacks permission to revoke it.
    """
    query = select(ApiKey).where(
        ApiKey.id == key_id,
        ApiKey.tenant_id == auth.tenant_id,
    )

    if not auth.has_full_access:
        query = query.where(ApiKey.user_id == auth.user_id)

    result = await db.execute(query)
    api_key = result.scalar_one_or_none()

    if not api_key:
        logger.warning(
            "API key revoke failed: key_id=%s user=%s (not found or forbidden)",
            key_id, auth.user_id,
        )
        return None

    if api_key.revoked_at is not None:
        # Already revoked, return current state
        return ApiKeyInfo(
            id=api_key.id,
            key_id=api_key.key_id,
            key_prefix=api_key.key_prefix,
            name=api_key.name,
            scopes=api_key.scopes,
            status="revoked",
            created_at=api_key.created_at,
            last_used_at=api_key.last_used_at,
            expires_at=api_key.expires_at,
            revoked_at=api_key.revoked_at,
        )

    now = datetime.now(UTC)
    upd = update(ApiKey).where(
        ApiKey.id == key_id, ApiKey.tenant_id == auth.tenant_id
    )
    if not auth.has_full_access:
        upd = upd.where(ApiKey.user_id == auth.user_id)
    revoke_result = await db.execute(upd.values(revoked_at=now))
    if getattr(revoke_result, "rowcount", 1) == 0:
        return None
    await db.flush()

    await log_event(
        db,
        tenant_id=auth.tenant_id,
        user_id=auth.user_id,
        action="key.revoke",
        resource_type="api_key",
        resource_id=str(api_key.id),
        detail={"key_id": api_key.key_id},
    )

    logger.info(
        "API key revoked: key_id=%s by user=%s tenant=%s",
        api_key.key_id, auth.user_id, auth.tenant_id,
    )

    info = ApiKeyInfo(
        id=api_key.id,
        key_id=api_key.key_id,
        key_prefix=api_key.key_prefix,
        name=api_key.name,
        scopes=api_key.scopes,
        status="revoked",
        created_at=api_key.created_at,
        last_used_at=api_key.last_used_at,
        expires_at=api_key.expires_at,
        revoked_at=now,
    )
    await db.commit()
    return info


async def rotate_api_key(
    auth: AuthContext,
    db: AsyncSession,
    *,
    key_id: uuid.UUID,
) -> tuple[ApiKeyInfo, str] | None:
    """Revoke one of the acting user's API keys and issue a replacement."""
    query = select(ApiKey).where(
        ApiKey.id == key_id,
        ApiKey.tenant_id == auth.tenant_id,
        ApiKey.user_id == auth.user_id,
        ApiKey.revoked_at.is_(None),
    )
    result = await db.execute(query)
    old_key = result.scalar_one_or_none()
    if old_key is None:
        return None
    if old_key.user_id != auth.user_id:
        logger.warning(
            "API key rotate failed: key_id=%s user=%s attempted cross-user rotation",
            key_id, auth.user_id,
        )
        return None

    now = datetime.now(UTC)
    rotate_result = await db.execute(
        update(ApiKey)
        .where(
            ApiKey.id == key_id,
            ApiKey.tenant_id == auth.tenant_id,
            ApiKey.user_id == auth.user_id,
            ApiKey.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )
    if getattr(rotate_result, "rowcount", 1) != 1:
        logger.warning(
            "API key rotate failed: key_id=%s user=%s lost active-key race",
            key_id, auth.user_id,
        )
        return None
    old_key.revoked_at = now
    raw_key, new_key_id, secret = generate_api_key()
    api_key = ApiKey(
        user_id=old_key.user_id,
        tenant_id=old_key.tenant_id,
        key_id=new_key_id,
        key_hash=hash_api_key(secret),
        key_prefix=f"ctx_{new_key_id}...",
        name=f"{old_key.name} (rotated)",
        scopes=old_key.scopes,
    )
    db.add(api_key)
    await db.flush()

    await log_event(
        db,
        tenant_id=auth.tenant_id,
        user_id=auth.user_id,
        action="key.rotate",
        resource_type="api_key",
        resource_id=str(api_key.id),
        detail={"old_key_id": old_key.key_id, "new_key_id": new_key_id},
    )

    key_info = ApiKeyInfo(
        id=api_key.id,
        key_id=api_key.key_id,
        key_prefix=api_key.key_prefix,
        name=api_key.name,
        scopes=api_key.scopes,
        status="active",
        created_at=api_key.created_at,
        last_used_at=None,
        expires_at=None,
        revoked_at=None,
    )
    await _queue_sync_credential_issued(db, auth.tenant_id)
    await db.commit()
    return key_info, raw_key
