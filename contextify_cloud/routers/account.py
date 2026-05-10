"""Account management REST API endpoints.

GET    /api/v1/account        - Get current user's profile
PUT    /api/v1/account        - Update account details
DELETE /api/v1/account        - Soft-delete account
GET    /api/v1/account/export - GDPR data export
"""

import logging
import re
from datetime import UTC, datetime, timedelta
from typing import Annotated, NamedTuple

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from contextify_cloud.database import get_db
from contextify_cloud.middleware.auth import AuthContext, resolve_api_key
from contextify_cloud.models import ApiKey, AuditLog, Tenant, User, UserSession
from contextify_cloud.schemas import (
    AccountExportResponse,
    AccountResponse,
    AccountUpdateRequest,
)
from contextify_cloud.services.audit import log_event
from contextify_cloud.services.plan_limits import get_effective_history_retention_days
from contextify_cloud.services.tenant_guard import check_tenant_active

logger = logging.getLogger(__name__)

_PG_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _quote_pg_identifier(identifier: str) -> str:
    """Validate and quote a PostgreSQL identifier (schema/table/column name)."""
    if not _PG_IDENT_RE.fullmatch(identifier):
        logger.error("Invalid schema identifier: %r", identifier)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal configuration error.",
        )
    return f'"{identifier}"'


router = APIRouter(prefix="/api/v1/account", tags=["account"])


class _RetentionPolicyFields(NamedTuple):
    days: int
    minimum_timestamp: int | None


def _retention_policy_fields(tenant: Tenant) -> _RetentionPolicyFields:
    """Return server-authoritative retention fields for API clients."""
    retention_days = get_effective_history_retention_days(tenant)
    minimum_timestamp = None
    if retention_days > 0:
        minimum_timestamp = int(
            (datetime.now(UTC) - timedelta(days=retention_days)).timestamp()
        )
    return _RetentionPolicyFields(
        days=retention_days,
        minimum_timestamp=minimum_timestamp,
    )


@router.get("", response_model=AccountResponse)
async def get_account(
    auth: Annotated[AuthContext, Depends(resolve_api_key)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> AccountResponse:
    """Get the authenticated user's account profile.

    Returns user details along with tenant name and plan.
    """
    user_result = await db.execute(
        select(User).where(User.id == auth.user_id)
    )
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    tenant_result = await db.execute(
        select(Tenant).where(Tenant.id == auth.tenant_id)
    )
    tenant = tenant_result.scalar_one_or_none()
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found.",
        )

    retention_policy = _retention_policy_fields(tenant)

    return AccountResponse(
        user_id=user.id,
        email=user.email,
        name=user.name,
        role=user.role,
        tenant_id=tenant.id,
        tenant_name=tenant.name,
        tenant_plan=tenant.plan,
        effective_history_retention_days=retention_policy.days,
        effective_history_retention_minimum_timestamp=retention_policy.minimum_timestamp,
        created_at=user.created_at,
    )


@router.put("", response_model=AccountResponse)
async def update_account(
    http_request: Request,
    request: AccountUpdateRequest,
    auth: Annotated[AuthContext, Depends(resolve_api_key)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> AccountResponse:
    """Update the authenticated user's account details.

    Currently supports updating the display name.
    """
    await check_tenant_active(db, auth.tenant_id)

    user_result = await db.execute(
        select(User).where(User.id == auth.user_id)
    )
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    # Update name
    await db.execute(
        update(User)
        .where(User.id == auth.user_id)
        .values(name=request.name)
    )

    tenant_result = await db.execute(
        select(Tenant).where(Tenant.id == auth.tenant_id)
    )
    tenant = tenant_result.scalar_one_or_none()
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found.",
        )

    await log_event(
        db,
        tenant_id=auth.tenant_id,
        user_id=auth.user_id,
        action="account.update",
        resource_type="user",
        resource_id=str(auth.user_id),
        detail={"name": request.name},
        ip_address=http_request.client.host if http_request.client else None,
    )

    logger.info("Account updated: user=%s", auth.user_id)

    retention_policy = _retention_policy_fields(tenant)

    return AccountResponse(
        user_id=user.id,
        email=user.email,
        name=request.name,
        role=user.role,
        tenant_id=tenant.id,
        tenant_name=tenant.name,
        tenant_plan=tenant.plan,
        effective_history_retention_days=retention_policy.days,
        effective_history_retention_minimum_timestamp=retention_policy.minimum_timestamp,
        created_at=user.created_at,
    )


@router.delete("")
async def delete_account(
    http_request: Request,
    auth: Annotated[AuthContext, Depends(resolve_api_key)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    """Soft-delete the authenticated user's account.

    Checks that the user is not the last owner of the tenant.
    Sets removed_at on the user and revokes all their API keys.
    """
    # Check if user is owner and if they're the last one
    user_result = await db.execute(
        select(User).where(User.id == auth.user_id)
    )
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    if user.role == "owner":
        await db.execute(
            select(Tenant).where(Tenant.id == auth.tenant_id).with_for_update()
        )
        owners_result = await db.execute(
            select(User.id).where(
                User.tenant_id == auth.tenant_id,
                User.role == "owner",
                User.removed_at.is_(None),
            ).with_for_update()
        )
        owner_ids = owners_result.scalars().all()
        if len(owner_ids) <= 1:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Cannot delete account: you are the sole owner. "
                    "To delete the entire tenant and its data, use "
                    "DELETE /api/v1/tenant with slug confirmation."
                ),
            )

    now = datetime.now(UTC)

    # Soft-delete user
    await db.execute(
        update(User)
        .where(User.id == auth.user_id)
        .values(removed_at=now)
    )

    # Revoke all API keys
    await db.execute(
        update(ApiKey)
        .where(
            ApiKey.user_id == auth.user_id,
            ApiKey.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )
    await db.execute(
        update(UserSession)
        .where(
            UserSession.user_id == auth.user_id,
            UserSession.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )

    await log_event(
        db,
        tenant_id=auth.tenant_id,
        user_id=auth.user_id,
        action="account.delete",
        resource_type="user",
        resource_id=str(auth.user_id),
        detail={"email": user.email},
        ip_address=http_request.client.host if http_request.client else None,
    )

    logger.info("Account deleted: user=%s email=%s", auth.user_id, user.email)

    return {"status": "deletion_initiated"}


@router.get("/export", response_model=AccountExportResponse)
async def export_account(
    auth: Annotated[AuthContext, Depends(resolve_api_key)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> AccountExportResponse:
    """Export user data for GDPR compliance.

    Returns the user's profile, API keys (without secrets),
    entry count from the tenant schema, and audit events.
    """
    # User profile
    user_result = await db.execute(
        select(User).where(User.id == auth.user_id)
    )
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    user_data = {
        "user_id": str(user.id),
        "email": user.email,
        "name": user.name,
        "role": user.role,
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }

    # API keys (without secrets)
    keys_result = await db.execute(
        select(ApiKey).where(ApiKey.user_id == auth.user_id)
    )
    keys = keys_result.scalars().all()
    api_keys_data = [
        {
            "id": str(k.id),
            "key_prefix": k.key_prefix,
            "name": k.name,
            "scopes": k.scopes,
            "created_at": k.created_at.isoformat() if k.created_at else None,
            "revoked_at": k.revoked_at.isoformat() if k.revoked_at else None,
        }
        for k in keys
    ]

    # Entry count from tenant schema
    tenant_result = await db.execute(
        select(Tenant).where(Tenant.id == auth.tenant_id)
    )
    tenant = tenant_result.scalar_one_or_none()
    entry_count = 0
    if tenant:
        from contextify_cloud.services.tenant import get_tenant_schema

        schema = get_tenant_schema(tenant.slug)
        safe_schema = _quote_pg_identifier(schema)
        try:
            count_result = await db.execute(
                text(
                    f"SELECT COUNT(*) FROM {safe_schema}.transcript_entries "
                    "WHERE uploaded_by_user_id = :user_id"
                ),
                {"user_id": str(auth.user_id)},
            )
            entry_count = count_result.scalar() or 0
        except Exception:
            logger.warning(
                "Failed to count entries for user=%s in schema=%s",
                auth.user_id, schema, exc_info=True,
            )

    # Audit events for this user
    audit_result = await db.execute(
        select(AuditLog)
        .where(
            AuditLog.tenant_id == auth.tenant_id,
            AuditLog.user_id == auth.user_id,
        )
        .order_by(AuditLog.created_at.desc())
        .limit(1000)
    )
    audit_events = [
        {
            "id": e.id,
            "action": e.action,
            "resource_type": e.resource_type,
            "resource_id": e.resource_id,
            "detail": e.detail,
            "created_at": e.created_at.isoformat() if e.created_at else None,
        }
        for e in audit_result.scalars().all()
    ]

    logger.info("Account export: user=%s", auth.user_id)

    return AccountExportResponse(
        user=user_data,
        api_keys=api_keys_data,
        entry_count=entry_count,
        audit_events=audit_events,
    )
