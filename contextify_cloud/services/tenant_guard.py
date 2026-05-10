"""Tenant write-guard for deletion lifecycle.

Provides a reusable guard function that mutating endpoints call before
performing writes. If the tenant is scheduled for deletion or actively
being purged, the guard raises HTTP 403 to prevent new data from being
written during the purge window.

Usage:
    from contextify_cloud.services.tenant_guard import check_tenant_active

    # At the top of any mutating endpoint, before writes:
    await check_tenant_active(db, auth.tenant_id)
"""

import logging
import uuid

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from contextify_cloud.models import Tenant

logger = logging.getLogger(__name__)


async def check_tenant_active(db: AsyncSession, tenant_id: uuid.UUID) -> None:
    """Raise 403 if the tenant is scheduled for deletion or being purged.

    This check should be called at the top of every mutating endpoint
    (POST/PUT/DELETE that creates or modifies tenant-scoped data) before
    any writes occur. It reads the tenant status within the current
    transaction so that it serializes correctly against the purge service.

    Uses FOR SHARE to serialize against the purge service's FOR UPDATE
    lock on the tenant row. This prevents the race where a write reads
    status='active' just before the purge marks it 'purge_in_progress'.
    FOR SHARE allows concurrent reads but blocks if the purge holds
    FOR UPDATE, ensuring the guard sees the correct status.

    Args:
        db: Async database session (same transaction as the endpoint).
        tenant_id: UUID of the tenant to check.

    Raises:
        HTTPException: 403 if tenant status is deletion_scheduled or
            purge_in_progress.
    """
    result = await db.execute(
        select(Tenant.status).where(Tenant.id == tenant_id).with_for_update(read=True)
    )
    status = result.scalar_one_or_none()

    if status in ("deletion_scheduled", "purge_in_progress"):
        logger.info(
            "Write rejected: tenant=%s status=%s",
            tenant_id,
            status,
        )
        raise HTTPException(
            status_code=403,
            detail="Tenant is scheduled for deletion. No new data accepted.",
        )
