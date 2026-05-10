"""Audit logging service for recording state-changing operations.

Provides a single async function `log_event()` that creates an AuditLog
row in the same transaction as the operation being audited. Uses a
SAVEPOINT so audit insert failures are isolated and do not abort the
caller's main transaction.

Usage:
    from contextify_cloud.services.audit import log_event

    await log_event(
        db=db,
        tenant_id=auth.tenant_id,
        user_id=auth.user_id,
        action="key.create",
        resource_type="api_key",
        resource_id=str(key.id),
        detail={"key_id": key.key_id, "scopes": key.scopes},
        ip_address=request.client.host if request.client else None,
    )
"""

import logging
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from contextify_cloud.models import AuditLog

logger = logging.getLogger(__name__)


async def log_event(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID | None,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    detail: dict[str, object] | None = None,
    ip_address: str | None = None,
) -> None:
    """Record an audit log entry using a nested transaction (SAVEPOINT).

    The entry is flushed immediately inside a SAVEPOINT so that insert
    failures (bad data, missing table during rollout, etc.) roll back
    only the audit write, not the caller's outer transaction.

    The audit row remains atomic with the outer transaction: if the
    outer transaction rolls back, the audit row rolls back too.

    Args:
        db: Async database session (same transaction as the operation).
        tenant_id: UUID of the tenant.
        user_id: UUID of the acting user (None for token-based flows).
        action: Action identifier (e.g. 'sync.push', 'key.create').
        resource_type: Type of the affected resource (e.g. 'api_key', 'user').
        resource_id: ID of the affected resource (optional).
        detail: Additional context as a JSON-serializable dict (optional).
        ip_address: Client IP address (optional).
    """
    try:
        async with db.begin_nested():
            entry = AuditLog(
                tenant_id=tenant_id,
                user_id=user_id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                detail=detail,
                ip_address=ip_address,
            )
            db.add(entry)
            await db.flush([entry])
    except Exception:
        logger.warning(
            "Failed to record audit event: action=%s resource_type=%s tenant=%s",
            action,
            resource_type,
            tenant_id,
            exc_info=True,
        )
