"""Purge service for tenant data destruction.

Implements the purge pipeline that permanently removes tenant data after
the grace period expires. Uses PostgreSQL advisory locks to prevent
concurrent purge sweeps and per-tenant locks to prevent double-purge.

The main entry point is ``run_purge_once()``, which:
  1. Acquires a global advisory lock (transaction-scoped)
  2. Finds tenants with status='deletion_scheduled' and purge_due_at <= now
  3. For each candidate, calls ``_purge_single_tenant()``
  4. Runs a tombstone expiry pass to hard-delete old tombstones
  5. Returns a ``PurgeResult`` with counts

Each tenant is purged in its own database transaction so that one
tenant's failure does not roll back successful purges of others.
Advisory locks are transaction-scoped, auto-releasing on commit/rollback.
"""

import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from contextify_cloud.config import settings
from contextify_cloud.database import async_session_factory
from contextify_cloud.models import ApiKey, DeletedTenant, Tenant, User
from contextify_cloud.services.tenant import _validate_schema_name, get_tenant_schema

logger = logging.getLogger(__name__)

# Advisory lock ID for global purge coordination.
# Uses a fixed integer derived from "CTXP" (Contextify Purge) in hex.
PURGE_GLOBAL_LOCK_ID = 0x43545850


@dataclass
class PurgeResult:
    """Result of a single purge sweep."""

    candidates: int = 0
    purged: int = 0
    skipped_locked: int = 0
    errors: list[str] = field(default_factory=list)
    tombstones_expired: int = 0
    dry_run: bool = False


class _TenantLockError(Exception):
    """Raised when the per-tenant advisory lock cannot be acquired."""

    pass


async def run_purge_once(
    *,
    now: datetime | None = None,
    dry_run: bool = False,
    batch_limit: int | None = None,
) -> PurgeResult:
    """Execute one purge sweep.

    Args:
        now: Override current time (for testing with injected clock).
        dry_run: If True, report candidates without any mutation.
        batch_limit: Max tenants to process. Defaults to settings.purge_batch_limit.

    Returns:
        PurgeResult with counts and any error details.
    """
    if now is None:
        now = datetime.now(UTC)
    if batch_limit is None:
        batch_limit = settings.purge_batch_limit
    result = PurgeResult()
    result.dry_run = dry_run

    # Phase 1: Discover candidates under global lock.
    # Uses its own short transaction so the global lock is released quickly.
    candidate_ids: list[uuid.UUID] = []
    async with async_session_factory() as session:
        async with session.begin():
            # Acquire global advisory lock (transaction-scoped).
            lock_result = await session.execute(
                text("SELECT pg_try_advisory_xact_lock(:lock_id)"),
                {"lock_id": PURGE_GLOBAL_LOCK_ID},
            )
            if not lock_result.scalar():
                logger.info("Purge sweep skipped: another worker holds the lock")
                return result

            candidates = await session.execute(
                select(Tenant.id)
                .where(
                    Tenant.status == "deletion_scheduled",
                    Tenant.purge_due_at <= now,
                )
                .order_by(Tenant.purge_due_at.asc())
                .limit(batch_limit)
            )
            candidate_ids = list(candidates.scalars().all())
            result.candidates = len(candidate_ids)

            if dry_run:
                logger.info("Purge dry-run: %d candidates found", result.candidates)
                return result

    # Phase 2: Purge each tenant in its own transaction.
    # This ensures one tenant's failure (e.g. schema drop error) does not
    # roll back successful purges of other tenants.
    for tenant_id in candidate_ids:
        try:
            async with async_session_factory() as session:
                async with session.begin():
                    tenant_result = await session.execute(
                        select(Tenant).where(Tenant.id == tenant_id)
                    )
                    tenant = tenant_result.scalar_one_or_none()
                    if not tenant:
                        continue
                    await _purge_single_tenant(session, tenant, now)
            result.purged += 1
        except _TenantLockError:
            result.skipped_locked += 1
        except Exception as exc:
            result.errors.append(f"tenant={tenant_id}: {exc}")
            logger.error(
                "Purge failed for tenant %s: %s",
                tenant_id,
                exc,
                exc_info=True,
            )

    # Phase 3: Tombstone expiry in its own transaction.
    async with async_session_factory() as session:
        async with session.begin():
            result.tombstones_expired = await _expire_tombstones(session, now)

    logger.info(
        "Purge sweep complete: candidates=%d purged=%d skipped=%d errors=%d tombstones_expired=%d",
        result.candidates,
        result.purged,
        result.skipped_locked,
        len(result.errors),
        result.tombstones_expired,
    )
    return result


async def _purge_single_tenant(
    session: AsyncSession,
    tenant: Tenant,
    now: datetime,
) -> None:
    """Purge a single tenant's data.

    Steps:
      1. Acquire per-tenant advisory lock (prevents double-purge)
      2. Re-load tenant with FOR UPDATE to serialize against concurrent writes
      3. Write tombstone (or skip if already exists from a prior crash)
      4. Mark tenant as purge_in_progress
      5. Revoke all API keys
      6. DROP SCHEMA IF EXISTS tenant_{slug} CASCADE
      7. DELETE FROM tenants WHERE id = tenant_id (cascades public-schema children)
      8. Update tombstone: set purged_at and tombstone_expires_at
    """
    tenant_lock_id = _tenant_lock_id(tenant.id)

    # Step 1: Per-tenant advisory lock
    lock_result = await session.execute(
        text("SELECT pg_try_advisory_xact_lock(:lock_id)"),
        {"lock_id": tenant_lock_id},
    )
    if not lock_result.scalar():
        raise _TenantLockError(f"Could not acquire lock for tenant {tenant.id}")

    # Step 2: Re-load tenant with FOR UPDATE to serialize against concurrent writes
    tenant_result = await session.execute(
        select(Tenant).where(Tenant.id == tenant.id).with_for_update()
    )
    locked_tenant: Tenant | None = tenant_result.scalar_one_or_none()
    if not locked_tenant:
        logger.info("Tenant %s already deleted, skipping", tenant.id)
        return
    if locked_tenant.status not in ("deletion_scheduled", "purge_in_progress"):
        logger.info(
            "Tenant %s status is %s, skipping purge",
            locked_tenant.id,
            locked_tenant.status,
        )
        return
    # Use the freshly-loaded, row-locked tenant from here on.
    tenant = locked_tenant

    # Find owner email for tombstone
    owner_result = await session.execute(
        select(User.email).where(
            User.tenant_id == tenant.id,
            User.role == "owner",
            User.removed_at.is_(None),
        ).limit(1)
    )
    owner_email = owner_result.scalar() or "unknown"

    # Step 3: Write or update tombstone (idempotent via ON CONFLICT)
    tombstone_values = {
        "tenant_id": tenant.id,
        "slug": tenant.slug,
        "plan": tenant.plan,
        "billing_interval": tenant.billing_interval or "month",
        "stripe_customer_id": tenant.stripe_customer_id,
        "stripe_subscription_id": tenant.stripe_subscription_id,
        "owner_email": owner_email,
        "deletion_trigger": tenant.deletion_trigger or "explicit_delete",
        "deletion_requested_at": tenant.deletion_requested_at or now,
        "purge_due_at": tenant.purge_due_at or now,
        "requested_by_user_id": None,
    }
    await session.execute(
        pg_insert(DeletedTenant)
        .values(**tombstone_values)
        .on_conflict_do_nothing(index_elements=["tenant_id"])
    )

    # Step 4: Mark as purge_in_progress
    await session.execute(
        update(Tenant)
        .where(Tenant.id == tenant.id)
        .values(status="purge_in_progress")
    )
    await session.flush()

    # Step 5: Revoke all API keys for the tenant
    await session.execute(
        update(ApiKey)
        .where(
            ApiKey.tenant_id == tenant.id,
            ApiKey.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )

    # Step 6: DROP SCHEMA IF EXISTS
    schema_name = get_tenant_schema(tenant.slug)
    _validate_schema_name(schema_name)
    await session.execute(
        text(f"DROP SCHEMA IF EXISTS {schema_name} CASCADE")
    )
    logger.info("Dropped schema %s for tenant %s", schema_name, tenant.id)

    # Step 7: DELETE tenant row (cascades to users, api_keys, devices, etc.)
    await session.execute(
        delete(Tenant).where(Tenant.id == tenant.id)
    )

    # Step 8: Update tombstone with completion timestamps
    tombstone_expires = now + timedelta(
        days=settings.purge_tombstone_retention_months * 30
    )
    await session.execute(
        update(DeletedTenant)
        .where(DeletedTenant.tenant_id == tenant.id)
        .values(purged_at=now, tombstone_expires_at=tombstone_expires)
    )

    logger.info(
        "Purge complete: tenant=%s slug=%s schema=%s tombstone_expires=%s",
        tenant.id,
        tenant.slug,
        schema_name,
        tombstone_expires,
    )


async def _expire_tombstones(session: AsyncSession, now: datetime) -> int:
    """Hard-delete tombstones past their retention period."""
    result = await session.execute(
        delete(DeletedTenant).where(
            DeletedTenant.purged_at.isnot(None),
            DeletedTenant.tombstone_expires_at <= now,
        )
    )
    count: int = getattr(result, "rowcount", 0) or 0
    if count > 0:
        logger.info("Expired %d tombstone records", count)
    return count


def _tenant_lock_id(tenant_id: uuid.UUID) -> int:
    """Derive an advisory lock ID from a tenant UUID.

    Uses the first 8 bytes of the UUID as a signed 64-bit integer,
    which PostgreSQL advisory locks accept as a bigint key.
    """
    return int.from_bytes(tenant_id.bytes[:8], byteorder="big", signed=True)
