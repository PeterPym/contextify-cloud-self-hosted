"""Device lifecycle transitions using the identity foundation's locks and CAS.

No content write, coverage waiver, or local-stop certification belongs here.
The client proves its full inventory and handles H.5 exclusions before retiring.
"""

import copy
import uuid
from datetime import UTC, datetime

from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from contextify_cloud.device_schemas import RestoreDevice, RetireDevice
from contextify_cloud.middleware.auth import AuthContext
from contextify_cloud.models import AuditLog, Device, Tenant
from contextify_cloud.services import device_identity as identity


async def lifecycle_owner(
    db: AsyncSession, auth: AuthContext, owner_user_id: uuid.UUID | None,
) -> AuthContext:
    if owner_user_id is None or owner_user_id == auth.user_id:
        return auth
    if not auth.has_full_access:
        raise HTTPException(404, "Device not found")
    owner = copy.copy(auth)
    owner.user_id = owner_user_id
    await identity.owned_user(db, owner)  # Includes tenant boundary.
    return owner


async def retire_memberships(db: AsyncSession, device: Device) -> None:
    """Retain history and invalidate live scope within the retirement transaction."""
    from contextify_cloud.services.machine_groups import revise_device_groups

    await revise_device_groups(db, [device.id], retired=True)


def audit_transition(
    db: AsyncSession, auth: AuthContext, device: Device, kind: str,
    payload: RetireDevice | RestoreDevice, actor_user_id: uuid.UUID | None,
) -> None:
    """Commit audit and lifecycle together; reconciled retries never call this."""
    actor = actor_user_id or auth.user_id
    db.add(AuditLog(
        tenant_id=auth.tenant_id, user_id=actor, action=f"device.{kind}",
        resource_type="device", resource_id=str(device.id), detail={
            "request_id": str(payload.request_id),
            "expected_lifecycle_revision": payload.expected_lifecycle_revision,
            "actor_user_id": str(actor), "owner_user_id": str(device.user_id),
        },
    ))


async def retire_device(
    db: AsyncSession, auth: AuthContext, machine_id: str, payload: RetireDevice,
    *, actor_user_id: uuid.UUID | None = None,
) -> Device:
    await identity.owned_user(db, auth, lock=True)
    device = await identity.owned_device(db, auth, machine_id, lock=True)
    if identity.reconcile(device, "lifecycle", "retire", payload,
                          payload.expected_lifecycle_revision):
        return device
    if device.retired_at or device.removed_at:
        identity.fail("DEVICE_RETIRED", "This device is already retired. Refresh device details.")
    if device.identity_instance_id != payload.identity_instance_id:
        identity.fail("DEVICE_IDENTITY_REQUIRED", "Retirement requires this installation's claim.")
    if device.last_sync_at != payload.expected_last_sync_at:
        identity.fail("DEVICE_SYNC_CHANGED", "Device synced after coverage. Run preflight again.")
    device.retired_at = datetime.now(UTC)
    device.identity_instance_id = None
    identity.finish(device, "lifecycle", "retire", payload)
    audit_transition(db, auth, device, "retire", payload, actor_user_id)
    await retire_memberships(db, device)
    await db.flush()
    return device


async def restore_device(
    db: AsyncSession, auth: AuthContext, tenant: Tenant, machine_id: str,
    payload: RestoreDevice, *, remove: bool = False, actor_user_id: uuid.UUID | None = None,
) -> Device:
    await identity.owned_user(db, auth, lock=True)
    device = await identity.owned_device(db, auth, machine_id, lock=True)
    kind = "remove" if remove else "reactivate"
    if identity.reconcile(device, "lifecycle", kind, payload,
                          payload.expected_lifecycle_revision):
        return device
    if device.retired_at is None or device.retired_at != payload.expected_retired_at:
        identity.fail("REQUEST_SUPERSEDED", "Retirement changed. Refresh device details.")
    if remove:
        if device.removed_at:
            identity.fail("REQUEST_SUPERSEDED", "Device already removed. Refresh device details.")
        device.removed_at = datetime.now(UTC)
    else:
        await identity.check_cap(db, auth.user_id, tenant)
        device.retired_at = None
        device.removed_at = None
        from contextify_cloud.services.machine_groups import revise_device_groups
        await revise_device_groups(db, [device.id])
    identity.finish(device, "lifecycle", kind, payload)
    audit_transition(db, auth, device, kind, payload, actor_user_id)
    await db.flush()
    return device
