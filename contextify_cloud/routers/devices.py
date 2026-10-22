"""Owned device management API. Browser adapters share these services."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from contextify_cloud.database import get_db
from contextify_cloud.device_schemas import (
    ClaimDevice,
    DeviceDirectory,
    DeviceView,
    MergeDevice,
    RenameDevice,
    RestoreDevice,
    RetireDevice,
)
from contextify_cloud.middleware.auth import AuthContext
from contextify_cloud.middleware.endpoint_rate_limit import require_sync_rate_limit
from contextify_cloud.models import Tenant
from contextify_cloud.services import device_identity as identity
from contextify_cloud.services.tenant_guard import check_tenant_active

router = APIRouter(prefix="/api/v1/devices", tags=["devices"])
Auth = Annotated[AuthContext, Depends(require_sync_rate_limit)]
DB = Annotated[AsyncSession, Depends(get_db)]


async def mutation_tenant(db: AsyncSession, auth: AuthContext) -> Tenant:
    if auth.role not in {"owner", "admin", "member"}:
        raise HTTPException(403, "Insufficient role")
    await check_tenant_active(db, auth.tenant_id)
    tenant = (
        await db.execute(select(Tenant).where(Tenant.id == auth.tenant_id))
    ).scalar_one_or_none()
    if tenant is None:
        raise HTTPException(404, "Tenant not found")
    return tenant


@router.get("", response_model=DeviceDirectory)
async def list_devices(
    auth: Auth,
    db: DB,
    include_all: bool = False,
    hardware_fingerprint_hash: Annotated[str | None, Query(pattern=r"^[0-9a-f]{64}$")] = None,
) -> DeviceDirectory:
    rows = await identity.directory(db, auth)
    return DeviceDirectory(
        devices=[
            d
            for d in rows
            if (include_all or d.active)
            and (
                hardware_fingerprint_hash is None
                or d.hardware_fingerprint_hash == hardware_fingerprint_hash
            )
        ]
    )


@router.get("/{machine_id}", response_model=DeviceView)
async def show_device(
    machine_id: str, auth: Auth, db: DB, owner_user_id: uuid.UUID | None = None,
) -> DeviceView:
    from contextify_cloud.services.device_lifecycle import lifecycle_owner

    owner = await lifecycle_owner(db, auth, owner_user_id)
    for device in await identity.directory(db, owner):
        if device.machine_id == machine_id:
            return device
    raise HTTPException(404, "Device not found")


@router.patch("/{machine_id}", response_model=DeviceView)
async def rename_device(machine_id: str, payload: RenameDevice, auth: Auth, db: DB) -> DeviceView:
    await mutation_tenant(db, auth)
    device = await identity.owned_device(db, auth, machine_id, lock=True)
    device.display_name = payload.display_name
    await db.flush()
    return await show_device(machine_id, auth, db)


@router.post("/{machine_id}/claim", response_model=DeviceView)
async def claim_device(machine_id: str, payload: ClaimDevice, auth: Auth, db: DB) -> DeviceView:
    tenant = await mutation_tenant(db, auth)
    await identity.claim_device(db, auth, tenant, machine_id, payload, adopt=False)
    return await show_device(machine_id, auth, db)


@router.post("/{machine_id}/adopt", response_model=DeviceView)
async def adopt_device(machine_id: str, payload: ClaimDevice, auth: Auth, db: DB) -> DeviceView:
    tenant = await mutation_tenant(db, auth)
    await identity.claim_device(db, auth, tenant, machine_id, payload, adopt=True)
    return await show_device(machine_id, auth, db)


@router.post("/{machine_id}/merge", response_model=DeviceView)
async def merge_device(machine_id: str, payload: MergeDevice, auth: Auth, db: DB) -> DeviceView:
    await mutation_tenant(db, auth)
    await identity.merge_device(db, auth, machine_id, payload, undo=False)
    return await show_device(machine_id, auth, db)


@router.delete("/{machine_id}/merge", response_model=DeviceView)
async def unmerge_device(machine_id: str, payload: MergeDevice, auth: Auth, db: DB) -> DeviceView:
    await mutation_tenant(db, auth)
    await identity.merge_device(db, auth, machine_id, payload, undo=True)
    return await show_device(machine_id, auth, db)


@router.post("/{machine_id}/retire", response_model=DeviceView)
async def retire_device(
    machine_id: str, payload: RetireDevice, auth: Auth, db: DB,
    owner_user_id: uuid.UUID | None = None,
) -> DeviceView:
    from contextify_cloud.services import device_lifecycle as lifecycle

    await mutation_tenant(db, auth)
    owner = await lifecycle.lifecycle_owner(db, auth, owner_user_id)
    await lifecycle.retire_device(db, owner, machine_id, payload, actor_user_id=auth.user_id)
    return await show_device(machine_id, owner, db)


@router.post("/{machine_id}/reactivate", response_model=DeviceView)
async def reactivate_device(
    machine_id: str, payload: RestoreDevice, auth: Auth, db: DB,
    owner_user_id: uuid.UUID | None = None,
) -> DeviceView:
    return await lifecycle_restore(machine_id, payload, auth, db, owner_user_id, remove=False)


@router.post("/{machine_id}/remove", response_model=DeviceView)
async def remove_device(
    machine_id: str, payload: RestoreDevice, auth: Auth, db: DB,
    owner_user_id: uuid.UUID | None = None,
) -> DeviceView:
    return await lifecycle_restore(machine_id, payload, auth, db, owner_user_id, remove=True)


async def lifecycle_restore(
    machine_id: str, payload: RestoreDevice, auth: Auth, db: DB,
    owner_user_id: uuid.UUID | None, *, remove: bool,
) -> DeviceView:
    from contextify_cloud.services import device_lifecycle as lifecycle

    tenant = await mutation_tenant(db, auth)
    owner = await lifecycle.lifecycle_owner(db, auth, owner_user_id)
    await lifecycle.restore_device(
        db, owner, tenant, machine_id, payload, remove=remove, actor_user_id=auth.user_id,
    )
    return await show_device(machine_id, owner, db)
