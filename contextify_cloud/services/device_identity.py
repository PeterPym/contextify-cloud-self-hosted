"""Device identity, registration and presentation. Transactions belong to callers.

Quota/user NO KEY UPDATE locks precede device locks and allow FK key-share inserts.
Push locks its existing device only;
registration releases no lock until commit. Read activity is committed before the
pull table lock, so device and transcript SHARE locks never nest.
"""

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import HTTPException
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from contextify_cloud.device_schemas import ClaimDevice, DeviceView, IdentityProof, MergeDevice
from contextify_cloud.middleware.auth import AuthContext
from contextify_cloud.models import AuditLog, Device, Tenant, User
from contextify_cloud.schemas import DeviceInfo
from contextify_cloud.services.plan_limits import get_plan_limits

ACTIVITY_WINDOW = timedelta(minutes=10)
MAX_REVISION = 2**63 - 1


def fail(code: str, message: str) -> None:
    raise HTTPException(409, detail={"code": code, "message": message})


async def owned_user(db: AsyncSession, auth: AuthContext, *, lock: bool = False) -> User:
    query = select(User).where(User.id == auth.user_id, User.tenant_id == auth.tenant_id)
    if lock:
        query = query.with_for_update(key_share=True)
    user = (await db.execute(query.execution_options(populate_existing=True))).scalar_one_or_none()
    if user is None:
        raise HTTPException(404, "User not found")
    return user


async def owned_device(
    db: AsyncSession, auth: AuthContext, machine_id: str, *, lock: bool = False
) -> Device:
    query = select(Device).where(Device.user_id == auth.user_id, Device.machine_id == machine_id)
    if lock:
        query = query.with_for_update()
    device = (
        await db.execute(query.execution_options(populate_existing=True))
    ).scalar_one_or_none()
    if device is None:
        raise HTTPException(404, "Device not found")
    return device


async def check_cap(db: AsyncSession, user_id: uuid.UUID, tenant: Tenant) -> None:
    limit = get_plan_limits(tenant).max_devices_per_user
    if limit is not None:
        count = (
            await db.execute(
                select(func.count(Device.id)).where(
                    Device.user_id == user_id,
                    Device.retired_at.is_(None),
                    Device.removed_at.is_(None),
                )
            )
        ).scalar() or 0
        if count >= limit:
            raise HTTPException(
                403,
                detail={
                    "code": "DEVICE_LIMIT", "plan": tenant.plan, "limit": limit,
                    "message": f"Device limit reached ({count}/{limit}) "
                    f"for the {tenant.plan} plan. "
                    "Unlink an unused legacy device on the web Sync page or upgrade your plan.",
                },
            )


def has_identity_state(device: Device) -> bool:
    """Hard deletion must preserve claims, fences and transition retry guards."""
    return any((
        device.identity_instance_id, device.hardware_fingerprint_hash, device.fingerprint_kind,
        device.legacy_writes_fenced, device.merged_into_device_id,
        device.retired_at, device.removed_at,
        device.identity_revision, device.identity_last_request_id,
        device.identity_last_request_kind, device.identity_last_payload_hash,
        device.merge_revision, device.merge_last_request_id,
        device.merge_last_request_kind, device.merge_last_payload_hash,
        device.lifecycle_revision, device.lifecycle_last_request_id,
        device.lifecycle_last_request_kind, device.lifecycle_last_payload_hash,
    ))


async def register_device(
    db: AsyncSession, auth: AuthContext, tenant: Tenant, info: DeviceInfo
) -> Device:
    """Return a locked row; serialize absent-row registration even on unlimited plans."""
    query = select(Device).where(
        Device.user_id == auth.user_id, Device.machine_id == info.machine_id
    )
    device = (await db.execute(query.with_for_update())).scalar_one_or_none()
    if device is None:
        # Held through the first batch; same-user status polls may briefly wait.
        await db.execute(
            select(User.id)
            .where(User.id == auth.user_id, User.tenant_id == auth.tenant_id)
            .with_for_update(key_share=True)
        )
        device = (await db.execute(query.with_for_update())).scalar_one_or_none()
        if device is None:
            await check_cap(db, auth.user_id, tenant)
            device = Device(
                user_id=auth.user_id,
                machine_id=info.machine_id,
                machine_name=info.machine_name,
                display_name=info.display_name,
                os=info.os,
                app_version=info.app_version,
                identity_revision=0,
                merge_revision=0,
                lifecycle_revision=0,
                legacy_writes_fenced=False,
            )
            db.add(device)
            await db.flush()
    return device


def proof_matches(device: Device, proof: IdentityProof) -> bool:
    return device.identity_instance_id == proof.identity_instance_id and not (
        device.hardware_fingerprint_hash
        and proof.hardware_fingerprint_hash
        and (
            device.hardware_fingerprint_hash != proof.hardware_fingerprint_hash
            or device.fingerprint_kind != proof.fingerprint_kind
        )
    )


def write_refusal(device: Device, proof: IdentityProof, now: datetime) -> str | None:
    if device.retired_at or device.removed_at:
        return "DEVICE_RETIRED"
    if proof.identity_instance_id is None:
        return "DEVICE_IDENTITY_REQUIRED" if device.legacy_writes_fenced else None
    if device.identity_instance_id is not None and not proof_matches(device, proof):
        if device.last_seen_at and device.last_seen_at + ACTIVITY_WINDOW > now:
            return "DEVICE_ID_CONFLICT"
        return "DEVICE_ADOPTION_REQUIRED"
    return None


def bind_proof(device: Device, proof: IdentityProof) -> None:
    if proof.identity_instance_id is not None:
        if device.identity_instance_id is None:
            if (device.identity_revision or 0) >= MAX_REVISION:
                fail("REVISION_EXHAUSTED", "Device identity revision exhausted")
            device.identity_instance_id = proof.identity_instance_id
            device.identity_revision = (device.identity_revision or 0) + 1
        if proof.hardware_fingerprint_hash:
            device.hardware_fingerprint_hash = proof.hardware_fingerprint_hash
            device.fingerprint_kind = proof.fingerprint_kind


async def record_read_activity(
    db: AsyncSession,
    auth: AuthContext,
    machine_id: str | None,
    instance_id: uuid.UUID | None,
    setup: bool = False,
) -> None:
    if setup:
        if instance_id is None:
            raise HTTPException(422, "Setup discovery requires identity_instance_id")
        return
    if machine_id and instance_id:
        # The conditional update rechecks the proof after any adoption lock wait.
        await db.execute(
            update(Device)
            .where(
                Device.user_id == auth.user_id,
                Device.machine_id == machine_id,
                Device.identity_instance_id == instance_id,
            )
            .values(last_seen_at=func.clock_timestamp())
        )
    else:
        await db.execute(
            update(User)
            .where(User.id == auth.user_id, User.tenant_id == auth.tenant_id)
            .values(last_unattributed_sync_at=func.clock_timestamp())
        )
    await db.commit()


def available_at(device: Device, user: User) -> datetime:
    times = [user.identity_observation_started_at]
    if user.last_unattributed_sync_at:
        times.append(user.last_unattributed_sync_at)
    if device.last_seen_at:
        times.append(device.last_seen_at)
    return max(times) + ACTIVITY_WINDOW


def short_ids(devices: list[Device]) -> dict[str, str]:
    ids = {d.machine_id for d in devices}
    result = {}
    for value in ids:
        length = min(8, len(value))
        while length < len(value) and any(
            other != value and other.endswith(value[-length:]) for other in ids
        ):
            length += 1
        result[value] = value[-length:]
    return result


def project_devices(devices: list[Device], user: User) -> list[DeviceView]:
    by_id = {d.id: d for d in devices}
    suffixes = short_ids(devices)
    now = datetime.now(UTC)
    views = []
    for d in devices:
        canonical = by_id.get(d.merged_into_device_id, d) if d.merged_into_device_id else d
        constituents = [
            x.machine_id
            for x in devices
            if x.id == canonical.id or x.merged_into_device_id == canonical.id
        ]
        until = available_at(d, user)
        activity = "inactive"
        if d.last_seen_at and d.last_seen_at + ACTIVITY_WINDOW > now:
            activity = "active"
        elif until > now:
            activity = "unknown"
        views.append(
            DeviceView(
                device_record_id=d.id,
                device_id=d.machine_id,
                machine_id=d.machine_id,
                machine_name=d.display_name or d.machine_name,
                reported_name=d.machine_name,
                display_name=d.display_name,
                short_id=suffixes[d.machine_id],
                os=d.os,
                app_version=d.app_version,
                active=d.retired_at is None and d.removed_at is None,
                merged=d.merged_into_device_id is not None,
                canonical_device_id=canonical.machine_id,
                constituent_device_ids=sorted(constituents),
                merged_into_device_id=canonical.machine_id if d.merged_into_device_id else None,
                last_sync_at=d.last_sync_at,
                last_seen_at=d.last_seen_at,
                activity=activity,
                adoption_eligible=until <= now,
                adoption_available_at=until if until > now else None,
                hardware_fingerprint_hash=d.hardware_fingerprint_hash,
                fingerprint_kind=d.fingerprint_kind,
                identity_instance_id=d.identity_instance_id,
                identity_revision=d.identity_revision,
                identity_last_request_id=d.identity_last_request_id,
                identity_last_request_kind=d.identity_last_request_kind,
                identity_last_payload_hash=d.identity_last_payload_hash,
                merge_revision=d.merge_revision,
                merge_last_request_id=d.merge_last_request_id,
                merge_last_request_kind=d.merge_last_request_kind,
                merge_last_payload_hash=d.merge_last_payload_hash,
                lifecycle_revision=d.lifecycle_revision,
                lifecycle_last_request_id=d.lifecycle_last_request_id,
                lifecycle_last_request_kind=d.lifecycle_last_request_kind,
                lifecycle_last_payload_hash=d.lifecycle_last_payload_hash,
                retired_at=d.retired_at,
                removed_at=d.removed_at,
            )
        )
    return views


async def directory(db: AsyncSession, auth: AuthContext) -> list[DeviceView]:
    user = await owned_user(db, auth)
    rows = (
        (
            await db.execute(
                select(Device).where(Device.user_id == auth.user_id).order_by(Device.machine_id)
            )
        )
        .scalars()
        .all()
    )
    return project_devices(list(rows), user)


def operation_hash(kind: str, payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            {"kind": kind, "payload": payload.model_dump(mode="json")}, sort_keys=True
        ).encode()
    ).hexdigest()


def reconcile(d: Device, family: str, kind: str, payload: Any, expected: int) -> bool:
    revision = getattr(d, f"{family}_revision")
    if getattr(d, f"{family}_last_request_id") == payload.request_id:
        if (
            getattr(d, f"{family}_last_payload_hash") == operation_hash(kind, payload)
            and revision == expected + 1
        ):
            return True
        fail("REQUEST_SUPERSEDED", "Request no longer matches the current device operation")
    if revision != expected:
        fail("REQUEST_SUPERSEDED", "Refresh device details before retrying")
    if revision >= MAX_REVISION:
        fail("REVISION_EXHAUSTED", "Device revision exhausted")
    return False


def finish(d: Device, family: str, kind: str, payload: Any) -> None:
    setattr(d, f"{family}_revision", getattr(d, f"{family}_revision") + 1)
    setattr(d, f"{family}_last_request_id", payload.request_id)
    setattr(d, f"{family}_last_request_kind", kind)
    setattr(d, f"{family}_last_payload_hash", operation_hash(kind, payload))


async def claim_device(
    db: AsyncSession,
    auth: AuthContext,
    tenant: Tenant,
    machine_id: str,
    payload: ClaimDevice,
    *,
    adopt: bool,
) -> Device:
    user = await owned_user(db, auth, lock=True)
    if adopt:
        d = await owned_device(db, auth, machine_id, lock=True)
    else:
        d = await register_device(
            db,
            auth,
            tenant,
            DeviceInfo(
                machine_id=machine_id,
                machine_name=payload.machine_name,
                os=payload.os,
                app_version=payload.app_version,
            ),
        )
    kind = "adopt" if adopt else "claim"
    if reconcile(d, "identity", kind, payload, payload.expected_identity_revision):
        lifecycle_matches = d.lifecycle_revision == payload.expected_lifecycle_revision
        if (d.lifecycle_revision == payload.expected_lifecycle_revision + 1
                and d.lifecycle_last_request_id == payload.request_id
                and d.lifecycle_last_request_kind == "adopt"
                and d.lifecycle_last_payload_hash == operation_hash("adopt", payload)):
            lifecycle_matches = True
        if d.identity_instance_id != payload.identity_instance_id or not lifecycle_matches:
            fail("REQUEST_SUPERSEDED", "Device claim has changed")
        return d
    if d.lifecycle_revision != payload.expected_lifecycle_revision:
        fail("REQUEST_SUPERSEDED", "Device lifecycle has changed")
    retired = bool(d.retired_at or d.removed_at)
    if retired and not adopt:
        fail("DEVICE_RETIRED", "Return this device to service before claiming it")
    if adopt:
        now = datetime.now(UTC)
        # A user's attestation resolves uncertainty only. Attributed source
        # activity always wins, including a push/poll committed while we waited.
        if d.last_seen_at and d.last_seen_at + ACTIVITY_WINDOW > now:
            fail(
                "DEVICE_ACTIVE",
                "This device is still active. Stop Contextify on that device and try again.",
            )
        if available_at(d, user) > now and not payload.source_offline_attested:
            fail(
                "SOURCE_OFFLINE_REQUIRED",
                "Contextify cannot confirm whether this device is active. "
                "Confirm the original installation is no longer in use.",
            )
        if retired:
            # Same quota-owner/device lock order and durable lifecycle family.
            reconcile(d, "lifecycle", "adopt", payload, payload.expected_lifecycle_revision)
            await check_cap(db, auth.user_id, tenant)
            d.retired_at = None
            d.removed_at = None
            from contextify_cloud.services.machine_groups import revise_device_groups
            await revise_device_groups(db, [d.id])
            finish(d, "lifecycle", "adopt", payload)
        # Durable, transaction-scoped attestation and the locked activity basis.
        # Unlike best-effort telemetry, this evidence must commit with transfer.
        db.add(AuditLog(
            tenant_id=auth.tenant_id, user_id=auth.user_id, action="device.adopt",
            resource_type="device", resource_id=str(d.id), detail={
                "request_id": str(payload.request_id),
                "source_offline_attested": payload.source_offline_attested,
                "activity_basis": {
                    "last_seen_at": d.last_seen_at.isoformat() if d.last_seen_at else None,
                    "last_unattributed_sync_at": user.last_unattributed_sync_at.isoformat()
                    if user.last_unattributed_sync_at else None,
                    "identity_observation_started_at":
                        user.identity_observation_started_at.isoformat(),
                    "checked_at": now.isoformat(),
                },
            },
        ))
        d.legacy_writes_fenced = True
    elif d.identity_instance_id is not None:
        fail("DEVICE_ADOPTION_REQUIRED", "This identity is already bound; use explicit adoption")
    d.identity_instance_id = payload.identity_instance_id
    d.hardware_fingerprint_hash = payload.hardware_fingerprint_hash
    d.fingerprint_kind = payload.fingerprint_kind
    d.last_seen_at = datetime.now(UTC)
    finish(d, "identity", kind, payload)
    await db.flush()
    return d


async def merge_device(
    db: AsyncSession, auth: AuthContext, machine_id: str, payload: MergeDevice, *, undo: bool
) -> Device:
    # User lock serializes graph edits, including initially absent aliases. Sorted
    # device locks keep operand ordering independent of request direction.
    await owned_user(db, auth, lock=True)
    rows = list(
        (
            await db.execute(
                select(Device)
                .where(Device.user_id == auth.user_id)
                .order_by(Device.id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    )
    by_machine = {d.machine_id: d for d in rows}
    source = by_machine.get(machine_id)
    target = by_machine.get(payload.into_device_id)
    if source is None or target is None:
        raise HTTPException(404, "Device not found")
    kind = "unmerge" if undo else "merge"
    if reconcile(source, "merge", kind, payload, payload.expected_merge_revision):
        return source
    if undo:
        if source.merged_into_device_id != target.id:
            fail("REQUEST_SUPERSEDED", "Merge target has changed")
        source.merged_into_device_id = None
    else:
        if (
            source.id == target.id
            or target.merged_into_device_id
            or source.merged_into_device_id
            or any(d.merged_into_device_id == source.id for d in rows)
        ):
            fail(
                "INVALID_MERGE",
                "Merge requires a canonical target and a source "
                "without aliases or an existing merge",
            )
        source.merged_into_device_id = target.id
    from contextify_cloud.services.machine_groups import revise_device_groups

    await revise_device_groups(db, [source.id, target.id])
    finish(source, "merge", kind, payload)
    await db.flush()
    return source


async def read_device_set(db: AsyncSession, auth: AuthContext, machine_id: str) -> list[str]:
    """Exact owned selector expands only the presentation relation, never ACLs."""
    rows = list((await db.execute(select(Device).where(Device.user_id == auth.user_id))).scalars())
    source = next((d for d in rows if d.machine_id == machine_id), None)
    if source is None:
        raise HTTPException(404, "Device not found")
    canonical_id = source.merged_into_device_id or source.id
    return [
        d.machine_id
        for d in rows
        if d.id == canonical_id or d.merged_into_device_id == canonical_id
    ]
