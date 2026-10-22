"""Group metadata and enrollment. Caller owns the transaction.

Lock order: quota owner, physical devices in UUID order, groups in UUID order,
then tokens. Never acquire a transcript SHARE lock in a mutation transaction.
"""

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import HTTPException
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from contextify_cloud.group_schemas import (
    CreateGroup,
    CreateToken,
    EditGroup,
    JoinGroup,
    MemberEdit,
    ProjectSelector,
)
from contextify_cloud.middleware.auth import AuthContext, hash_api_key, verify_api_key
from contextify_cloud.models import (
    AuditLog,
    Device,
    MachineGroup,
    MachineGroupDevice,
    MachineGroupJoinToken,
    MachineGroupTokenRedemption,
    Tenant,
    User,
)
from contextify_cloud.services import device_identity as identity
from contextify_cloud.services.plan_limits import (
    machine_group_capabilities,
    require_machine_group_team,
)
from contextify_cloud.services.tenant import get_tenant_schema
from contextify_cloud.services.tenant_guard import check_tenant_active


def fail(code: str, message: str, status: int = 409) -> None:
    raise HTTPException(status, {"code": code, "message": message, "complete": False})


def manages(auth: AuthContext, group: MachineGroup) -> bool:
    return auth.role != "viewer" and (
        group.owner_user_id == auth.user_id or (group.visibility == "team" and auth.has_full_access)
    )


async def tenant_for(db: AsyncSession, auth: AuthContext, *, mutation: bool = False) -> Tenant:
    user = await identity.owned_user(db, auth)
    if user.removed_at is not None:
        raise HTTPException(401, "Account unavailable")
    # Recheck role on each operation, including cookie-authenticated adapters.
    auth.role = user.role
    tenant = await db.get(Tenant, auth.tenant_id)
    if tenant is None or tenant.status != "active":
        raise HTTPException(403, "Tenant unavailable")
    if mutation:
        if auth.role == "viewer":
            raise HTTPException(403, "Read-only viewers cannot manage groups")
        await check_tenant_active(db, auth.tenant_id)
    return tenant


def visible(auth: AuthContext) -> Any:
    return (MachineGroup.tenant_id == auth.tenant_id) & (
        (MachineGroup.owner_user_id == auth.user_id) | (MachineGroup.visibility == "team")
    )


async def resolve(
    db: AsyncSession, auth: AuthContext, selector: str, *, lock: bool = False, manage: bool = False
) -> MachineGroup:
    rows = list((await db.scalars(select(MachineGroup).where(visible(auth)))).all())
    exact = [g for g in rows if str(g.id) == selector]
    candidates = exact or [g for g in rows if g.normalized_name == selector.strip().casefold()]
    if not candidates and len(selector) >= 4:
        candidates = [g for g in rows if str(g.id).startswith(selector.lower())]
    if not candidates:
        raise HTTPException(404, "Group not found")
    if len(candidates) != 1:
        raise HTTPException(
            409,
            {
                "code": "ambiguous_group",
                "candidates": [{"id": str(g.id), "name": g.name} for g in candidates],
            },
        )
    g = candidates[0]
    if lock:
        g = (
            await db.execute(
                select(MachineGroup)
                .where(MachineGroup.id == g.id, visible(auth))
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        ).scalar_one()
    if manage and not manages(auth, g):
        raise HTTPException(403, "Group management permission required")
    if g.visibility == "team":
        require_machine_group_team(await tenant_for(db, auth))
    return g


def audit(
    db: AsyncSession, auth: AuthContext, group: MachineGroup, action: str, **detail: Any
) -> None:
    db.add(
        AuditLog(
            tenant_id=auth.tenant_id,
            user_id=auth.user_id,
            action="group." + action,
            resource_type="machine_group",
            resource_id=str(group.id),
            detail=detail,
        )
    )


def bump(group: MachineGroup) -> None:
    group.revision += 1
    group.updated_at = datetime.now(UTC)


def cas(group: MachineGroup, expected: int) -> None:
    if group.revision != expected:
        fail("scope_changed", "Group changed. Refresh its details and retry.")


async def validate_project(
    db: AsyncSession, auth: AuthContext, tenant: Tenant, selector: ProjectSelector | None
) -> None:
    if selector is None:
        return
    schema = get_tenant_schema(tenant.slug)
    column = "id" if selector.kind == "project_id" else "repo_group_key"
    found = await db.scalar(
        text(f"""
        SELECT 1 FROM {schema}.projects p WHERE p.{column} = :value
          AND (:full OR p.created_by_user_id = :uid OR EXISTS (
            SELECT 1 FROM {schema}.project_team_shares s
            WHERE s.project_id=p.id AND :member)) LIMIT 1
    """),
        {
            "value": selector.value,
            "full": auth.has_full_access,
            "uid": auth.user_id,
            "member": auth.role == "member",
        },
    )
    if not found:
        fail("project_not_found", "Select an existing visible Cloud project", 404)


async def create(db: AsyncSession, auth: AuthContext, payload: CreateGroup) -> MachineGroup:
    tenant = await tenant_for(db, auth, mutation=True)
    if payload.visibility == "team":
        require_machine_group_team(tenant)
        if not auth.has_full_access:
            raise HTTPException(403, "Only owners and admins can create team groups")
    await validate_project(db, auth, tenant, payload.project_selector)
    group = MachineGroup(
        tenant_id=auth.tenant_id,
        owner_user_id=auth.user_id,
        name=payload.name,
        normalized_name=payload.name.casefold(),
        visibility=payload.visibility,
        project_selector=payload.project_selector.model_dump()
        if payload.project_selector
        else None,
        revision=0,
    )
    try:
        async with db.begin_nested():
            db.add(group)
            await db.flush()
    except IntegrityError:
        fail("duplicate_group_name", "A group with this name already exists")
    audit(db, auth, group, "create")
    return group


async def edit(
    db: AsyncSession, auth: AuthContext, selector: str, payload: EditGroup
) -> MachineGroup:
    tenant = await tenant_for(db, auth, mutation=True)
    group = await resolve(db, auth, selector, lock=True, manage=True)
    cas(group, payload.expected_revision)
    if "project_selector" in payload.model_fields_set:
        await validate_project(db, auth, tenant, payload.project_selector)
        value = payload.project_selector.model_dump() if payload.project_selector else None
        if value != group.project_selector:
            group.project_selector = value
            bump(group)
    try:
        async with db.begin_nested():
            if payload.name is not None:
                group.name = payload.name
                group.normalized_name = payload.name.casefold()
            group.updated_at = datetime.now(UTC)
            await db.flush()
    except IntegrityError:
        fail("duplicate_group_name", "A group with this name already exists")
    audit(db, auth, group, "edit")
    return group


async def locked_devices(db: AsyncSession, auth: AuthContext, record_id: uuid.UUID) -> list[Device]:
    # Resolve tenant-qualified owner first, then serialize alias edits with the
    # owning user exactly as identity.merge_device does.
    owner_id = await db.scalar(
        select(Device.user_id)
        .join(User)
        .where(Device.id == record_id, User.tenant_id == auth.tenant_id, User.removed_at.is_(None))
    )
    if owner_id is None:
        raise HTTPException(404, "Device not found")
    await db.execute(select(User.id).where(User.id == owner_id).with_for_update(key_share=True))
    return list(
        (
            await db.scalars(
                select(Device)
                .where(Device.user_id == owner_id)
                .order_by(Device.id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        ).all()
    )


async def change_member(
    db: AsyncSession, auth: AuthContext, selector: str, payload: MemberEdit, *, remove: bool
) -> MachineGroup:
    await tenant_for(db, auth, mutation=True)
    devices = await locked_devices(db, auth, payload.device_record_id)
    device = next(d for d in devices if d.id == payload.device_record_id)
    group = await resolve(db, auth, selector, lock=True)
    if not manages(auth, group) and not (remove and device.user_id == auth.user_id):
        raise HTTPException(403, "Group management permission required")
    if group.visibility == "private" and device.user_id != group.owner_user_id:
        raise HTTPException(404, "Device not found")
    canonical = device.merged_into_device_id or device.id
    ids = [d.id for d in devices if d.id == canonical or d.merged_into_device_id == canonical]
    members = list(
        (
            await db.scalars(
                select(MachineGroupDevice).where(
                    MachineGroupDevice.group_id == group.id,
                    MachineGroupDevice.device_record_id.in_(ids if remove else [device.id]),
                )
            )
        ).all()
    )
    if remove and not members:
        return group  # Idempotent removal, including a lost response.
    cas(group, payload.expected_revision)
    if remove:
        for member in members:
            await db.delete(member)
        bump(group)
    else:
        await add_member(db, group, device)
    audit(db, auth, group, "remove" if remove else "add", device_record_id=str(device.id))
    await db.flush()
    return group


async def add_member(db: AsyncSession, group: MachineGroup, device: Device) -> None:
    if device.retired_at or device.removed_at:
        fail("DEVICE_RETIRED", "Return this physical device to service before adding it")
    member = await db.get(MachineGroupDevice, (group.id, device.id))
    if member and member.state == "active":
        return
    if member:
        member.state, member.retired_at = "active", None
        member.joined_at = datetime.now(UTC)
    else:
        db.add(MachineGroupDevice(group_id=group.id, device_record_id=device.id, state="active"))
    bump(group)


async def join(
    db: AsyncSession, auth: AuthContext, selector: str, payload: JoinGroup
) -> MachineGroup:
    tenant = await tenant_for(db, auth, mutation=True)
    # Registration, claim, token redemption and membership commit or roll back together.
    if payload.claim:
        device = await identity.claim_device(
            db, auth, tenant, payload.device_id, payload.claim, adopt=False
        )
    else:
        await identity.owned_user(db, auth, lock=True)
        device = await identity.owned_device(db, auth, payload.device_id, lock=True)
        if payload.identity_instance_id is None or (
            device.identity_instance_id != payload.identity_instance_id
        ):
            fail("DEVICE_IDENTITY_REQUIRED", "Join requires this installation's current claim")
    group = await resolve(db, auth, selector, lock=True)
    if payload.join_token is not None:
        if group.visibility != "team":
            fail("invalid_join_token", "Join token is not valid", 403)
        await redeem(db, auth, group, device, payload.join_token.get_secret_value())
    elif not manages(auth, group):
        fail("join_token_required", "Use a teammate join token with your own account key", 403)
    if group.visibility == "private" and group.owner_user_id != device.user_id:
        raise HTTPException(404, "Group not found")
    await add_member(db, group, device)
    audit(db, auth, group, "join", device_record_id=str(device.id))
    await db.flush()
    return group


async def redeem(
    db: AsyncSession, auth: AuthContext, group: MachineGroup, device: Device, raw: str
) -> None:
    try:
        prefix, token_id, secret = raw.split("_")
        token_uuid = uuid.UUID(hex=token_id)
        if prefix != "ctxg" or len(secret) != 64:
            raise ValueError
    except ValueError:
        fail("invalid_join_token", "Join token is not valid", 403)
    from contextify_cloud.config import settings
    from contextify_cloud.middleware.endpoint_rate_limit import _check_rate_limit, _sync_request_log

    _check_rate_limit(
        _sync_request_log,
        f"group-token:{token_uuid}",
        settings.rate_limit_sync_per_minute,
        "group token",
    )
    token = await db.scalar(
        select(MachineGroupJoinToken)
        .where(MachineGroupJoinToken.id == token_uuid, MachineGroupJoinToken.group_id == group.id)
        .with_for_update()
    )
    if token is None or not await asyncio.to_thread(verify_api_key, secret, token.secret_hash):
        fail("invalid_join_token", "Join token is not valid", 403)
    assert token is not None
    issuer = await db.get(User, token.issuer_user_id)
    if (
        token.revoked_at
        or token.expires_at <= datetime.now(UTC)
        or issuer is None
        or issuer.removed_at
        or issuer.tenant_id != auth.tenant_id
        or issuer.role == "viewer"
        or not (issuer.id == group.owner_user_id or issuer.role in {"owner", "admin"})
    ):
        fail("invalid_join_token", "Join token expired, revoked, or no longer authorized", 403)
    prior = await db.get(MachineGroupTokenRedemption, (token.id, device.id))
    if prior is None:
        if token.uses >= token.max_uses:
            fail("join_token_exhausted", "Join token has no uses remaining", 403)
        token.uses += 1
        db.add(MachineGroupTokenRedemption(token_id=token.id, device_record_id=device.id))


def token_view(token: MachineGroupJoinToken) -> dict[str, Any]:
    return {
        "id": str(token.id),
        "create_request_id": str(token.create_request_id),
        "expires_at": token.expires_at,
        "revoked_at": token.revoked_at,
        "max_uses": token.max_uses,
        "uses": token.uses,
        "delivery_acknowledged_at": token.delivery_acknowledged_at,
        "state": "revoked"
        if token.revoked_at
        else "expired"
        if token.expires_at <= datetime.now(UTC)
        else "delivered"
        if token.delivery_acknowledged_at
        else "issued_unsaved",
    }


async def issue_token(
    db: AsyncSession, auth: AuthContext, selector: str, payload: CreateToken
) -> dict[str, Any]:
    import secrets

    await tenant_for(db, auth, mutation=True)
    group = await resolve(db, auth, selector, lock=True, manage=True)
    if group.visibility != "team":
        fail("team_group_required", "Private groups use owner credentials", 400)
    prior = await db.scalar(
        select(MachineGroupJoinToken).where(
            MachineGroupJoinToken.group_id == group.id,
            MachineGroupJoinToken.issuer_user_id == auth.user_id,
            MachineGroupJoinToken.create_request_id == payload.create_request_id,
        )
    )
    if prior:
        return {**token_view(prior), "secret": None, "reconciled": True}
    secret = secrets.token_hex(32)
    token = MachineGroupJoinToken(
        group_id=group.id,
        issuer_user_id=auth.user_id,
        create_request_id=payload.create_request_id,
        secret_hash=await asyncio.to_thread(hash_api_key, secret),
        expires_at=datetime.now(UTC) + timedelta(seconds=payload.expires_in),
        max_uses=payload.max_uses,
        uses=0,
    )
    db.add(token)
    await db.flush()
    audit(db, auth, group, "token_issue", token_id=str(token.id))
    return {**token_view(token), "secret": f"ctxg_{token.id.hex}_{secret}", "reconciled": False}


async def tokens(
    db: AsyncSession, auth: AuthContext, selector: str, *,
    include_inactive: bool = False, limit: int = 50, offset: int = 0,
) -> dict[str, Any]:
    await tenant_for(db, auth)
    group = await resolve(db, auth, selector, manage=True)
    query = select(MachineGroupJoinToken).where(MachineGroupJoinToken.group_id == group.id)
    if not include_inactive:
        query = query.where(
            MachineGroupJoinToken.revoked_at.is_(None),
            MachineGroupJoinToken.expires_at > datetime.now(UTC),
        )
    rows = list(await db.scalars(query.order_by(
        MachineGroupJoinToken.created_at.desc(), MachineGroupJoinToken.id.desc(),
    ).offset(offset).limit(limit + 1)))
    return {"tokens": [token_view(t) for t in rows[:limit]], "has_more": len(rows) > limit,
            "next_offset": offset + limit if len(rows) > limit else None}



async def update_token(
    db: AsyncSession, auth: AuthContext, selector: str, token_id: uuid.UUID, *, revoke: bool
) -> dict[str, Any]:
    await tenant_for(db, auth, mutation=True)
    group = await resolve(db, auth, selector, lock=True, manage=True)
    token = await db.scalar(
        select(MachineGroupJoinToken)
        .where(MachineGroupJoinToken.id == token_id, MachineGroupJoinToken.group_id == group.id)
        .with_for_update()
    )
    if token is None:
        raise HTTPException(404, "Token not found")
    if revoke:
        if token.revoked_at is None:
            token.revoked_at = datetime.now(UTC)
            audit(db, auth, group, "token_revoke", token_id=str(token.id))
    elif token.revoked_at is None and token.delivery_acknowledged_at is None:
        token.delivery_acknowledged_at = datetime.now(UTC)
        audit(db, auth, group, "token_delivery", token_id=str(token.id))
    await db.flush()
    return token_view(token)


async def revise_device_groups(
    db: AsyncSession, device_ids: list[uuid.UUID], *, retired: bool = False
) -> None:
    # Include indirect aliases: an origin can be live through a sibling's membership.
    canonicals = select(func.coalesce(Device.merged_into_device_id, Device.id)).where(
        Device.id.in_(device_ids)
    )
    affected = select(Device.id).where(
        func.coalesce(Device.merged_into_device_id, Device.id).in_(canonicals)
    )
    ids = select(MachineGroupDevice.group_id).where(
        MachineGroupDevice.device_record_id.in_(affected)
    )
    groups = list(
        (
            await db.scalars(
                select(MachineGroup)
                .where(MachineGroup.id.in_(ids))
                .order_by(MachineGroup.id)
                .with_for_update()
            )
        ).all()
    )
    for group in groups:
        if retired:
            members = await db.scalars(
                select(MachineGroupDevice).where(
                    MachineGroupDevice.group_id == group.id,
                    MachineGroupDevice.device_record_id.in_(device_ids),
                    MachineGroupDevice.state == "active",
                )
            )
            for member in members:
                member.state, member.retired_at = "retired", datetime.now(UTC)
        bump(group)
    await db.flush()


async def detail(db: AsyncSession, auth: AuthContext, group: MachineGroup) -> dict[str, Any]:
    rows = (
        await db.execute(
            select(Device, User, MachineGroupDevice)
            .join(User, User.id == Device.user_id)
            .join(MachineGroupDevice, MachineGroupDevice.device_record_id == Device.id)
            .where(MachineGroupDevice.group_id == group.id, User.tenant_id == auth.tenant_id)
            .order_by(Device.id)
        )
    ).all()
    direct = {d.id: member for d, user, member in rows}
    canonical_ids = {d.merged_into_device_id or d.id for d, user, member in rows}
    effective = (
        await db.execute(
            select(Device, User)
            .join(User)
            .where(
                User.tenant_id == auth.tenant_id,
                User.removed_at.is_(None),
                func.coalesce(Device.merged_into_device_id, Device.id).in_(canonical_ids),
            )
            .order_by(Device.id)
        )
    ).all()
    projections = {}
    for owner_id in {d.user_id for d, user in effective}:
        owned = [(d, u) for d, u in effective if d.user_id == owner_id]
        projections.update(
            {
                v.device_record_id: v
                for v in identity.project_devices([d for d, u in owned], owned[0][1])
            }
        )
    devices = []
    for d, user in effective:
        projection = projections[d.id]
        member = direct.get(d.id)
        canonical = d.merged_into_device_id or d.id
        active_inherited = any(
            m.state == "active" and (other.merged_into_device_id or other.id) == canonical
            for other, _, m in rows
        )
        state = member.state if member else "active" if active_inherited else "retired"
        devices.append(
            {
                "device_record_id": str(d.id),
                "device_id": d.machine_id,
                "name": projection.machine_name,
                "short_id": projection.short_id,
                "state": state,
                "stored_membership": member is not None,
                "physically_active": projection.active,
                "canonical_record_id": str(canonical),
                "owner_user_id": str(d.user_id),
                "owner_name": user.name,
                "last_seen_at": d.last_seen_at,
                "last_push_at": d.last_sync_at,
                "retired_at": member.retired_at if member else d.retired_at,
            }
        )
    return {
        "id": str(group.id),
        "name": group.name,
        "visibility": group.visibility,
        "owner_user_id": str(group.owner_user_id),
        "revision": group.revision,
        "project_selector": group.project_selector,
        "can_manage": manages(auth, group),
        "devices": devices,
        "active_count": sum(d["state"] == "active" and d["physically_active"] for d in devices),
        "retired_count": sum(
            d["state"] == "retired" or not d["physically_active"] for d in devices
        ),
    }


async def directory(db: AsyncSession, auth: AuthContext) -> dict[str, Any]:
    tenant = await tenant_for(db, auth)
    groups = await db.scalars(select(MachineGroup).where(visible(auth)).order_by(MachineGroup.name))
    return {
        "groups": [await detail(db, auth, g) for g in groups],
        "capabilities": machine_group_capabilities(tenant),
    }
