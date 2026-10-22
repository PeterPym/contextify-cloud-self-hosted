"""Machine groups: additive management and server-authoritative recall API."""

import asyncio
import uuid
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, Security
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import ValidationError
from sqlalchemy import text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from contextify_cloud.config import settings
from contextify_cloud.database import async_session_factory, get_db
from contextify_cloud.group_schemas import (
    AcknowledgeToken,
    CreateGroup,
    CreateToken,
    EditGroup,
    GroupQuery,
    JoinGroup,
    MemberEdit,
)
from contextify_cloud.middleware.auth import AuthContext, api_key_header, verify_credential
from contextify_cloud.middleware.endpoint_rate_limit import (
    _check_rate_limit,
    _search_request_log,
    _sync_request_log,
)
from contextify_cloud.models import ApiKey
from contextify_cloud.services import group_reads
from contextify_cloud.services import machine_groups as groups


def error_response(
    request: Request, detail: Any, status: int, headers: dict[str, str] | None = None
) -> JSONResponse:
    code = (
        str(detail.get("code", detail.get("error", "request_failed")))
        if isinstance(detail, dict)
        else {
            401: "authentication_required",
            403: "permission_denied",
            404: "not_found",
            422: "invalid_input",
            429: "rate_limited",
            503: "activity_busy",
        }.get(status, "request_failed")
    )
    headers = {**(headers or {}), "Cache-Control": "no-store"}
    return JSONResponse(
        {
            "detail": detail,
            "complete": False,
            "details": {
                "code": code,
                "requested_scope": {"group": request.path_params.get("selector")},
                "retry_after": headers.get("Retry-After"),
            },
        },
        status_code=status,
        headers=headers,
    )


class GroupRoute(APIRoute):
    """No-store responses; exceptions must escape so dependency rollback runs."""

    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        handler = super().get_route_handler()

        async def scoped(request: Request) -> Response:
            response = await handler(request)
            response.headers["Cache-Control"] = "no-store"
            return response

        return scoped


router = APIRouter(prefix="/api/v1/machine-groups", tags=["machine-groups"], route_class=GroupRoute)
DB = Annotated[AsyncSession, Depends(get_db)]


async def short_auth(
    request: Request, api_key: Annotated[str | None, Security(api_key_header)]
) -> AuthContext:
    # Verification ends before the page transaction begins. Bookkeeping never
    # waits behind a long push holding this same API key's row.
    async with async_session_factory() as db:
        auth = await verify_credential(request, api_key, db, record_usage=False)
    try:
        async with asyncio.timeout(0.15), async_session_factory.begin() as db:
            await db.execute(text("SET LOCAL lock_timeout = '50ms'"))
            await db.execute(
                update(ApiKey)
                .where(ApiKey.key_id == auth.key_id)
                .values(last_used_at=datetime.now(UTC))
            )
    except (DBAPIError, TimeoutError):
        pass
    return auth


def budget(request: Request, auth: AuthContext, *, search: bool) -> AuthContext:
    scope = "search" if search else "sync"
    if scope not in auth.scopes:
        raise HTTPException(403, f"API key missing required scope: {scope}")
    remaining, limit, reset = _check_rate_limit(
        _search_request_log if search else _sync_request_log,
        auth.key_id if search else f"group:{auth.tenant_id}:{auth.user_id}",
        settings.rate_limit_search_per_minute if search else settings.rate_limit_sync_per_minute,
        "search" if search else "group management",
    )
    request.state.rate_limit_remaining = remaining
    request.state.rate_limit_limit = limit
    request.state.rate_limit_reset = reset
    if not search:
        _check_rate_limit(
            _sync_request_log,
            f"group-ip:{request.client.host if request.client else ''}",
            settings.rate_limit_sync_per_minute * 3,
            "group management",
        )
    return auth


async def manage_auth(
    request: Request, auth: Annotated[AuthContext, Depends(short_auth)]
) -> AuthContext:
    return budget(request, auth, search=False)


async def read_auth(
    request: Request, auth: Annotated[AuthContext, Depends(short_auth)]
) -> AuthContext:
    return budget(request, auth, search=True)


Auth = Annotated[AuthContext, Depends(manage_auth)]
ReadAuth = Annotated[AuthContext, Depends(read_auth)]


async def metadata_auth(
    request: Request, auth: Annotated[AuthContext, Depends(short_auth)]
) -> AuthContext:
    if not {"sync", "search"}.intersection(auth.scopes):
        raise HTTPException(403, "API key requires sync or search scope")
    return budget(request, auth, search="sync" not in auth.scopes)


MetadataAuth = Annotated[AuthContext, Depends(metadata_auth)]


@router.get("")
async def list_groups(auth: MetadataAuth, db: DB) -> dict[str, Any]:
    return await groups.directory(db, auth)


@router.post("")
async def create_group(payload: CreateGroup, auth: Auth, db: DB) -> dict[str, Any]:
    return await groups.detail(db, auth, await groups.create(db, auth, payload))


@router.get("/{selector}")
async def show_group(
    selector: str,
    request: Request,
    auth: MetadataAuth,
    db: DB,
    with_activity: bool = Query(False, alias="activity"),
    include_retired: bool = False,
) -> dict[str, Any]:
    await groups.tenant_for(db, auth)
    result = await groups.detail(db, auth, await groups.resolve(db, auth, selector))
    if with_activity:
        if "sync" in auth.scopes:
            budget(request, auth, search=True)
        await db.commit()
        result["activity"] = await activity(
            selector,
            auth,
            scope="{}",
            cursor="",
            from_now=False,
            limit=200,
            include_retired=include_retired,
            snapshot=True,
        )
        if len(group_reads.encoded(result)) > group_reads.MAX_PAGE_BYTES:
            groups.fail("data_inconsistent", "Group snapshot exceeds the page bound")
    return result


@router.patch("/{selector}")
async def edit_group(selector: str, payload: EditGroup, auth: Auth, db: DB) -> dict[str, Any]:
    return await groups.detail(db, auth, await groups.edit(db, auth, selector, payload))


@router.post("/{selector}/join")
async def join_group(selector: str, payload: JoinGroup, auth: Auth, db: DB) -> dict[str, Any]:
    return await groups.detail(db, auth, await groups.join(db, auth, selector, payload))


@router.post("/{selector}/devices")
async def add_device(selector: str, payload: MemberEdit, auth: Auth, db: DB) -> dict[str, Any]:
    return await groups.detail(
        db, auth, await groups.change_member(db, auth, selector, payload, remove=False)
    )


@router.delete("/{selector}/devices")
async def remove_device(selector: str, payload: MemberEdit, auth: Auth, db: DB) -> dict[str, Any]:
    return await groups.detail(
        db, auth, await groups.change_member(db, auth, selector, payload, remove=True)
    )


@router.get("/{selector}/tokens")
async def list_tokens(
    selector: str, auth: Auth, db: DB, include_inactive: bool = False,
    limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0, le=100000),
) -> dict[str, Any]:
    return await groups.tokens(
        db, auth, selector, include_inactive=include_inactive, limit=limit, offset=offset,
    )


@router.post("/{selector}/tokens")
async def create_token(
    selector: str, payload: CreateToken, auth: Auth, db: DB, response: Response
) -> dict[str, Any]:
    response.headers["Cache-Control"] = "no-store"
    return await groups.issue_token(db, auth, selector, payload)


@router.patch("/{selector}/tokens/{token_id}")
async def acknowledge_token(
    selector: str, token_id: uuid.UUID, payload: AcknowledgeToken, auth: Auth, db: DB
) -> dict[str, Any]:
    return await groups.update_token(db, auth, selector, token_id, revoke=False)


@router.delete("/{selector}/tokens/{token_id}")
async def revoke_token(selector: str, token_id: uuid.UUID, auth: Auth, db: DB) -> dict[str, Any]:
    return await groups.update_token(db, auth, selector, token_id, revoke=True)


@router.post("/{selector}/search")
async def search(selector: str, payload: GroupQuery, auth: ReadAuth, db: DB) -> dict[str, Any]:
    if not payload.q.strip():
        groups.fail("invalid_query", "Use plain search terms, for example migration rollback", 400)
    tenant, group, schema = await group_reads.prepare(db, auth, selector, payload)
    return await group_reads.read(db, auth, tenant, group, schema, payload)


def parse_scope(scope: str) -> GroupQuery:
    try:
        return GroupQuery.model_validate_json(scope)
    except (ValidationError, ValueError):
        raise HTTPException(422, "Invalid version 1 group scope") from None


@router.get("/{selector}/entries/{entry_id}")
async def entry(
    selector: str, entry_id: str, auth: ReadAuth, db: DB, scope: str = Query("{}", max_length=16384)
) -> dict[str, Any]:
    payload = parse_scope(scope)
    tenant, group, schema = await group_reads.prepare(db, auth, selector, payload)
    return await group_reads.read(db, auth, tenant, group, schema, payload, anchor=entry_id)


@router.get("/{selector}/entries/{entry_id}/context")
async def context(
    selector: str, entry_id: str, auth: ReadAuth, db: DB, scope: str = Query("{}", max_length=16384)
) -> dict[str, Any]:
    payload = parse_scope(scope)
    tenant, group, schema = await group_reads.prepare(db, auth, selector, payload)
    return await group_reads.read(
        db, auth, tenant, group, schema, payload, anchor=entry_id, context=True
    )


@router.get("/{selector}/activity")
async def activity(
    selector: str,
    auth: ReadAuth,
    scope: str = Query("{}", max_length=16384),
    cursor: str = Query("", max_length=4096),
    from_now: bool = False,
    limit: int = Query(200, ge=1, le=200),
    include_retired: bool = False,
    snapshot: bool = False,
) -> dict[str, Any]:
    payload = parse_scope(scope)
    if snapshot and (cursor or from_now):
        groups.fail("invalid_input", "Activity snapshots cannot use a cursor or from_now", 400)
    try:
        async with asyncio.timeout(2), async_session_factory() as db:
            tenant, group, schema = await group_reads.prepare(db, auth, selector, payload)
            # Compatibility work completes before SHARE; no device locks exist.
            await db.commit()
            await db.execute(text("SET LOCAL statement_timeout = '1800ms'"))
            await db.execute(text("SET LOCAL lock_timeout = '50ms'"))
            await db.execute(text(f"LOCK TABLE {schema}.transcript_entries IN SHARE MODE NOWAIT"))
            result = await group_reads.read(
                db,
                auth,
                tenant,
                group,
                schema,
                payload,
                live=True,
                cursor=cursor,
                from_now=from_now,
                page_limit=limit,
                include_retired=include_retired,
                snapshot=snapshot,
            )
            await db.commit()
            return result
    except (DBAPIError, TimeoutError) as exc:
        if isinstance(exc, DBAPIError) and getattr(exc.orig, "sqlstate", None) not in {
            "55P03",
            "57014",
        }:
            raise
        raise HTTPException(
            503,
            "Sync writes are in progress. Retry with the same cursor.",
            headers={"Retry-After": "1"},
        ) from None
