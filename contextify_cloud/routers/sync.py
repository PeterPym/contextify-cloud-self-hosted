"""Sync endpoints - push data from local app/CLI to cloud."""

import hashlib
import json
import logging
import random
import re
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi import Request as HttpRequest
from pydantic import BaseModel, ValidationError
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from contextify_cloud.config import settings
from contextify_cloud.database import get_db
from contextify_cloud.middleware.auth import AuthContext, require_scope
from contextify_cloud.middleware.endpoint_rate_limit import require_sync_rate_limit
from contextify_cloud.models import Device, SyncIdempotency, SyncSession, Tenant, UsageEvent, User
from contextify_cloud.schemas import (
    ActivePushSessionStatus,
    DeviceInfo,
    PullEntry,
    PullProject,
    PullSummary,
    PullTranscript,
    SyncEntry,
    SyncItemError,
    SyncPullResponse,
    SyncPushRequest,
    SyncPushResponse,
    SyncStatusResponse,
)
from contextify_cloud.services.attribution import with_tenant_acquisition_properties
from contextify_cloud.services.audit import log_event
from contextify_cloud.services.funnel_events import emit_funnel_event, funnel_backend_registered
from contextify_cloud.services.operator_notifications import notify_first_activation
from contextify_cloud.services.plan_limits import (
    RETENTION_BATCH_SIZE,
    get_effective_history_retention_days,
    get_plan_limits,
    is_unlimited,
)
from contextify_cloud.services.repo_grouping import canonical_repo_group_key, normalize_repo_origin
from contextify_cloud.services.sync_status import (
    STALL_WINDOW,
    finalize_effectively_complete_sessions,
    session_is_bulk_catch_up,
    session_is_effectively_complete,
)
from contextify_cloud.services.tenant import (
    ensure_tenant_schema_compat,
    get_tenant_schema,
    tenant_is_internal,
)
from contextify_cloud.services.tenant_guard import check_tenant_active
from contextify_cloud.services.user_scoping import build_user_scope_clause
from contextify_cloud.sync_partial_accept import PartialAcceptSpec, validate_items

logger = logging.getLogger(__name__)

_SCHEMA_NAME_RE = re.compile(r"^tenant_[a-z0-9_]+$")

router = APIRouter(prefix="/api/v1/sync", tags=["sync"])


# ct-1841: Per-entry partial-accept constants & helpers.
#
# The push body cap (`max_request_body_bytes`, default 50 MB) sets the
# transport ceiling. The per-entry materialized ceiling sits well below that
# so JSON quoting overhead + sibling entries in the same batch still fit.
_MATERIALIZED_BYTE_CEILING = 32 * 1024 * 1024  # 32 MB per entry

# Stable client-facing error codes routed through SyncItemError.error_code.
# Adding a new code is forward-compatible: clients route on `retryable`, not
# on the code identity, and unknown codes fall through to a generic handler.
_PYDANTIC_TYPE_TO_CODE: dict[str, str] = {
    "string_too_long": "ENTRY_TOO_LARGE",
    "missing": "ENTRY_MISSING_FIELD",
    "value_error": "ENTRY_INVALID_FIELD",
    "string_type": "ENTRY_INVALID_FIELD",
    "int_type": "ENTRY_INVALID_FIELD",
    "bool_type": "ENTRY_INVALID_FIELD",
    "list_type": "ENTRY_INVALID_FIELD",
    "dict_type": "ENTRY_INVALID_FIELD",
    "string_pattern_mismatch": "ENTRY_INVALID_FIELD",
    "string_too_short": "ENTRY_INVALID_FIELD",
    "too_short": "ENTRY_INVALID_FIELD",
    "too_long": "ENTRY_TOO_LARGE",
}


def _classify_pydantic_error(pydantic_type: str) -> str:
    """Map a Pydantic error type string to a stable client-facing error code.

    Unknown types collapse to ENTRY_UNKNOWN_VALIDATION so previously unseen
    failures still quarantine cleanly without poisoning the batch. The raw
    `pydantic_type` rides along in the SyncItemError for triage so we can
    promote new mappings in follow-up changes.
    """
    return _PYDANTIC_TYPE_TO_CODE.get(pydantic_type, "ENTRY_UNKNOWN_VALIDATION")


def _extract_entry_id(raw: Any) -> str | None:
    """Return the `id` field of a raw entry dict, or None when missing."""
    if isinstance(raw, dict):
        candidate = raw.get("id")
        if isinstance(candidate, str) and candidate:
            return candidate
    return None


def _build_entry_partial_accept_spec(
    capture: Callable[..., None] | None,
) -> PartialAcceptSpec[SyncEntry]:
    """ct-1841 unit-6 extraction: package the per-entry partial-accept
    contract as a `PartialAcceptSpec` so the same mechanics can be
    applied to other item kinds (projects, transcripts, summaries, etc.)
    in follow-up phases. The Sentry capture is parameterized so tests
    can opt out of monitoring side effects."""
    return PartialAcceptSpec[SyncEntry](
        item_kind="entry",
        item_model=SyncEntry,
        classifier=_classify_pydantic_error,
        extract_item_id=_extract_entry_id,
        capture_validation_error=capture,
        array_key="entries",
    )


def _sanitize_pydantic_errors(errors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Strip the `input` field from Pydantic error dicts before exposing them.

    Pydantic embeds the offending raw value in `input`, which for sync entries
    can be transcript content. Returning it in 422 bodies or shipping it to
    Sentry leaks user content. Keep `type`, `loc`, `msg`, `ctx` (and other
    metadata) but drop `input`.
    """
    return [{k: v for k, v in err.items() if k != "input"} for err in errors]


def _summarize_loc(loc: list[str | int] | tuple[Any, ...]) -> str:
    return ".".join(str(part) for part in loc)


def _jsonable(item: Any) -> Any:
    """Return a JSON-serializable representation of a payload item.

    Used by `_compute_request_sha256` so the request-hash computation works
    uniformly across typed Pydantic models and raw dicts. `entries[]` arrives
    as raw dicts after ct-1841; the other arrays stay typed. A single helper
    keeps the canonical hash stable regardless of which array is which.
    """
    if isinstance(item, BaseModel):
        return item.model_dump(mode="json")
    return item


def _compute_request_sha256(request: SyncPushRequest) -> str:
    """Compute a stable SHA-256 hash of the request payload for idempotency checks.

    Uses a canonical JSON representation of the data-bearing fields (excludes
    idempotency_key itself and batch_seq from the hash).
    """
    canonical = {
        "device": request.device.model_dump(mode="json"),
        "projects": [_jsonable(p) for p in request.projects],
        "transcripts": [_jsonable(t) for t in request.transcripts],
        "entries": [_jsonable(e) for e in request.entries],
        "summaries": [_jsonable(s) for s in request.summaries],
        "usage": [_jsonable(u) for u in request.usage],
        "tool_invocations": [_jsonable(t) for t in request.tool_invocations],
        "transcript_metadata": [_jsonable(m) for m in request.transcript_metadata],
    }
    serialized = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode()).hexdigest()


def _verify_entry_size_and_sha(
    entry: SyncEntry,
    index: int,
) -> SyncItemError | None:
    """Post-Pydantic, entry-specific checks: byte caps + sha verify.

    Sits outside the generic `validate_items` helper because the per-chunk
    transport cap (`1 MB` inline), per-entry materialized ceiling (32 MB),
    and `content_sha256` invariant are all sync-domain semantics, not
    framework boilerplate. Returns None on success or a `SyncItemError`
    to route into `item_errors`.

    Order matters: inline >1MB surfaces as a distinct ENTRY_TOO_LARGE
    pointing at `content`, so the client can recognise the suggested fix
    is to chunk; bigger materialized overflows point at the entry
    boundary; sha mismatch is data-integrity rather than size.
    """
    # Inline byte cap (transport rule: inline must be <= 1 MB; clients
    # exceeding this are expected to use content_chunks). The Pydantic
    # validator allows arbitrary inline content; we recheck here so the
    # failure carries the ENTRY_TOO_LARGE code instead of the generic
    # ENTRY_INVALID_FIELD a Pydantic value_error would yield.
    if entry.content is not None:
        inline_bytes = len(entry.content.encode("utf-8"))
        if inline_bytes > 1_000_000:
            return SyncItemError(
                item_kind="entry",
                index=index,
                item_id=entry.id,
                error_code="ENTRY_TOO_LARGE",
                retryable=False,
                detail=(
                    f"inline `content` is {inline_bytes} bytes; clients must use "
                    "`content_chunks` for entries over 1,000,000 UTF-8 bytes"
                ),
                pydantic_type="string_too_long",
                loc=["body", "entries", index, "content"],
            )

    materialized = entry.materialized_content()
    materialized_bytes = materialized.encode("utf-8")
    if len(materialized_bytes) > _MATERIALIZED_BYTE_CEILING:
        return SyncItemError(
            item_kind="entry",
            index=index,
            item_id=entry.id,
            error_code="ENTRY_TOO_LARGE",
            retryable=False,
            detail=(
                f"materialized content {len(materialized_bytes)} bytes exceeds "
                f"ceiling {_MATERIALIZED_BYTE_CEILING}"
            ),
            pydantic_type=None,
            loc=["body", "entries", index, "content"],
        )

    computed_sha = hashlib.sha256(materialized_bytes).hexdigest()
    if computed_sha != entry.content_sha256:
        return SyncItemError(
            item_kind="entry",
            index=index,
            item_id=entry.id,
            error_code="ENTRY_SHA_MISMATCH",
            retryable=False,
            detail="content_sha256 does not match materialized content",
            pydantic_type=None,
            loc=["body", "entries", index, "content_sha256"],
        )

    return None


async def _rollback_savepoint(db: AsyncSession, sp: str) -> None:
    """Rollback and release a savepoint, logging any cleanup failures."""
    try:
        await db.execute(text(f"ROLLBACK TO SAVEPOINT {sp}"))
    except Exception as e:
        logger.debug("Savepoint rollback failed for %s: %s", sp, e)
    try:
        await db.execute(text(f"RELEASE SAVEPOINT {sp}"))
    except Exception as e:
        logger.debug("Savepoint release failed for %s: %s", sp, e)


def _entry_insert_params(
    entry: SyncEntry,
    *,
    suffix: str,
    auth: AuthContext,
    device: Device | None,
) -> dict[str, object]:
    return {
        f"id{suffix}": entry.id,
        f"transcript_id{suffix}": entry.transcript_id,
        f"project_id{suffix}": entry.project_id,
        f"session_id{suffix}": entry.session_id,
        f"provider{suffix}": entry.provider,
        f"kind{suffix}": entry.kind,
        f"timestamp{suffix}": entry.timestamp,
        # ct-1841: chunked entries arrive with `content` unset and content split
        # into `content_chunks`. Materialize back to a single string here so the
        # INSERT sees one logical row regardless of the transport shape.
        f"content{suffix}": entry.materialized_content(),
        f"content_sha256{suffix}": entry.content_sha256,
        f"display_in_timeline{suffix}": entry.display_in_timeline,
        f"git_branch{suffix}": entry.git_branch,
        f"git_commit{suffix}": entry.git_commit,
        f"cwd{suffix}": entry.cwd,
        f"user_id{suffix}": str(auth.user_id),
        # Prefer per-entry source provenance (originating device) over
        # request-level device info (uploading device). They differ when a DB is
        # copied/restored before sync.
        f"device_id{suffix}": entry.source_device_id or (device.machine_id if device else None),
        f"device_name{suffix}": entry.source_device_name
        or (device.machine_name if device else None),
        f"created_at{suffix}": entry.created_at,
        f"updated_at{suffix}": entry.updated_at,
    }


def _entry_values_sql(suffix: str) -> str:
    return (
        f"(:id{suffix}, :transcript_id{suffix}, :project_id{suffix},"
        f" :session_id{suffix}, :provider{suffix}, :kind{suffix},"
        f" :timestamp{suffix}, :content{suffix}, :content_sha256{suffix},"
        f" :display_in_timeline{suffix},"
        f" :git_branch{suffix}, :git_commit{suffix}, :cwd{suffix},"
        f" :user_id{suffix}, :device_id{suffix}, :device_name{suffix},"
        f" :created_at{suffix}, :updated_at{suffix})"
    )


def _insert_entries_sql(schema: str, values_sql: str) -> str:
    return f"""
        INSERT INTO {schema}.transcript_entries
            (id, transcript_id, project_id, session_id, provider, kind,
             timestamp, content, content_sha256, display_in_timeline,
             git_branch, git_commit, cwd, uploaded_by_user_id,
             uploaded_by_device_id, uploaded_by_device_name,
             created_at, updated_at)
        VALUES {values_sql}
        ON CONFLICT (id) DO NOTHING
    """


@router.post("/push", response_model=SyncPushResponse)
async def sync_push(
    http_request: HttpRequest,
    request: SyncPushRequest,
    auth: Annotated[AuthContext, Depends(require_sync_rate_limit)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> SyncPushResponse:
    """Push entries from local database to cloud.

    Requires sync scope and owner/admin/member role. Viewers cannot push data.

    Deduplicates by entry ID for entries, by primary key for other tables.
    Supports idempotency via client-provided idempotency_key. When an
    idempotency_key is provided:
    - If the key was already used with the same payload: returns cached response.
    - If the key was already used with a different payload: returns 409.
    - If the key is new: processes the request and caches the response.

    Partial failure semantics: individual item failures are collected in the
    errors list but do not abort the entire batch. The client receives counts
    of accepted items and errors, and can retry failed items.
    """
    # Inline role check (previously via require_role dependency)
    if auth.role not in {"owner", "admin", "member"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient role. Required: owner, admin, or member.",
        )

    # --- Idempotency check (before any processing) ---
    # Uses INSERT ... ON CONFLICT to avoid SELECT-then-INSERT race where two
    # concurrent requests both see "no row" and then both try to INSERT,
    # causing a uniqueness violation (500). The ON CONFLICT DO NOTHING makes
    # the insert a no-op if a row already exists, then we SELECT to check.
    request_sha = _compute_request_sha256(request)
    if request.idempotency_key:
        # Opportunistic cleanup: purge incomplete idempotency records older
        # than 1 minute. These are leftovers from requests that failed
        # (413, 500, etc.) before marking complete, blocking retries.
        try:
            async with db.begin_nested():
                await db.execute(
                    text(
                        "DELETE FROM public.sync_idempotency "
                        "WHERE is_complete = false "
                        "AND created_at < NOW() - INTERVAL '1 minute'"
                    )
                )
        except Exception:
            pass  # Best-effort cleanup
        # Try advisory lock for fail-fast on exact concurrent duplicates.
        # Uses a hash of (tenant_id, key_id, idempotency_key) as lock key.
        lock_input = f"{auth.tenant_id}:{auth.key_id}:{request.idempotency_key}"
        lock_key = int(hashlib.sha256(lock_input.encode()).hexdigest()[:15], 16)
        lock_result = await db.execute(
            text("SELECT pg_try_advisory_xact_lock(:key)"),
            {"key": lock_key},
        )
        got_lock = lock_result.scalar()
        if not got_lock:
            raise HTTPException(
                status_code=409,
                detail=(
                    "Request with this idempotency key is currently "
                    "being processed by another request. Retry later."
                ),
            )

        # Atomically insert-if-not-exists via ON CONFLICT DO NOTHING
        stmt = (
            pg_insert(SyncIdempotency)
            .values(
                tenant_id=auth.tenant_id,
                key_id=auth.key_id,
                idempotency_key=request.idempotency_key,
                request_sha256=request_sha,
                expires_at=datetime.now(UTC) + timedelta(hours=settings.idempotency_ttl_hours),
            )
            .on_conflict_do_nothing(
                constraint="uq_idempotency_key",
            )
        )
        result = await db.execute(stmt)
        await db.flush()

        # If rowcount == 0, the row already existed. Check it.
        if result.rowcount == 0:  # type: ignore[attr-defined]
            existing = await db.execute(
                select(SyncIdempotency).where(
                    SyncIdempotency.tenant_id == auth.tenant_id,
                    SyncIdempotency.key_id == auth.key_id,
                    SyncIdempotency.idempotency_key == request.idempotency_key,
                )
            )
            existing_row = existing.scalar_one_or_none()

            if existing_row:
                if existing_row.request_sha256 != request_sha:
                    raise HTTPException(
                        status_code=409,
                        detail=(
                            "Idempotency key already used with a different request payload. "
                            "Use a new idempotency_key for different requests."
                        ),
                    )
                if existing_row.is_complete and existing_row.response_json:
                    logger.info(
                        "Idempotent replay: tenant=%s key_id=%s idem_key=%s",
                        auth.tenant_id,
                        auth.key_id,
                        request.idempotency_key,
                    )
                    return SyncPushResponse.model_validate_json(existing_row.response_json)
                if not existing_row.is_complete:
                    raise HTTPException(
                        status_code=409,
                        detail=(
                            "Request with this idempotency key is still "
                            "being processed. Retry later."
                        ),
                    )

    # --- Billing state enforcement ---
    # Block sync for tenants with unpaid, canceled, or archived subscriptions.
    billing_tenant = await db.execute(select(Tenant).where(Tenant.id == auth.tenant_id))
    billing_tenant_obj = billing_tenant.scalar_one_or_none()
    if billing_tenant_obj and not is_unlimited():
        blocked_statuses = {"unpaid", "canceled", "archived"}
        tenant_sub_status = getattr(billing_tenant_obj, "subscription_status", "active")
        if tenant_sub_status in blocked_statuses:
            raise HTTPException(
                status_code=403,
                detail=(
                    f"Sync disabled: subscription is {tenant_sub_status}. "
                    "Please update your billing at hosted billing"
                ),
            )

    # --- Tenant deletion state enforcement ---
    # Block sync for tenants scheduled for deletion or being purged.
    await check_tenant_active(db, auth.tenant_id)

    # Validate batch size limits
    total_items = (
        len(request.entries)
        + len(request.projects)
        + len(request.transcripts)
        + len(request.summaries)
        + len(request.usage)
        + len(request.tool_invocations)
        + len(request.transcript_metadata)
    )
    if total_items > settings.max_batch_size:
        raise HTTPException(
            status_code=413,
            detail=(
                f"Batch too large: {total_items} items exceeds limit of {settings.max_batch_size}."
            ),
        )
    if request.entries_sent is not None and request.entries_sent != len(request.entries):
        # ct-1841 follow-up (unit-7 audit): this is a sync-invariant
        # violation, not user input - a client should never emit it
        # under normal operation. Surface to Sentry explicitly so
        # operators can correlate client bugs across releases.
        from contextify_cloud import monitoring as _monitoring

        _monitoring.capture_handled_operational_response(
            request=http_request,
            status_code=422,
            error_kind="entries_sent_mismatch",
            extra_tags={
                "declared": str(request.entries_sent),
                "actual": str(len(request.entries)),
            },
        )
        raise HTTPException(
            status_code=422,
            detail=(
                f"entries_sent mismatch: declared={request.entries_sent}, "
                f"actual={len(request.entries)}"
            ),
        )
    entries_sent_total = (
        request.entries_sent if request.entries_sent is not None else len(request.entries)
    )

    # ct-1841: per-entry validation MUST run before any downstream code touches
    # entries (project allow-list, project_id remap, transcript remap, FK
    # lookups). Downstream code reads typed attributes (entry.project_id,
    # entry.id, entry.content_sha256); raw dicts would 500.
    #
    # The generic mechanics (try/except, SyncItemError construction,
    # Sentry capture) live in `sync_partial_accept.validate_items`. The
    # entry-specific size/sha checks live in `_verify_entry_size_and_sha`
    # because those are sync-domain semantics, not framework boilerplate.
    #
    # Downstream code uses a local `entries: list[SyncEntry]` from here on;
    # we don't mutate request.entries (which keeps its `list[dict[str, Any]]`
    # type) so mypy can statically verify the rest of the handler.
    from contextify_cloud import monitoring as _monitoring  # local import; avoids cycles

    raw_entries: list[Any] = list(request.entries)
    spec = _build_entry_partial_accept_spec(capture=_monitoring.capture_sync_item_validation)
    helper_result = validate_items(
        raw_items=raw_entries,
        spec=spec,
        request=http_request,
    )
    item_errors: list[SyncItemError] = list(helper_result.item_errors)
    entries_permanent_failed = helper_result.permanent_failed

    # Entry-specific post-validation: byte caps + sha verify. The helper
    # already populated item_errors for Pydantic-level failures; this
    # second pass handles size/sha rejections, which can't be expressed
    # in Pydantic without sacrificing the ENTRY_TOO_LARGE vs
    # ENTRY_INVALID_FIELD distinction.
    entries: list[SyncEntry] = []
    for entry in helper_result.valid_items:
        original_index = helper_result.raw_index_by_item_id.get(entry.id)
        if original_index is None:
            # `id` may have been duplicated; recover by linear search.
            original_index = next(
                (
                    i
                    for i, r in enumerate(raw_entries)
                    if isinstance(r, dict) and r.get("id") == entry.id
                ),
                0,
            )
        post_err = _verify_entry_size_and_sha(entry, original_index)
        if post_err is not None:
            item_errors.append(post_err)
            entries_permanent_failed += 1
            _monitoring.capture_sync_item_validation(
                request=http_request,
                item_kind="entry",
                item_id=post_err.item_id,
                loc=_summarize_loc(post_err.loc),
                pydantic_type=post_err.pydantic_type or "",
                error_code=post_err.error_code,
            )
            continue
        entries.append(entry)

    # Resolve tenant schema
    tenant = await db.execute(select(Tenant).where(Tenant.id == auth.tenant_id))
    tenant_obj = tenant.scalar_one_or_none()
    if not tenant_obj:
        raise HTTPException(status_code=404, detail="Tenant not found.")

    plan_limits = get_plan_limits(tenant_obj)
    schema = get_tenant_schema(tenant_obj.slug)
    await ensure_tenant_schema_compat(db, schema)
    if not _SCHEMA_NAME_RE.match(schema):
        logger.error("Unsafe tenant schema name: %r", schema)
        raise HTTPException(status_code=500, detail="Internal configuration error.")
    accepted = 0
    duplicates = 0
    errors: list[str] = []
    error_codes: set[str] = set()
    entries_accepted = 0
    entries_duplicates = 0
    entries_conflicted = 0
    entries_retriable_failed = 0
    entries_blocked_policy = 0

    # Register/update device
    device_result = await db.execute(
        select(Device).where(
            Device.user_id == auth.user_id,
            Device.machine_id == request.device.machine_id,
        )
    )
    device = device_result.scalar_one_or_none()
    # ct-2106: track whether THIS device's last_sync_at was NULL before this
    # request (a NULL->non-NULL first-sync transition). The UPDATEs below are raw
    # SQL and do NOT mutate the loaded ORM object, so device.last_sync_at still
    # holds the PRE-update value; capture the boolean BEFORE issuing each UPDATE.
    device_was_first_sync = False
    if device:
        device_was_first_sync = device.last_sync_at is None
        await db.execute(
            update(Device)
            .where(Device.id == device.id)
            .values(
                machine_name=request.device.machine_name,
                os=request.device.os,
                app_version=request.device.app_version,
                last_sync_at=datetime.now(UTC),
            )
        )
    else:
        device_limit = plan_limits.max_devices_per_user
        if device_limit is not None:
            # Lock the user row to serialize concurrent new-device registrations
            await db.execute(
                select(User.id)
                .where(
                    User.id == auth.user_id,
                    User.tenant_id == auth.tenant_id,
                )
                .with_for_update()
            )
            # Re-check after lock: another request may have created the device
            device_recheck = await db.execute(
                select(Device).where(
                    Device.user_id == auth.user_id,
                    Device.machine_id == request.device.machine_id,
                )
            )
            device = device_recheck.scalar_one_or_none()
        if device is None and device_limit is not None:
            device_count_result = await db.execute(
                select(func.count(Device.id)).where(Device.user_id == auth.user_id)
            )
            device_count = device_count_result.scalar() or 0
            if device_count >= device_limit:
                raise HTTPException(
                    status_code=403,
                    detail=(
                        f"Device limit reached ({device_limit}/{device_limit}) for the "
                        f"{tenant_obj.plan} plan. Remove an old device or upgrade at "
                        "hosted billing."
                    ),
                )
        if device is not None:
            # Device was created by a concurrent request after our initial check
            # ct-2106: capture the pre-update first-sync transition here too.
            device_was_first_sync = device.last_sync_at is None
            await db.execute(
                update(Device)
                .where(Device.id == device.id)
                .values(
                    machine_name=request.device.machine_name,
                    os=request.device.os,
                    app_version=request.device.app_version,
                    last_sync_at=datetime.now(UTC),
                )
            )
        else:
            # ct-2106: a brand-new device's first sync is always a first-sync.
            device_was_first_sync = True
            device = Device(
                user_id=auth.user_id,
                machine_name=request.device.machine_name,
                machine_id=request.device.machine_id,
                os=request.device.os,
                app_version=request.device.app_version,
                last_sync_at=datetime.now(UTC),
            )
            db.add(device)
            await db.flush()

    # ── Sync session tracking (validate existing session) ────────────
    # If the client provided a sync_session_id, validate it belongs to this
    # tenant + user. If not provided, we'll create a new session later.
    sync_session_id: str | None = None
    sync_session_tracking_enabled = True
    sync_session_obj: SyncSession | None = None
    requested_session_uuid: uuid.UUID | None = None
    if request.sync_session_id:
        try:
            requested_session_uuid = uuid.UUID(request.sync_session_id)
        except ValueError:
            raise HTTPException(
                status_code=404,
                detail="Sync session not found.",
            )
        try:
            async with db.begin_nested():
                existing_session = await db.execute(
                    select(SyncSession).where(
                        SyncSession.id == requested_session_uuid,
                    )
                )
                sync_session_obj = existing_session.scalar_one_or_none()
                if not sync_session_obj:
                    if request.batch_seq != 1:
                        raise HTTPException(
                            status_code=404,
                            detail="Sync session not found.",
                        )
                    # Client-provided session IDs are allowed for first-batch
                    # bootstrap. If no matching row exists, we create it later
                    # after batch processing succeeds.
                    sync_session_id = str(requested_session_uuid)
                elif (
                    sync_session_obj.tenant_id != auth.tenant_id
                    or sync_session_obj.user_id != auth.user_id
                ):
                    raise HTTPException(
                        status_code=404,
                        detail="Sync session not found.",
                    )
                elif (
                    request.total_batches is not None
                    and sync_session_obj.total_batches is not None
                    and request.total_batches != sync_session_obj.total_batches
                ):
                    raise HTTPException(
                        status_code=409,
                        detail=(
                            "Sync session total_batches does not match the existing "
                            "session. Resume with the original total_batches value."
                        ),
                    )
                elif sync_session_obj.status != "in_progress":
                    raise HTTPException(
                        status_code=409,
                        detail=f"Sync session is {sync_session_obj.status}, cannot resume.",
                    )
                else:
                    sync_session_id = str(sync_session_obj.id)
        except HTTPException:
            raise
        except Exception:
            # Rolling deploy safety: SAVEPOINT ensures a DB error (e.g.
            # UndefinedTable during migration rollout) does not poison the
            # outer transaction, so the main sync path can proceed.
            logger.warning(
                "Sync session validation unavailable; continuing without session tracking",
                exc_info=True,
            )
            sync_session_tracking_enabled = False

    # ── Project allow-list enforcement ──────────────────────────────
    # If the tenant has a project allow-list, filter out projects (and their
    # associated entries/transcripts/summaries) that are not in the list.
    # Also block payload objects referencing project IDs not in request.projects
    # (prevents orphaned rows under allow-list policy).
    blocked_projects: list[str] = []
    blocked_project_ids: set[str] = set()
    original_entry_count = len(entries)
    allowlist = tenant_obj.project_allowlist
    if allowlist is not None:
        allowed_set = set(allowlist)
        original_projects = request.projects
        provided_project_ids = {p.id for p in original_projects}

        def _proj_name(p: Any) -> str:
            return (p.name or "").strip()

        allowed_project_ids = {p.id for p in original_projects if _proj_name(p) in allowed_set}

        # Filter projects (by name, handle None names safely)
        blocked_projects = [
            (_proj_name(p) or "<unnamed>")
            for p in original_projects
            if _proj_name(p) not in allowed_set
        ]
        request.projects = [p for p in original_projects if _proj_name(p) in allowed_set]

        # Check referenced-but-not-provided project IDs against the DB.
        # Incremental sync batches may reference existing projects without
        # re-sending the project definition. We query the DB to determine
        # whether those projects exist and are allow-listed, rather than
        # blindly blocking them.
        referenced_project_ids = (
            {t.project_id for t in request.transcripts}
            | {e.project_id for e in entries}
            | {m.project_id for m in request.transcript_metadata}
        )
        missing_from_batch = referenced_project_ids - provided_project_ids
        unknown_project_ids: set[str] = set()
        if missing_from_batch:
            # Look up existing projects by ID to get their names
            placeholders = ", ".join(f":pid_{i}" for i in range(len(missing_from_batch)))
            pid_params = {f"pid_{i}": pid for i, pid in enumerate(missing_from_batch)}
            existing_result = await db.execute(
                text(f"SELECT id, name FROM {schema}.projects WHERE id IN ({placeholders})"),
                pid_params,
            )
            existing_db_projects = {
                row.id: (row.name or "").strip() for row in existing_result.fetchall()
            }
            for pid in missing_from_batch:
                name = existing_db_projects.get(pid)
                if name is not None and name in allowed_set:
                    # Existing project with an allowed name - treat as allowed
                    allowed_project_ids.add(pid)
                elif name is not None:
                    # Existing project but not in allow-list
                    blocked_projects.append(name or "<unnamed>")
                else:
                    # Project doesn't exist in DB at all
                    unknown_project_ids.add(pid)
        blocked_project_ids = (provided_project_ids - allowed_project_ids) | (
            missing_from_batch - allowed_project_ids
        )

        # Filter payload components by *allowed* project IDs.
        request.transcripts = [
            t for t in request.transcripts if t.project_id in allowed_project_ids
        ]
        entries = [e for e in entries if e.project_id in allowed_project_ids]
        entries_blocked_policy = max(0, original_entry_count - len(entries))
        if entries_blocked_policy > 0:
            error_codes.add("ENTRY_POLICY_BLOCKED")

        allowed_entry_ids = {e.id for e in entries}
        allowed_transcript_ids = {t.id for t in request.transcripts}
        request.usage = [u for u in request.usage if u.entry_id in allowed_entry_ids]
        request.summaries = [s for s in request.summaries if s.entry_id in allowed_entry_ids]
        request.tool_invocations = [
            inv
            for inv in request.tool_invocations
            if (inv.entry_id in allowed_entry_ids) or (inv.transcript_id in allowed_transcript_ids)
        ]
        request.transcript_metadata = [
            m for m in request.transcript_metadata if m.project_id in allowed_project_ids
        ]

        if blocked_projects or unknown_project_ids:
            shown = blocked_projects[:25]
            extra = ""
            if len(blocked_projects) > 25:
                extra = f" (+{len(blocked_projects) - 25} more)"
            logger.info(
                "Project allow-list: blocked=%d unknown_ids=%d tenant=%s blocked_names=%s%s",
                len(blocked_projects),
                len(unknown_project_ids),
                auth.tenant_id,
                shown,
                extra,
            )

    # Upsert projects (with repo_group_key deduplication)
    # When a client pushes a project ID that doesn't exist on the server but
    # its repo_group_key matches an existing project, the incoming ID is an
    # alias for the same logical repo (e.g. different devices generating
    # different UUIDs for the same git repo). We remap the alias to the
    # canonical (first-seen) project ID and rewrite transcript/entry
    # references in this batch accordingly.
    now_epoch = int(datetime.now(UTC).timestamp())
    project_id_remap: dict[str, str] = {}
    for i, proj in enumerate(request.projects):
        sp = f"sp_proj_{i}"
        try:
            normalized_repo_origin = normalize_repo_origin(proj.repo_origin_normalized)
            effective_repo_group_key = canonical_repo_group_key(
                proj.repo_group_key,
                proj.repo_identity,
                normalized_repo_origin,
            )
            await db.execute(text(f"SAVEPOINT {sp}"))

            # Check if this exact project ID already exists
            existing_by_id = await db.execute(
                text(f"SELECT id FROM {schema}.projects WHERE id = :id"),
                {"id": proj.id},
            )
            if existing_by_id.scalar_one_or_none() is not None:
                # Project exists by ID, do a normal update
                await db.execute(
                    text(f"""
                    UPDATE {schema}.projects SET
                        name = :name,
                        root_path = :root_path,
                        repo_group_key = COALESCE(:repo_group_key, repo_group_key),
                        repo_identity = COALESCE(:repo_identity, repo_identity),
                        repo_origin_normalized = COALESCE(
                            :repo_origin_normalized, repo_origin_normalized
                        ),
                        git_common_dir = COALESCE(:git_common_dir, git_common_dir),
                        is_worktree = CASE
                            WHEN :repo_identity IS NOT NULL THEN :is_worktree
                            ELSE is_worktree
                        END,
                        default_branch = COALESCE(:default_branch, default_branch),
                        vcs_provider = COALESCE(:vcs_provider, vcs_provider),
                        worktree_name = COALESCE(:worktree_name, worktree_name),
                        repo_name = COALESCE(:repo_name, repo_name),
                        updated_at = :updated_at
                    WHERE id = :id
                """),
                    {
                        "id": proj.id,
                        "name": proj.name,
                        "root_path": proj.root_path,
                        "repo_group_key": effective_repo_group_key,
                        "repo_identity": proj.repo_identity,
                        "repo_origin_normalized": normalized_repo_origin,
                        "git_common_dir": proj.git_common_dir,
                        "is_worktree": proj.is_worktree,
                        "default_branch": proj.default_branch,
                        "vcs_provider": proj.vcs_provider,
                        "worktree_name": proj.worktree_name,
                        "repo_name": proj.repo_name,
                        "updated_at": now_epoch,
                    },
                )
                await db.execute(text(f"RELEASE SAVEPOINT {sp}"))
                accepted += 1
                continue

            # Project ID is new. Check for repo_group_key match (same logical
            # repo pushed by a different device with a different local UUID).
            if effective_repo_group_key:
                canonical_result = await db.execute(
                    text(
                        f"SELECT id FROM {schema}.projects "
                        f"WHERE repo_group_key = :rgk AND id != :id "
                        f"ORDER BY created_at ASC LIMIT 1"
                    ),
                    {"rgk": effective_repo_group_key, "id": proj.id},
                )
                canonical_id = canonical_result.scalar_one_or_none()
                if canonical_id is not None:
                    # Remap: this project ID is an alias for the canonical one
                    project_id_remap[proj.id] = canonical_id
                    logger.info(
                        "Project identity merge: %s -> %s (repo_group_key=%s)",
                        proj.id,
                        canonical_id,
                        effective_repo_group_key,
                    )
                    # Update the canonical project's metadata
                    await db.execute(
                        text(f"""
                        UPDATE {schema}.projects SET
                            name = COALESCE(:name, name),
                            repo_identity = COALESCE(:repo_identity, repo_identity),
                            repo_origin_normalized = COALESCE(
                                :repo_origin_normalized, repo_origin_normalized
                            ),
                            git_common_dir = COALESCE(:git_common_dir, git_common_dir),
                            is_worktree = CASE
                                WHEN :repo_identity IS NOT NULL THEN :is_worktree
                                ELSE is_worktree
                            END,
                            default_branch = COALESCE(:default_branch, default_branch),
                            vcs_provider = COALESCE(:vcs_provider, vcs_provider),
                            worktree_name = COALESCE(:worktree_name, worktree_name),
                            repo_name = COALESCE(:repo_name, repo_name),
                            updated_at = :updated_at
                        WHERE id = :canonical_id
                    """),
                        {
                            "canonical_id": canonical_id,
                            "name": proj.name,
                            "repo_identity": proj.repo_identity,
                            "repo_origin_normalized": normalized_repo_origin,
                            "git_common_dir": proj.git_common_dir,
                            "is_worktree": proj.is_worktree,
                            "default_branch": proj.default_branch,
                            "vcs_provider": proj.vcs_provider,
                            "worktree_name": proj.worktree_name,
                            "repo_name": proj.repo_name,
                            "updated_at": now_epoch,
                        },
                    )
                    await db.execute(text(f"RELEASE SAVEPOINT {sp}"))
                    accepted += 1
                    continue

            # Genuinely new project, insert it
            await db.execute(
                text(f"""
                INSERT INTO {schema}.projects
                    (
                        id, name, root_path, repo_group_key, repo_identity,
                        repo_origin_normalized, git_common_dir, is_worktree,
                        default_branch, vcs_provider, worktree_name, repo_name,
                        created_by_user_id, created_at, updated_at
                    )
                VALUES (
                    :id, :name, :root_path, :repo_group_key,
                    :repo_identity, :repo_origin_normalized,
                    :git_common_dir, :is_worktree, :default_branch, :vcs_provider,
                    :worktree_name, :repo_name, :user_id, :created_at, :updated_at
                )
            """),
                {
                    "id": proj.id,
                    "name": proj.name,
                    "root_path": proj.root_path,
                    "repo_group_key": effective_repo_group_key,
                    "repo_identity": proj.repo_identity,
                    "repo_origin_normalized": normalized_repo_origin,
                    "git_common_dir": proj.git_common_dir,
                    "is_worktree": proj.is_worktree,
                    "default_branch": proj.default_branch,
                    "vcs_provider": proj.vcs_provider,
                    "worktree_name": proj.worktree_name,
                    "repo_name": proj.repo_name,
                    "user_id": str(auth.user_id),
                    "created_at": now_epoch,
                    "updated_at": now_epoch,
                },
            )
            await db.execute(text(f"RELEASE SAVEPOINT {sp}"))
            accepted += 1
        except Exception as e:
            await _rollback_savepoint(db, sp)
            errors.append(f"Project {proj.id}: {e}")

    # Apply project_id_remap to transcripts and entries before upserting
    if project_id_remap:
        for tx in request.transcripts:
            if tx.project_id in project_id_remap:
                tx.project_id = project_id_remap[tx.project_id]
        for entry in entries:
            if entry.project_id in project_id_remap:
                entry.project_id = project_id_remap[entry.project_id]
        for meta in request.transcript_metadata:
            if meta.project_id in project_id_remap:
                meta.project_id = project_id_remap[meta.project_id]

    transcript_id_remap: dict[str, str] = {}

    # Upsert transcripts
    for i, tx in enumerate(request.transcripts):
        sp = f"sp_tx_{i}"
        try:
            await db.execute(text(f"SAVEPOINT {sp}"))
            tx_params = {
                "id": tx.id,
                "project_id": tx.project_id,
                "file_path": tx.file_path,
                "provider": tx.provider,
                "provider_session_id": tx.provider_session_id,
                "user_id": str(auth.user_id),
                "device_id": str(device.id) if device else None,
                "line_count": tx.line_count,
                "created_at": tx.created_at,
                "updated_at": tx.updated_at,
            }
            existing_by_id = await db.execute(
                text(f"""
                SELECT id FROM {schema}.transcripts
                WHERE id = :id
            """),
                tx_params,
            )
            canonical_transcript_id = existing_by_id.scalar_one_or_none()

            if canonical_transcript_id is None:
                existing_by_path = await db.execute(
                    text(f"""
                    SELECT id FROM {schema}.transcripts
                    WHERE project_id = :project_id
                      AND file_path = :file_path
                      AND uploaded_by_user_id = :user_id
                """),
                    tx_params,
                )
                canonical_transcript_id = existing_by_path.scalar_one_or_none()

            if canonical_transcript_id is not None:
                if canonical_transcript_id != tx.id:
                    transcript_id_remap[tx.id] = canonical_transcript_id
                await db.execute(
                    text(f"""
                    UPDATE {schema}.transcripts
                    SET provider = :provider,
                        provider_session_id = :provider_session_id,
                        device_id = :device_id,
                        line_count = :line_count,
                        updated_at = :updated_at
                    WHERE id = :canonical_id
                """),
                    {**tx_params, "canonical_id": canonical_transcript_id},
                )
            else:
                await db.execute(
                    text(f"""
                    INSERT INTO {schema}.transcripts
                        (id, project_id, file_path, provider, provider_session_id,
                         uploaded_by_user_id, device_id, line_count, created_at, updated_at)
                    VALUES (:id, :project_id, :file_path, :provider, :provider_session_id,
                            :user_id, :device_id, :line_count, :created_at, :updated_at)
                """),
                    tx_params,
                )
            await db.execute(text(f"RELEASE SAVEPOINT {sp}"))
            accepted += 1
        except Exception as e:
            await _rollback_savepoint(db, sp)
            errors.append(f"Transcript {tx.id}: {e}")

    if transcript_id_remap:
        for entry in entries:
            if entry.transcript_id in transcript_id_remap:
                entry.transcript_id = transcript_id_remap[entry.transcript_id]
        for inv in request.tool_invocations:
            if inv.transcript_id in transcript_id_remap:
                inv.transcript_id = transcript_id_remap[inv.transcript_id]
        for meta in request.transcript_metadata:
            if meta.transcript_id in transcript_id_remap:
                meta.transcript_id = transcript_id_remap[meta.transcript_id]

    # ct-2028 (CL-S01): capture the entry high-water mark BEFORE inserting this
    # request's entries. server_sequence is assigned monotonically by a
    # server-side sequence on INSERT, so it is the only reliable server-arrival
    # marker (created_at/timestamp are client-supplied and can predate the
    # retention window for restores/backfills). Rows inserted in THIS request
    # get server_sequence > pre_push_max_seq; the on-push retention cleanup
    # below excludes them so just-pushed older-than-window history is never
    # deleted in the same request it was accepted.
    pre_push_max_seq = 0
    # ct-2076: only trust a 0 watermark for first-activation detection when the
    # read actually succeeded; the fail-safe below also yields 0.
    pre_push_watermark_known = False
    try:
        # ct-2028 (review iter-01): run the watermark read inside a SAVEPOINT so a
        # statement failure rolls back only the nested transaction. On PostgreSQL
        # a failed statement aborts the WHOLE transaction (InFailedSQLTransaction)
        # and poisons the session; without the savepoint the subsequent entry
        # inserts / retention / audit logging / idempotency update would all fail.
        async with db.begin_nested():
            pre_push_seq_result = await db.execute(
                text(f"SELECT COALESCE(MAX(server_sequence), 0) FROM {schema}.transcript_entries")
            )
            pre_push_max_seq = pre_push_seq_result.scalar() or 0
        pre_push_watermark_known = True
    except Exception:
        # If we cannot read the high-water mark, fail safe: a 0 watermark means
        # the retention DELETE below matches no rows (server_sequence is NOT
        # NULL and always >= 1), so we never delete rather than risk deleting
        # just-pushed history. The savepoint above keeps the outer transaction
        # usable so the rest of the push still completes.
        logger.warning(
            "Pre-push retention watermark unavailable; skipping retention eligibility",
            exc_info=True,
        )
        pre_push_max_seq = 0

    # Upsert entries (deduplicate by ID only) -- bulk two-phase approach
    # Phase 1: Batch duplicate/conflict check
    if entries:
        entry_ids = [e.id for e in entries]
        # Build parameterized IN clause for batch lookup
        id_params = {f"eid_{i}": eid for i, eid in enumerate(entry_ids)}
        id_placeholders = ", ".join(f":eid_{i}" for i in range(len(entry_ids)))
        existing_result = await db.execute(
            text(f"""
                SELECT id, content_sha256 FROM {schema}.transcript_entries
                WHERE id IN ({id_placeholders})
            """),
            id_params,
        )
        existing_map = {row.id: row.content_sha256 for row in existing_result}

        # Classify: new entries vs duplicates vs conflicts
        new_entries: list[SyncEntry] = []
        for entry in entries:
            if entry.id in existing_map:
                if existing_map[entry.id] == entry.content_sha256:
                    # Same ID, same content: idempotent duplicate
                    duplicates += 1
                    entries_duplicates += 1
                else:
                    # Same ID, different content: conflict error.
                    # ct-1841: also surface in item_errors so the client can
                    # quarantine this row by id without parsing the legacy
                    # `errors[]` strings.
                    entries_conflicted += 1
                    error_codes.add("ENTRY_CONFLICT")
                    errors.append(
                        f"Entry {entry.id}: conflict - entry exists with different content "
                        f"(existing sha: {existing_map[entry.id][:16]}..., "
                        f"new sha: {entry.content_sha256[:16]}...)"
                    )
                    item_errors.append(
                        SyncItemError(
                            item_kind="entry",
                            item_id=entry.id,
                            error_code="ENTRY_CONFLICT",
                            retryable=False,
                            detail=(
                                f"entry exists with different content "
                                f"(existing sha {existing_map[entry.id][:16]}..., "
                                f"new sha {entry.content_sha256[:16]}...)"
                            ),
                        )
                    )
            else:
                new_entries.append(entry)

        # Phase 2: Bulk INSERT with per-batch SAVEPOINT and per-row fallback.
        # Note: ON CONFLICT DO NOTHING means concurrent pushes of the same
        # new entry result in a lower rowcount (silent skip) rather than a
        # duplicate count. Data is safe; the client may see fewer accepted
        # entries than expected but can retry safely.
        # If the bulk INSERT fails, row-level savepoints keep one poison row
        # from stalling the rest of the batch.
        if new_entries:
            sp = "sp_entries_batch"
            try:
                await db.execute(text(f"SAVEPOINT {sp}"))
                # Build multi-row VALUES INSERT (sub-batch at 1000 to stay
                # under asyncpg's 32767 parameter limit: 18 cols * 1000 = 18000)
                entry_sub_batch = 1000
                total_inserted = 0
                for batch_start in range(0, len(new_entries), entry_sub_batch):
                    batch = new_entries[batch_start : batch_start + entry_sub_batch]
                    value_rows = []
                    params: dict[str, object] = {}
                    for j, entry in enumerate(batch):
                        suffix = f"_{j}"
                        value_rows.append(_entry_values_sql(suffix))
                        params.update(
                            _entry_insert_params(
                                entry,
                                suffix=suffix,
                                auth=auth,
                                device=device,
                            )
                        )
                    values_sql = ",\n                        ".join(value_rows)
                    result = await db.execute(
                        text(_insert_entries_sql(schema, values_sql)),
                        params,
                    )
                    total_inserted += result.rowcount  # type: ignore[attr-defined]
                entries_accepted += total_inserted
                accepted += total_inserted
                await db.execute(text(f"RELEASE SAVEPOINT {sp}"))
            except Exception as e:
                await _rollback_savepoint(db, sp)
                batch_insert_error = str(e)
                consecutive_row_failures = 0
                fallback_item_errors_emitted = 0
                batch_fallback_reported = False
                for i, entry in enumerate(new_entries):
                    if consecutive_row_failures >= 5:
                        remaining = len(new_entries) - i
                        entries_retriable_failed += remaining
                        error_codes.add("ENTRY_RETRYABLE_DB")
                        errors.append(
                            "Per-row entry insert fallback stopped after repeated "
                            f"failures; {remaining} entries marked retryable."
                        )
                        break

                    row_sp = f"sp_entry_fallback_{i}"
                    try:
                        await db.execute(text(f"SAVEPOINT {row_sp}"))
                        result = await db.execute(
                            text(_insert_entries_sql(schema, _entry_values_sql(""))),
                            _entry_insert_params(
                                entry,
                                suffix="",
                                auth=auth,
                                device=device,
                            ),
                        )
                        inserted = result.rowcount  # type: ignore[attr-defined]
                        entries_accepted += inserted
                        accepted += inserted
                        await db.execute(text(f"RELEASE SAVEPOINT {row_sp}"))
                        consecutive_row_failures = 0
                    except Exception as row_error:
                        await _rollback_savepoint(db, row_sp)
                        consecutive_row_failures += 1
                        entries_retriable_failed += 1
                        error_codes.add("ENTRY_RETRYABLE_DB")
                        if not batch_fallback_reported:
                            batch_fallback_reported = True
                            errors.append(
                                f"Batch entry insert ({len(new_entries)} entries) "
                                f"fell back to per-row insert: {batch_insert_error}"
                            )
                        if fallback_item_errors_emitted < 10:
                            fallback_item_errors_emitted += 1
                            errors.append(
                                f"Entry {entry.id}: retryable DB insert failure: {row_error}"
                            )
                            item_errors.append(
                                SyncItemError(
                                    item_kind="entry",
                                    item_id=entry.id,
                                    error_code="ENTRY_RETRYABLE_DB",
                                    retryable=True,
                                    detail="retryable database insert failure",
                                )
                            )

    # Upsert summaries
    for i, summary in enumerate(request.summaries):
        sp = f"sp_sum_{i}"
        try:
            await db.execute(text(f"SAVEPOINT {sp}"))
            await db.execute(
                text(f"""
                INSERT INTO {schema}.timeline_summaries
                    (id, entry_id, content_sha256, window_sha256,
                     present_form, past_form, disposition, generated_at)
                VALUES (:id, :entry_id, :content_sha256, :window_sha256,
                        :present_form, :past_form, :disposition, :generated_at)
                ON CONFLICT (content_sha256, window_sha256) DO NOTHING
            """),
                {
                    "id": str(uuid.uuid4()),
                    "entry_id": summary.entry_id,
                    "content_sha256": summary.content_sha256,
                    "window_sha256": summary.window_sha256,
                    "present_form": summary.present_form,
                    "past_form": summary.past_form,
                    "disposition": summary.disposition,
                    "generated_at": summary.generated_at,
                },
            )
            await db.execute(text(f"RELEASE SAVEPOINT {sp}"))
            accepted += 1
        except Exception as e:
            await _rollback_savepoint(db, sp)
            errors.append(f"Summary for {summary.entry_id}: {e}")

    # Upsert usage
    for i, usage in enumerate(request.usage):
        sp = f"sp_usage_{i}"
        try:
            await db.execute(text(f"SAVEPOINT {sp}"))
            await db.execute(
                text(f"""
                INSERT INTO {schema}.assistant_usage
                    (entry_id, request_id, model, input_tokens, output_tokens,
                     cache_creation_tokens, cache_read_tokens)
                VALUES (:entry_id, :request_id, :model, :input_tokens, :output_tokens,
                        :cache_creation_tokens, :cache_read_tokens)
                ON CONFLICT (entry_id, request_id) DO NOTHING
            """),
                {
                    "entry_id": usage.entry_id,
                    "request_id": usage.request_id,
                    "model": usage.model,
                    "input_tokens": usage.input_tokens,
                    "output_tokens": usage.output_tokens,
                    "cache_creation_tokens": usage.cache_creation_tokens,
                    "cache_read_tokens": usage.cache_read_tokens,
                },
            )
            await db.execute(text(f"RELEASE SAVEPOINT {sp}"))
            accepted += 1
        except Exception as e:
            await _rollback_savepoint(db, sp)
            errors.append(f"Usage {usage.entry_id}/{usage.request_id}: {e}")

    # Upsert tool invocations
    for i, inv in enumerate(request.tool_invocations):
        sp = f"sp_inv_{i}"
        try:
            await db.execute(text(f"SAVEPOINT {sp}"))
            await db.execute(
                text(f"""
                INSERT INTO {schema}.tool_invocations
                    (id, entry_id, transcript_id, tool_name, tool_key, status,
                     started_at, completed_at, metadata_json, created_at, updated_at)
                VALUES (:id, :entry_id, :transcript_id, :tool_name, :tool_key, :status,
                        :started_at, :completed_at, :metadata_json, :created_at, :updated_at)
                ON CONFLICT (id) DO NOTHING
            """),
                {
                    "id": inv.id,
                    "entry_id": inv.entry_id,
                    "transcript_id": inv.transcript_id,
                    "tool_name": inv.tool_name,
                    "tool_key": inv.tool_key,
                    "status": inv.status,
                    "started_at": inv.started_at,
                    "completed_at": inv.completed_at,
                    "metadata_json": json.dumps(inv.metadata_json) if inv.metadata_json else None,
                    "created_at": inv.created_at,
                    "updated_at": inv.updated_at,
                },
            )
            await db.execute(text(f"RELEASE SAVEPOINT {sp}"))
            accepted += 1
        except Exception as e:
            await _rollback_savepoint(db, sp)
            errors.append(f"ToolInvocation {inv.id}: {e}")

    # Upsert transcript metadata
    for i, meta in enumerate(request.transcript_metadata):
        sp = f"sp_meta_{i}"
        try:
            await db.execute(text(f"SAVEPOINT {sp}"))
            await db.execute(
                text(f"""
                INSERT INTO {schema}.transcript_metadata
                    (transcript_id, project_id, title, description, topics,
                     confidence, generated_at, model, created_at, updated_at)
                VALUES (:transcript_id, :project_id, :title, :description, :topics,
                        :confidence, :generated_at, :model, :created_at, :updated_at)
                ON CONFLICT (transcript_id) DO UPDATE SET
                    title = EXCLUDED.title,
                    description = EXCLUDED.description,
                    topics = EXCLUDED.topics,
                    updated_at = EXCLUDED.updated_at
            """),
                {
                    "transcript_id": meta.transcript_id,
                    "project_id": meta.project_id,
                    "title": meta.title,
                    "description": meta.description,
                    "topics": json.dumps(meta.topics),
                    "confidence": meta.confidence,
                    "generated_at": meta.generated_at,
                    "model": meta.model,
                    "created_at": meta.created_at,
                    "updated_at": meta.updated_at,
                },
            )
            await db.execute(text(f"RELEASE SAVEPOINT {sp}"))
            accepted += 1
        except Exception as e:
            await _rollback_savepoint(db, sp)
            errors.append(f"Metadata {meta.transcript_id}: {e}")

    # ── Data retention enforcement (on-push cleanup) ─────────────────
    # If the tenant has a data retention policy (> 0 days), delete entries
    # older than the retention window. This is opportunistic cleanup on push
    # rather than a background job.
    #
    # ct-2028 (CL-S01): only consider rows that were already resident on the
    # server BEFORE this request (server_sequence <= pre_push_max_seq). Entries
    # inserted in THIS push get a higher server_sequence and must NOT be deleted
    # in the same request, even when their client timestamp predates the window
    # (DB restore, late first sync, backfill of newly-discovered old
    # transcripts). The cloud is the source of truth; deleting just-pushed
    # history would silently lose data for any device that has not pulled yet.
    # Genuinely-resident truly-old rows (server_sequence <= pre_push_max_seq)
    # are still removed, so retention semantics are preserved.
    retention_days = get_effective_history_retention_days(tenant_obj)
    if retention_days > 0:
        retention_cutoff = int((datetime.now(UTC) - timedelta(days=retention_days)).timestamp())
        try:
            # ct-2028 (review iter-01): run the retention DELETE inside a SAVEPOINT
            # so a statement failure rolls back only the nested transaction. On
            # PostgreSQL a failed DELETE would otherwise abort the whole outer
            # transaction, poisoning the session and breaking the high-water mark
            # read, audit logging, and idempotency update that follow.
            async with db.begin_nested():
                cleanup_result = await db.execute(
                    text(
                        f"WITH rows AS ("
                        f"  SELECT ctid FROM {schema}.transcript_entries "
                        f"  WHERE timestamp < :cutoff "
                        f"    AND server_sequence <= :pre_push_max_seq "
                        f"  ORDER BY timestamp ASC "
                        f"  LIMIT :batch_size"
                        f") "
                        f"DELETE FROM {schema}.transcript_entries "
                        f"WHERE ctid IN (SELECT ctid FROM rows)"
                    ),
                    {
                        "cutoff": retention_cutoff,
                        "batch_size": RETENTION_BATCH_SIZE,
                        "pre_push_max_seq": pre_push_max_seq,
                    },
                )
                cleaned_count = cleanup_result.rowcount  # type: ignore[attr-defined]
            if cleaned_count > 0:
                logger.info(
                    "Data retention cleanup: deleted %d entries older than %d days for tenant=%s",
                    cleaned_count,
                    retention_days,
                    auth.tenant_id,
                )
        except Exception:
            logger.warning(
                "Data retention cleanup failed for tenant=%s",
                auth.tenant_id,
                exc_info=True,
            )

    # After all entries are inserted, get the current high-water mark.
    # Use MAX(server_sequence) instead of sequence last_value because
    # PostgreSQL sequences advance even on rolled-back transactions.
    # INTENTIONAL: not user-scoped (see sync_pull comment for rationale).
    server_sequence = 0
    try:
        max_result = await db.execute(
            text(f"SELECT COALESCE(MAX(server_sequence), 0) FROM {schema}.transcript_entries")
        )
        server_sequence = max_result.scalar() or 0
    except Exception:
        pass

    # ct-2076: detect first activation and resolve the user's email HERE, while
    # trailing writes (usage event, session completion, idempotency store) still
    # follow. Doing the lookup now keeps this SELECT from becoming the handler's
    # final statement, which the session-completion path asserts on. The
    # notification itself (no DB work) fires near the return.
    is_first_activation = (
        pre_push_watermark_known and pre_push_max_seq == 0 and entries_accepted > 0
    )
    activation_email: str | None = None
    if is_first_activation:
        activation_email_result = await db.execute(
            select(User.email).where(User.id == auth.user_id)
        )
        activation_email = activation_email_result.scalar_one_or_none()

    # Record usage event
    usage_event = UsageEvent(
        tenant_id=auth.tenant_id,
        user_id=auth.user_id,
        event_type="sync_push",
        entry_count=entries_accepted,
    )
    db.add(usage_event)

    # Record audit event for the sync push
    await log_event(
        db,
        tenant_id=auth.tenant_id,
        user_id=auth.user_id,
        action="sync.push",
        resource_type="sync_batch",
        detail={
            "entry_count": accepted,
            "project_count": len(request.projects),
            "duplicates": duplicates,
            "errors": len(errors),
        },
        ip_address=http_request.client.host if http_request.client else None,
    )

    # Add blocked project info to errors for client visibility
    if blocked_projects or blocked_project_ids:
        shown = blocked_projects[:25]
        extra = ""
        if len(blocked_projects) > 25:
            extra = f" (+{len(blocked_projects) - 25} more)"
        names = ", ".join(shown) if shown else "<none>"
        msg = f"Blocked by project allow-list: {names}{extra}"
        if blocked_project_ids:
            msg += f" (blocked_project_ids={len(blocked_project_ids)})"
        errors.append(msg)
        error_codes.add("ENTRY_POLICY_BLOCKED")

    logger.info(
        "Sync push: tenant=%s user=%s accepted=%d duplicates=%d errors=%d blocked=%d",
        auth.tenant_id,
        auth.user_id,
        accepted,
        duplicates,
        len(errors),
        len(blocked_projects),
    )

    entries_resolved = (
        entries_accepted
        + entries_duplicates
        + entries_conflicted
        + entries_blocked_policy
        + entries_permanent_failed  # ct-1841: permanent failures count as resolved
    )
    checkpoint_safe = entries_retriable_failed == 0 and entries_resolved == entries_sent_total
    # ct-1841: permanent failures (oversized, sha mismatch, malformed) bubble
    # up as needs_attention so the client surfaces them in the skipped-entries
    # row, but they do NOT mark the batch `blocked` -- only retriable failures
    # block. Permanent-only batches resolve as `completed_with_issues`.
    needs_attention_count = entries_conflicted + entries_blocked_policy + entries_permanent_failed
    completion_state: Literal["in_progress", "success", "completed_with_issues", "blocked"]
    if entries_retriable_failed > 0:
        completion_state = "blocked"
    elif needs_attention_count > 0:
        completion_state = "completed_with_issues"
    elif checkpoint_safe:
        completion_state = "success"
    else:
        completion_state = "in_progress"

    completed_batch_increment = 1 if checkpoint_safe else 0
    next_completed_batches = (
        sync_session_obj.completed_batches if sync_session_obj else 0
    ) + completed_batch_increment
    effective_total_batches = (
        sync_session_obj.total_batches
        if sync_session_obj and sync_session_obj.total_batches is not None
        else request.total_batches
    )
    should_complete_session = checkpoint_safe and session_is_effectively_complete(
        total_batches=effective_total_batches,
        completed_batches=next_completed_batches,
    )

    # ── Sync session create/update ──────────────────────────────────
    # Create a new session or update the existing one. This happens after
    # all item processing so the completed_batches count is accurate.
    if sync_session_tracking_enabled:
        try:
            session_now = datetime.now(UTC)
            async with db.begin_nested():
                if sync_session_obj:
                    update_values: dict[str, object] = {
                        "completed_batches": next_completed_batches,
                        "last_batch_at": session_now,
                    }
                    if request.total_batches and not sync_session_obj.total_batches:
                        update_values["total_batches"] = request.total_batches
                    if should_complete_session:
                        update_values["status"] = "completed"
                        update_values["completed_at"] = session_now
                    await db.execute(
                        update(SyncSession)
                        .where(SyncSession.id == sync_session_obj.id)
                        .values(**update_values)
                    )
                    sync_session_id = str(sync_session_obj.id)
                else:
                    new_session_id = requested_session_uuid or uuid.uuid4()
                    # Abandon any prior in_progress sessions for this device so
                    # stalled orphans don't linger in the status dashboard after
                    # the client reconnects with a new session. (ct-449)
                    device_machine_id = request.device.machine_id
                    abandoned_result = await db.execute(
                        update(SyncSession)
                        .where(
                            SyncSession.tenant_id == auth.tenant_id,
                            SyncSession.user_id == auth.user_id,
                            SyncSession.device_id == device_machine_id,
                            SyncSession.status == "in_progress",
                            SyncSession.id != new_session_id,
                        )
                        .values(status="abandoned", completed_at=session_now)
                    )
                    if abandoned_result.rowcount > 0:  # type: ignore[attr-defined]
                        logger.info(
                            "Abandoned %d orphaned session(s) for device %s on new session start",
                            abandoned_result.rowcount,  # type: ignore[attr-defined]
                            device_machine_id,
                        )
                    new_session = SyncSession(
                        id=new_session_id,
                        tenant_id=auth.tenant_id,
                        user_id=auth.user_id,
                        device_id=request.device.machine_id,
                        started_at=session_now,
                        completed_at=session_now if should_complete_session else None,
                        status="completed" if should_complete_session else "in_progress",
                        total_batches=request.total_batches,
                        completed_batches=next_completed_batches,
                        last_batch_at=session_now,
                    )
                    db.add(new_session)
                    await db.flush()
                    sync_session_id = str(new_session_id)
        except Exception:
            logger.warning(
                "Sync session tracking unavailable; returning response without sync_session_id",
                exc_info=True,
            )
            sync_session_id = None

    # ct-1841: surface every permanent item failure in item_errors[]. Each
    # entry's error_code carries forward to client-side error_codes set so
    # legacy clients can still see "ENTRY_TOO_LARGE", etc.
    for ie in item_errors:
        error_codes.add(ie.error_code)

    response = SyncPushResponse(
        accepted=accepted,
        duplicates_skipped=duplicates,
        errors=errors[:10],  # Cap human-readable error strings to avoid oversized responses
        sync_token=str(uuid.uuid4()),
        idempotency_key=request.idempotency_key,
        sync_session_id=sync_session_id,
        batch_seq=request.batch_seq,
        entries_sent=entries_sent_total,
        entries_accepted=entries_accepted,
        entries_duplicates=entries_duplicates,
        entries_conflicted=entries_conflicted,
        entries_blocked_policy=entries_blocked_policy,
        entries_permanent_failed=entries_permanent_failed,
        entries_retriable_failed=entries_retriable_failed,
        entries_resolved=entries_resolved,
        checkpoint_safe=checkpoint_safe,
        completion_state=completion_state,
        needs_attention_count=needs_attention_count,
        error_codes=sorted(error_codes),
        item_errors=item_errors,
        server_sequence=server_sequence,
        project_id_remapped=project_id_remap,
    )

    # Store only resolved idempotency responses for future replay. Retryable
    # blocked/in-progress responses are not stable outcomes; clear the guard row
    # so same-key client retries can reprocess immediately.
    if request.idempotency_key:
        idempotency_filter = (
            (SyncIdempotency.tenant_id == auth.tenant_id)
            & (SyncIdempotency.key_id == auth.key_id)
            & (SyncIdempotency.idempotency_key == request.idempotency_key)
        )
        if completion_state in {"success", "completed_with_issues"}:
            await db.execute(
                update(SyncIdempotency)
                .where(idempotency_filter)
                .values(
                    is_complete=True,
                    response_json=response.model_dump_json(),
                )
            )
        elif completion_state in {"blocked", "in_progress"}:
            await db.execute(delete(SyncIdempotency).where(idempotency_filter))
        # Unresolved outcomes are not stable replay results.

    # Opportunistic cleanup of expired idempotency records (~5% of requests).
    # Lightweight alternative to a dedicated background job. Deletes at most
    # 100 expired rows per invocation to avoid holding locks.
    if random.random() < 0.05:
        try:
            async with db.begin_nested():
                cleanup_result = await db.execute(
                    text(
                        "DELETE FROM sync_idempotency "
                        "WHERE id IN ("
                        "  SELECT id FROM sync_idempotency "
                        "  WHERE expires_at < now() "
                        "  LIMIT 100"
                        ")"
                    )
                )
            cleaned = cleanup_result.rowcount  # type: ignore[attr-defined]
            if cleaned > 0:
                logger.info("Idempotency cleanup: deleted %d expired rows", cleaned)
        except Exception:
            logger.debug("Idempotency cleanup skipped (non-critical)", exc_info=True)

        # Also clean up stale sync sessions (inactive for > session_ttl_hours).
        try:
            stale_cutoff = datetime.now(UTC) - timedelta(hours=settings.session_ttl_hours)
            async with db.begin_nested():
                stale_result = await db.execute(
                    update(SyncSession)
                    .where(
                        SyncSession.status == "in_progress",
                        SyncSession.last_batch_at < stale_cutoff,
                    )
                    .values(status="abandoned", completed_at=datetime.now(UTC))
                )
            stale_cleaned = stale_result.rowcount  # type: ignore[attr-defined]
            if stale_cleaned > 0:
                logger.info("Stale session cleanup: abandoned %d sessions", stale_cleaned)
        except Exception:
            logger.debug("Stale session cleanup skipped (non-critical)", exc_info=True)

    # ct-2076: fire the first-successful-sync (activation) operator notification.
    # Fires once, when a tenant that had NO entries (confirmed-empty watermark)
    # lands its first ones - the activation signal error monitoring cannot see,
    # and it auto-pings when a previously-stuck user (e.g. a legacy client that
    # finally drains after the cap raise) activates. Idempotent replays return
    # earlier and never reach here, so it does not double-fire. The email lookup
    # ran earlier, so this adds no trailing DB query (fire-and-forget).
    if is_first_activation:
        is_internal = tenant_is_internal(tenant_obj)
        await notify_first_activation(
            email=activation_email,
            tenant_id=str(auth.tenant_id),
            is_internal=is_internal,
        )
        # ct-2080: funnel event (no-op unless hosted backend registered).
        await emit_funnel_event(
            "first_sync",
            distinct_id=str(auth.tenant_id),
            properties=with_tenant_acquisition_properties(
                tenant_obj,
                {"entries_accepted": entries_accepted},
            ),
            is_internal=is_internal,
        )

    # ct-2106 + ct-2107: second_device_sync, the real ct-1460 activation North-Star.
    # Emits once when a 2nd DISTINCT device for the tenant completes its first sync
    # within 14 days of register. device_was_first_sync gates on THIS device's
    # NULL->non-NULL last_sync_at transition.
    #
    # ct-2107 hardening (previously a tracked follow-up): the emission is now
    # transactional fire-once, not best-effort. A per-tenant BLOCKING advisory lock
    # serializes concurrent first-syncs for the same tenant so the synced-device count
    # is read accurately (kills the under-read MISS, where two devices on a zero-synced
    # tenant each observe a count of 1 and the event is dropped), and a persisted marker
    # (tenants.second_device_synced_at) claimed atomically via UPDATE ... WHERE marker
    # IS NULL RETURNING fires the event exactly once (kills the over-read DUPLICATE and
    # any replay double-fire). The count uses >= 2 so a historically-under-read tenant
    # now at 3+ synced devices still activates once; the marker prevents the 3rd/4th
    # device from re-firing.
    #
    # The whole block is gated by funnel_backend_registered() so non-hosted builds pay
    # nothing (no lock, no count, no UPDATE), runs only on the rare device-first-sync
    # path (the common sync path never locks), and takes its lock AFTER the idempotency
    # lock at the top of push (one consistent acquire order across all requests -> no
    # deadlock).
    #
    # Failure isolation (ct-2107 review CT2107-P1-1): the DB portion runs inside a
    # SAVEPOINT (begin_nested). A statement error in the lock/count/claim - e.g. a
    # deploy-skew missing column, a lock timeout, or any operational error - would
    # otherwise leave the OUTER sync transaction aborted, so merely catching the Python
    # exception is not enough: the request would still 500 at commit. The savepoint
    # confines any such failure, the outer transaction stays committable, and activation
    # analytics genuinely cannot break a sync. emit_funnel_event is fire-and-forget and
    # touches no DB, so it runs AFTER the savepoint, outside the failure boundary.
    if device_was_first_sync and not tenant_is_internal(tenant_obj) and funnel_backend_registered():
        event_payload: dict[str, Any] | None = None
        try:
            async with db.begin_nested():
                tenant_lock_key = int(
                    hashlib.sha256(f"second_device_sync:{auth.tenant_id}".encode()).hexdigest()[
                        :15
                    ],
                    16,
                )
                await db.execute(
                    text("SELECT pg_advisory_xact_lock(:key)"),
                    {"key": tenant_lock_key},
                )
                synced_device_count = (
                    await db.execute(
                        select(func.count(func.distinct(Device.id)))
                        .select_from(Device)
                        .join(User, User.id == Device.user_id)
                        .where(
                            User.tenant_id == auth.tenant_id,
                            Device.last_sync_at.is_not(None),
                        )
                    )
                ).scalar() or 0
                if synced_device_count >= 2 and tenant_obj.created_at is not None:
                    register_age = datetime.now(UTC) - tenant_obj.created_at
                    if register_age <= timedelta(days=14):
                        # Atomic fire-once claim: only the first request to flip the
                        # marker NULL->now() wins and emits. public-qualified because the
                        # request search_path may point at a tenant schema.
                        claimed = (
                            await db.execute(
                                text(
                                    "UPDATE public.tenants "
                                    "SET second_device_synced_at = :now "
                                    "WHERE id = :tid "
                                    "AND second_device_synced_at IS NULL "
                                    "RETURNING id"
                                ),
                                {"now": datetime.now(UTC), "tid": auth.tenant_id},
                            )
                        ).scalar()
                        if claimed is not None:
                            event_payload = {
                                "device_count": synced_device_count,
                                "days_since_register": register_age.days,
                            }
        except Exception:  # noqa: BLE001 - activation analytics must never break a sync
            logger.warning(
                "event=second_device_sync_hardening_failed tenant_id=%s",
                auth.tenant_id,
                exc_info=True,
            )
        if event_payload is not None:
            await emit_funnel_event(
                "second_device_sync",
                distinct_id=str(auth.tenant_id),
                properties=with_tenant_acquisition_properties(
                    tenant_obj,
                    event_payload,
                ),
                is_internal=tenant_is_internal(tenant_obj),
            )

    return response


@router.get("/pull", response_model=SyncPullResponse)
async def sync_pull(
    auth: Annotated[AuthContext, Depends(require_scope("sync"))],
    db: Annotated[AsyncSession, Depends(get_db)],
    since: Annotated[int, Query(ge=0, description="server_sequence cursor")] = 0,
    limit: Annotated[int, Query(ge=1, le=1000, description="max entries per response")] = 200,
    project_id: Annotated[str | None, Query(description="optional project filter")] = None,
) -> SyncPullResponse:
    """Pull entries from cloud, using cursor-based pagination via server_sequence.

    Returns entries with server_sequence > since, ordered by server_sequence ASC.
    Includes referenced projects, transcripts, and summaries for the returned entries.
    """
    # Resolve tenant schema
    tenant = await db.execute(select(Tenant).where(Tenant.id == auth.tenant_id))
    tenant_obj = tenant.scalar_one_or_none()
    if not tenant_obj:
        raise HTTPException(status_code=404, detail="Tenant not found.")

    schema = get_tenant_schema(tenant_obj.slug)
    await ensure_tenant_schema_compat(db, schema)
    if not _SCHEMA_NAME_RE.match(schema):
        logger.error("Unsafe tenant schema name: %r", schema)
        raise HTTPException(status_code=500, detail="Internal configuration error.")

    # nextval allocation is not commit ordering: an uncommitted lower sequence
    # must not become visible after we checkpoint a higher one. SHARE conflicts
    # with entry writers' ROW EXCLUSIVE locks and lasts through the page commit,
    # making this page a stable committed boundary. NOWAIT avoids queueing a
    # pull (and its auth-row lock) behind a long upload. Other tenants are unaffected.
    try:
        await db.execute(text(f"LOCK TABLE {schema}.transcript_entries IN SHARE MODE NOWAIT"))
    except DBAPIError as exc:
        if getattr(exc.orig, "sqlstate", None) != "55P03":
            raise
        raise HTTPException(
            status_code=503,
            detail="Sync writes are in progress. Retry this pull with the same cursor.",
            headers={"Retry-After": "1"},
        ) from exc

    # Query entries with server_sequence > since, fetch limit+1 to detect has_more.
    # User scoping: members only see their own entries; owners/admins see all.
    scope_clause, scope_params = build_user_scope_clause(auth)
    pull_params: dict[str, object] = {"since": since, "fetch_limit": limit + 1, **scope_params}

    project_clause = ""
    if project_id:
        project_clause = "AND project_id = :project_id"
        pull_params["project_id"] = project_id

    entries_result = await db.execute(
        text(
            f"SELECT id, transcript_id, project_id, session_id, provider, kind, "
            f"timestamp, content, content_sha256, display_in_timeline, "
            f"git_branch, git_commit, cwd, uploaded_by_user_id, "
            f"uploaded_by_device_id, uploaded_by_device_name, "
            f"server_sequence, created_at, updated_at "
            f"FROM {schema}.transcript_entries "
            f"WHERE server_sequence IS NOT NULL AND server_sequence > :since "
            f"{project_clause} {scope_clause} "
            f"ORDER BY server_sequence ASC "
            f"LIMIT :fetch_limit"
        ),
        pull_params,
    )

    rows = entries_result.fetchall()
    has_more = len(rows) > limit
    if has_more:
        rows = rows[:limit]

    # Build entry list
    entries: list[PullEntry] = []
    project_ids: set[str] = set()
    transcript_ids: set[str] = set()
    entry_ids: list[str] = []
    skipped = 0

    for row in rows:
        try:
            entry = PullEntry(
                id=row.id,
                transcript_id=row.transcript_id,
                project_id=row.project_id,
                session_id=row.session_id,
                provider=row.provider,
                kind=row.kind,
                timestamp=row.timestamp,
                content=row.content,
                content_sha256=row.content_sha256,
                display_in_timeline=row.display_in_timeline,
                git_branch=row.git_branch,
                git_commit=row.git_commit,
                cwd=row.cwd,
                uploaded_by_user_id=str(row.uploaded_by_user_id),
                uploaded_by_device_id=row.uploaded_by_device_id,
                uploaded_by_device_name=row.uploaded_by_device_name,
                server_sequence=row.server_sequence,
                created_at=row.created_at,
                updated_at=row.updated_at,
            )
        except ValidationError:
            skipped += 1
            logger.warning(
                "Skipping invalid entry %s (server_seq=%s): validation failed",
                row.id,
                row.server_sequence,
                exc_info=True,
            )
            continue
        entries.append(entry)
        project_ids.add(row.project_id)
        transcript_ids.add(row.transcript_id)
        entry_ids.append(row.id)

    # Determine next_cursor from last row's server_sequence (not last valid
    # entry). This ensures skipped invalid rows don't cause infinite re-fetch.
    next_cursor = rows[-1].server_sequence if rows else since

    # Fetch referenced projects
    projects: list[PullProject] = []
    if project_ids:
        placeholders = ", ".join(f":p{i}" for i in range(len(project_ids)))
        params = {f"p{i}": pid for i, pid in enumerate(project_ids)}
        proj_result = await db.execute(
            text(f"SELECT id, name, root_path FROM {schema}.projects WHERE id IN ({placeholders})"),
            params,
        )
        for row in proj_result.fetchall():
            projects.append(
                PullProject(
                    id=row.id,
                    name=row.name,
                    root_path=row.root_path,
                )
            )

    # Fetch referenced transcripts
    transcripts: list[PullTranscript] = []
    if transcript_ids:
        placeholders = ", ".join(f":t{i}" for i in range(len(transcript_ids)))
        params = {f"t{i}": tid for i, tid in enumerate(transcript_ids)}
        tx_result = await db.execute(
            text(
                f"SELECT id, project_id, file_path, provider FROM {schema}.transcripts "
                f"WHERE id IN ({placeholders})"
            ),
            params,
        )
        for row in tx_result.fetchall():
            transcripts.append(
                PullTranscript(
                    id=row.id,
                    project_id=row.project_id,
                    file_path=row.file_path,
                    provider=row.provider,
                )
            )

    # Fetch summaries for returned entries
    summaries: list[PullSummary] = []
    if entry_ids:
        placeholders = ", ".join(f":e{i}" for i in range(len(entry_ids)))
        params = {f"e{i}": eid for i, eid in enumerate(entry_ids)}
        sum_result = await db.execute(
            text(
                f"SELECT entry_id, present_form, past_form, disposition "
                f"FROM {schema}.timeline_summaries "
                f"WHERE entry_id IN ({placeholders})"
            ),
            params,
        )
        for row in sum_result.fetchall():
            summaries.append(
                PullSummary(
                    entry_id=row.entry_id,
                    present_form=row.present_form,
                    past_form=row.past_form,
                    disposition=row.disposition,
                )
            )

    # Get current high-water mark (max server_sequence overall).
    # Use MAX(server_sequence) instead of sequence last_value because
    # PostgreSQL sequences advance even on rolled-back transactions.
    #
    # INTENTIONAL: server_sequence is NOT user-scoped. The sync protocol
    # requires clients to know the global high-water mark so they can detect
    # convergence (i.e., "am I fully caught up?"). The sequence number is a
    # monotonic counter that reveals no content, only that activity has occurred.
    # Scoping it per-user would break cursor-based pagination for clients that
    # sync across multiple devices. (Reviewed in ct-292 data scoping audit.)
    current_server_sequence = 0
    try:
        max_result = await db.execute(
            text(f"SELECT COALESCE(MAX(server_sequence), 0) FROM {schema}.transcript_entries")
        )
        current_server_sequence = max_result.scalar() or 0
    except Exception:
        pass

    logger.info(
        "Sync pull: tenant=%s user=%s role=%s entries=%d skipped=%d has_more=%s since=%d",
        auth.tenant_id,
        auth.user_id,
        auth.role,
        len(entries),
        skipped,
        has_more,
        since,
    )

    response = SyncPullResponse(
        entries=entries,
        projects=projects,
        transcripts=transcripts,
        summaries=summaries,
        has_more=has_more,
        next_cursor=next_cursor,
        server_sequence=current_server_sequence,
    )
    # Release the page lock before FastAPI transmits the response. Request-scope
    # yield teardown can otherwise keep it held behind a slow network reader.
    await db.commit()
    return response


@router.get("/status", response_model=SyncStatusResponse)
async def sync_status(
    auth: Annotated[AuthContext, Depends(require_scope("sync"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> SyncStatusResponse:
    """Get sync status for the authenticated user."""
    now = datetime.now(UTC)
    # Get devices
    devices_result = await db.execute(select(Device).where(Device.user_id == auth.user_id))
    devices = devices_result.scalars().all()

    # Get tenant for schema lookup
    tenant = await db.execute(select(Tenant).where(Tenant.id == auth.tenant_id))
    tenant_obj = tenant.scalar_one_or_none()

    entries_synced = 0
    server_sequence = 0
    if tenant_obj:
        schema = get_tenant_schema(tenant_obj.slug)
        await ensure_tenant_schema_compat(db, schema)
        if not _SCHEMA_NAME_RE.match(schema):
            logger.error("Unsafe tenant schema name: %r", schema)
            raise HTTPException(status_code=500, detail="Internal configuration error.")

        # Count entries visible to this user (members see only their own;
        # owners/admins see all entries in the tenant).
        scope_clause, scope_params = build_user_scope_clause(auth)
        try:
            async with db.begin_nested():
                count_sql = (
                    f"SELECT COUNT(*) FROM {schema}.transcript_entries WHERE 1=1 {scope_clause}"
                )
                result = await db.execute(text(count_sql), scope_params)
            entries_synced = result.scalar() or 0
        except Exception:
            pass  # Schema may not exist yet

        # INTENTIONAL: server_sequence is NOT user-scoped (same rationale as
        # sync_pull above). The global high-water mark is needed for sync
        # convergence. See ct-292 data scoping audit.
        try:
            async with db.begin_nested():
                max_result = await db.execute(
                    text(
                        f"SELECT COALESCE(MAX(server_sequence), 0) FROM {schema}.transcript_entries"
                    )
                )
            server_sequence = max_result.scalar() or 0
        except Exception:
            pass  # Schema may not exist yet

    last_sync = None
    if devices:
        sync_times: list[datetime] = [d.last_sync_at for d in devices if d.last_sync_at is not None]
        if sync_times:
            last_sync = max(sync_times)

    # Count in-progress sync sessions for this user (excludes stale sessions)
    pending_batches = 0
    active_push_session: ActivePushSessionStatus | None = None
    try:
        # Compatibility cleanup for older lingering sessions. This read path
        # intentionally mutates state, and get_db() commits on request teardown.
        async with db.begin_nested():
            await finalize_effectively_complete_sessions(auth, db, now=now)
            stale_cutoff = datetime.now(UTC) - timedelta(hours=settings.session_ttl_hours)
            pending_result = await db.execute(
                select(func.count(SyncSession.id)).where(
                    SyncSession.tenant_id == auth.tenant_id,
                    SyncSession.user_id == auth.user_id,
                    SyncSession.status == "in_progress",
                    SyncSession.last_batch_at >= stale_cutoff,
                    SyncSession.total_batches.is_not(None),
                    SyncSession.total_batches > 1,
                    SyncSession.completed_batches < SyncSession.total_batches,
                )
            )
            pending_batches = pending_result.scalar() or 0

            latest_session_result = await db.execute(
                select(SyncSession)
                .where(
                    SyncSession.tenant_id == auth.tenant_id,
                    SyncSession.user_id == auth.user_id,
                    SyncSession.status == "in_progress",
                    SyncSession.last_batch_at >= stale_cutoff,
                    SyncSession.total_batches.is_not(None),
                    SyncSession.total_batches > 1,
                    SyncSession.completed_batches < SyncSession.total_batches,
                )
                .order_by(
                    SyncSession.last_batch_at.desc(),
                    SyncSession.started_at.desc(),
                )
                .limit(1)
            )
        latest_session = latest_session_result.scalar_one_or_none()
        if latest_session:
            if not session_is_bulk_catch_up(
                total_batches=latest_session.total_batches,
                completed_batches=latest_session.completed_batches,
            ):
                latest_session = None
        if latest_session:
            # NOTE: Session currently tracks batch counts, not entry counts.
            # We still project this for UI continuity; entry-level progress can
            # be introduced once session baselines are persisted.
            entries_total = latest_session.total_batches
            entries_resolved = latest_session.completed_batches
            progress_percent = None
            eta_seconds = None

            if entries_total and entries_total > 0:
                progress_percent = min(100.0, (entries_resolved / entries_total) * 100.0)

            # Approximate ETA only when total batch count is available.
            if (
                entries_total
                and entries_total > 0
                and latest_session.started_at
                and latest_session.completed_batches > 0
            ):
                elapsed_seconds = max(1.0, (now - latest_session.started_at).total_seconds())
                batches_per_second = latest_session.completed_batches / elapsed_seconds
                if batches_per_second > 0:
                    remaining = max(0, entries_total - latest_session.completed_batches)
                    eta_seconds = int(remaining / batches_per_second)

            stalled_cutoff = now - STALL_WINDOW
            is_stalled = (
                latest_session.last_batch_at is not None
                and latest_session.last_batch_at < stalled_cutoff
            )

            active_push_session = ActivePushSessionStatus(
                sync_session_id=str(latest_session.id),
                phase="stalled" if is_stalled else "initial_upload",
                entries_resolved=entries_resolved,
                entries_total=entries_total,
                progress_percent=progress_percent,
                throughput_entries_per_min=None,
                eta_seconds=eta_seconds,
                checkpoint_safe=None,
                completion_state="in_progress",
                needs_attention_count=0,
                last_batch_at=latest_session.last_batch_at,
            )
    except Exception:
        pass  # Table may not exist yet during migration rollout

    return SyncStatusResponse(
        last_sync=last_sync,
        entries_synced=entries_synced,
        devices=[
            DeviceInfo(
                machine_id=d.machine_id,
                machine_name=d.machine_name,
                os=d.os,
                app_version=d.app_version,
            )
            for d in devices
        ],
        server_sequence=server_sequence,
        pending_batches=pending_batches,
        active_push_session=active_push_session,
    )
