"""One authorization/scope predicate for group search, hydration and activity.

The final SQL statement observes current credentials, group revision, aliases,
shares, retention and results together. No client fan-out or tenant writer lock.
"""

import base64
import hashlib
import hmac
import json
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import HTTPException
from fastapi.encoders import jsonable_encoder
from sqlalchemy import ARRAY, Text, Uuid, bindparam, text
from sqlalchemy.ext.asyncio import AsyncSession

from contextify_cloud.config import settings
from contextify_cloud.group_schemas import GroupQuery
from contextify_cloud.middleware.auth import AuthContext
from contextify_cloud.models import MachineGroup, Tenant
from contextify_cloud.services.machine_groups import fail, resolve, tenant_for
from contextify_cloud.services.plan_limits import get_effective_history_retention_days
from contextify_cloud.services.tenant import ensure_tenant_schema_compat, get_tenant_schema

MAX_PAGE_BYTES = 1024 * 1024
MAX_RECORD_BYTES = 32768


def encoded(value: Any) -> bytes:
    return json.dumps(jsonable_encoder(value), ensure_ascii=False, separators=(",", ":")).encode()


def cursor_encode(value: dict[str, Any]) -> str:
    data = encoded(value)
    signature = hmac.digest(settings.api_secret_key.encode(), b"group-v1:" + data, "sha256")
    return base64.urlsafe_b64encode(data + signature).decode().rstrip("=")


def cursor_decode(value: str) -> dict[str, Any]:
    try:
        data = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        body, signature = data[:-32], data[-32:]
        if not hmac.compare_digest(
            signature, hmac.digest(settings.api_secret_key.encode(), b"group-v1:" + body, "sha256")
        ):
            raise ValueError
        result = json.loads(body)
        if not isinstance(result, dict) or result.get("v") != 1:
            raise ValueError
        return result
    except (ValueError, TypeError):
        fail("invalid_cursor", "Use a cursor from this server and scope", 400)
    raise AssertionError


def scope_hash(auth: AuthContext, group: MachineGroup, query: GroupQuery) -> str:
    scope = query.model_dump(mode="json", exclude={"limit", "offset"})
    return hashlib.sha256(
        encoded(
            {
                "tenant": str(auth.tenant_id),
                "user": str(auth.user_id),
                "group": str(group.id),
                "scope": scope,
            }
        )
    ).hexdigest()


async def prepare(
    db: AsyncSession, auth: AuthContext, selector: str, query: GroupQuery
) -> tuple[Tenant, MachineGroup, str]:
    if query.project_scope.this_worktree:
        fail("unsupported_scope", "Cloud project IDs may combine worktrees; use repo scope", 400)
    tenant = await tenant_for(db, auth)
    group = await resolve(db, auth, selector)
    schema = get_tenant_schema(tenant.slug)
    await ensure_tenant_schema_compat(db, schema)
    return tenant, group, schema


def statement(
    schema: str,
    auth: AuthContext,
    tenant: Tenant,
    group: MachineGroup,
    query: GroupQuery,
    *,
    live: bool,
    lower: int = 0,
    high: int | None = None,
    anchor: str | None = None,
    context: bool = False,
    from_now: bool = False,
    page_limit: int = 200,
    include_retired: bool = False,
    snapshot: bool = False,
) -> tuple[str, dict[str, Any]]:
    scope = query.project_scope
    retention = get_effective_history_retention_days(tenant)
    params: dict[str, Any] = {
        "uid": auth.user_id,
        "tid": auth.tenant_id,
        "gid": group.id,
        "key": auth.key_id,
        "browser": auth.session_id is not None,
        "session": auth.session_id,
        "mode": scope.mode,
        "projects": scope.project_ids,
        "repo": scope.repo_group_key,
        "worktree": scope.this_worktree,
        "mine": query.mine,
        "device": query.device_id,
        "joined": query.joined_device_id,
        "instance": query.identity_instance_id,
        "query": query.q,
        "since": query.since,
        "until": query.until,
        "kinds": query.kinds,
        "transcript": query.transcript_id,
        "exclude_sessions": query.exclude_session_ids,
        "cutoff": int((datetime.now(UTC) - timedelta(days=retention)).timestamp())
        if retention
        else 0,
        "live": live and not include_retired,
        "lower": lower,
        "high": high,
        "anchor": anchor,
        "from_now": from_now,
        "fetch": page_limit + 1 if live else query.limit + 1,
        "offset": query.offset,
        "plan": tenant.plan,
        "retention": tenant.data_retention_days,
        "subscription": tenant.subscription_status,
    }
    # UserSession is rechecked by the browser auth dependency; group recall is API-only.
    # Management browser reads don't use this statement.
    ctes = f"""
    WITH actor AS MATERIALIZED (
      SELECT u.* FROM public.users u JOIN public.tenants t ON t.id=u.tenant_id
      WHERE u.id=:uid AND u.tenant_id=:tid AND u.removed_at IS NULL AND t.status='active'
        AND t.plan=:plan AND t.data_retention_days=:retention
        AND t.subscription_status=:subscription
      AND EXISTS (SELECT 1 FROM public.api_keys k WHERE k.key_id=:key
        AND k.user_id=u.id AND k.tenant_id=t.id AND k.revoked_at IS NULL
        AND (k.expires_at IS NULL OR k.expires_at>now()) AND 'search'=ANY(k.scopes))
    ), g AS MATERIALIZED (
      SELECT mg.*, a.role FROM public.machine_groups mg CROSS JOIN actor a
      WHERE mg.id=:gid AND mg.tenant_id=:tid
        AND (mg.visibility='team' OR mg.owner_user_id=:uid)
    ), physical AS MATERIALIZED (
      SELECT d.*, coalesce(d.merged_into_device_id,d.id) AS canonical
      FROM public.devices d JOIN public.users u ON u.id=d.user_id
      WHERE u.tenant_id=:tid AND u.removed_at IS NULL
    ), origins AS MATERIALIZED (
      SELECT d.*, direct.state AS direct_state FROM physical d CROSS JOIN g
      LEFT JOIN public.machine_group_devices direct
        ON direct.group_id=g.id AND direct.device_record_id=d.id
      WHERE EXISTS (SELECT 1 FROM public.machine_group_devices m
        JOIN physical sibling ON sibling.id=m.device_record_id
        WHERE m.group_id=g.id AND sibling.canonical=d.canonical
        AND (NOT :live OR m.state='active'))
      AND (NOT :live OR (d.retired_at IS NULL AND d.removed_at IS NULL
        AND coalesce(direct.state,'active')='active'))
    ), selected_device AS MATERIALIZED (
      SELECT * FROM physical WHERE machine_id=:device
    ), project_filter AS MATERIALIZED (
      SELECT p.id FROM {schema}.projects p CROSS JOIN g
      WHERE (:mode='ids' AND p.id=ANY(:projects))
        OR (:mode='repo' AND p.repo_group_key=:repo)
        OR (:mode='default' AND (
          (g.project_selector->>'kind'='project_id' AND p.id=g.project_selector->>'value')
          OR (g.project_selector->>'kind'='repo_group_key'
            AND p.repo_group_key=g.project_selector->>'value')))
    ), meta AS MATERIALIZED (
      SELECT g.*,
        (:mode='all' OR (:mode='default' AND g.project_selector IS NULL)) AS all_projects,
        ARRAY(SELECT id FROM project_filter ORDER BY id) AS project_ids,
        (SELECT count(*) FROM selected_device) AS device_matches,
        (:joined IS NULL OR EXISTS (
          SELECT 1 FROM physical d JOIN public.machine_group_devices m ON m.device_record_id=d.id
          WHERE m.group_id=g.id AND m.state='active' AND d.user_id=:uid
          AND d.machine_id=:joined AND d.identity_instance_id=:instance
          AND d.retired_at IS NULL AND d.removed_at IS NULL)) AS joined_ok,
        coalesce(CAST(:high AS bigint),
          (SELECT coalesce(max(server_sequence),0) FROM {schema}.transcript_entries)) AS frontier
      FROM g
    ), eligible AS NOT MATERIALIZED (
      SELECT e.*, d.id AS device_record_id, d.canonical AS canonical_record_id,
        coalesce(d.display_name,d.machine_name) AS device_label,
        (d.retired_at IS NOT NULL OR d.direct_state='retired') AS retired,
        u.name AS author_name, p.name AS project_name, d.last_seen_at, d.last_sync_at
      FROM {schema}.transcript_entries e
      JOIN origins d ON d.machine_id=e.uploaded_by_device_id AND d.user_id=e.uploaded_by_user_id
      JOIN public.users u ON u.id=e.uploaded_by_user_id
      LEFT JOIN {schema}.projects p ON p.id=e.project_id CROSS JOIN meta m
      WHERE (m.all_projects OR e.project_id=ANY(m.project_ids))
        AND (NOT :mine OR e.uploaded_by_user_id=:uid)
        AND (m.role IN ('owner','admin') OR e.uploaded_by_user_id=:uid OR
          (m.role='member' AND NOT m.all_projects AND EXISTS (
            SELECT 1 FROM {schema}.project_team_shares s
            WHERE s.project_id=e.project_id AND s.user_id=e.uploaded_by_user_id)))
        AND (:device IS NULL OR d.canonical IN
             (SELECT canonical FROM selected_device))
        AND (CAST(:since AS bigint) IS NULL OR e.timestamp>=:since)
        AND (CAST(:until AS bigint) IS NULL OR e.timestamp<=:until)
        AND e.timestamp>=:cutoff
        AND (cardinality(:kinds)=0 OR e.kind=ANY(:kinds))
        AND (:transcript IS NULL OR e.transcript_id=:transcript)
        AND (e.session_id IS NULL OR NOT e.session_id=ANY(:exclude_sessions))
    )
    """
    # UTF-8 previews are truncated again in Python after the bounded SQL fetch.
    fields = """
      e.id AS entry_id, e.transcript_id, e.project_id, e.session_id, e.kind, e.timestamp,
      e.server_sequence, e.uploaded_by_device_id AS device_id, e.device_record_id,
      e.canonical_record_id,
      left(e.uploaded_by_device_name,256) AS origin_device_name,
      left(e.device_label,256) AS device_label, e.retired,
      e.uploaded_by_user_id AS author_user_id, left(e.author_name,256) AS author_name,
      (e.uploaded_by_user_id=:uid) AS is_own, left(e.project_name,256) AS project_name,
      octet_length(coalesce(e.content,'')) AS content_byte_size,
      left(coalesce(e.content,''),2048) AS preview,
      e.last_seen_at, e.last_sync_at AS last_push_at
    """
    if anchor is not None:
        fields += (
            ", left(coalesce(e.content,''),16384) AS content"
            if context
            else (", left(coalesce(e.content,''),131072) AS content")
        )
        if context:
            # Select individually-authorized neighbors, bounded around the anchor.
            ctes += ", anchor AS (SELECT * FROM eligible WHERE id=:anchor)"
            rows = f"""SELECT {fields} FROM eligible e CROSS JOIN anchor a
              WHERE e.transcript_id=a.transcript_id
              ORDER BY abs(e.server_sequence-a.server_sequence), e.server_sequence
              LIMIT 42 OFFSET :offset"""
        else:
            rows = f"SELECT {fields} FROM eligible e WHERE e.id=:anchor"
    elif live:
        direction = "DESC" if snapshot else "ASC"
        rows = f"""SELECT {fields} FROM eligible e CROSS JOIN meta m
          WHERE NOT :from_now AND e.server_sequence>:lower AND e.server_sequence<=m.frontier
          AND (:query='' OR e.search_vector @@ plainto_tsquery('english',:query))
          ORDER BY e.server_sequence {direction} LIMIT :fetch"""
    else:
        rows = f"""SELECT {fields},
          ts_rank_cd(e.search_vector,plainto_tsquery('english',:query)) AS score
          FROM eligible e WHERE e.search_vector @@ plainto_tsquery('english',:query)
          ORDER BY score DESC,e.timestamp DESC,e.id LIMIT :fetch OFFSET :offset"""
    sql = (
        ctes
        + f""", page AS ({rows})
      SELECT (SELECT row_to_json(m) FROM meta m) AS metadata,
        coalesce((SELECT json_agg(p) FROM page p),'[]'::json) AS entries,
        EXISTS (SELECT 1 FROM eligible WHERE id=:anchor) AS anchor_ok
    """
    )
    return sql, params


async def read(
    db: AsyncSession,
    auth: AuthContext,
    tenant: Tenant,
    group: MachineGroup,
    schema: str,
    query: GroupQuery,
    *,
    live: bool = False,
    cursor: str = "",
    from_now: bool = False,
    page_limit: int = 200,
    anchor: str | None = None,
    context: bool = False,
    include_retired: bool = False,
    snapshot: bool = False,
) -> dict[str, Any]:
    start = time.monotonic()
    digest = scope_hash(auth, group, query) + (":inspection" if include_retired else "")
    previous = cursor_decode(cursor) if cursor else None
    if previous and previous.get("scope") != digest:
        fail("scope_changed", "Cursor belongs to a different scope; reset explicitly")
    if from_now and cursor:
        fail("invalid_cursor", "from_now cannot accompany a cursor", 400)
    sql, params = statement(
        schema,
        auth,
        tenant,
        group,
        query,
        live=live,
        lower=previous["position"] if previous else 0,
        high=previous.get("high") if previous else None,
        anchor=anchor,
        context=context,
        from_now=from_now,
        page_limit=page_limit,
        include_retired=include_retired,
        snapshot=snapshot,
    )
    query_sql = text(sql).bindparams(
        *[bindparam(name, type_=ARRAY(Text)) for name in ("projects", "kinds", "exclude_sessions")],
        *[bindparam(name, type_=Text) for name in ("joined", "device", "transcript")],
        bindparam("instance", type_=Uuid),
    )
    result = (await db.execute(query_sql, params)).one()
    meta = result.metadata
    if not meta:
        raise HTTPException(404, "Group or credentials no longer available")
    if previous and previous["revision"] != meta["revision"]:
        fail("scope_changed", "Group membership changed; reset or backfill explicitly")
    if not meta["joined_ok"]:
        fail("joined_membership_stale", "This installation is no longer an active group member")
    if query.device_id and meta["device_matches"] != 1:
        fail(
            "ambiguous_device" if meta["device_matches"] else "device_not_found",
            "Use an unambiguous exact physical device ID",
            400,
        )
    if (
        query.project_scope.mode == "default"
        and meta["project_selector"]
        and not meta["project_ids"]
    ):
        fail("project_not_found", "The group's associated project no longer exists", 404)
    if query.project_scope.this_worktree and not meta["project_ids"]:
        fail("unsupported_scope", "Cloud cannot represent this worktree exactly", 400)
    records = result.entries
    if anchor and not result.anchor_ok:
        raise HTTPException(404, "Entry not found in current group scope")
    limit = page_limit if live else 41 if context else 1 if anchor else query.limit
    has_more = len(records) > limit
    records = records[:limit]
    output: dict[str, Any] = {
        "contract_version": 1,
        "source": "cloud",
        "coverage": "synced_only",
        "group": {"id": meta["id"], "name": meta["name"], "revision": meta["revision"]},
        "resolved_scope": {
            "project_ids": meta["project_ids"],
            "all_projects": meta["all_projects"],
            "mine": query.mine,
            "device_id": query.device_id,
        },
        "entries": [],
        "has_more": has_more,
        "query_ms": 0.0,
    }
    # Reserve enough for the bounded scope envelope and signed cursor. Each
    # accepted record is measured as actually serialized JSON, never by chars.
    byte_count = len(encoded(output)) + 8192
    emitted = []
    for record in records:
        record["preview"] = record["preview"].encode()[:2048].decode("utf-8", errors="ignore")
        record["preview_truncated"] = len(record["preview"].encode()) < record["content_byte_size"]
        record["hydration_available"] = True
        size = len(encoded(record))
        if anchor and "content" in record:
            record["content_truncated"] = (
                len(record["content"].encode()) < record["content_byte_size"]
            )
            size = len(encoded(record))
        if not anchor and size > MAX_RECORD_BYTES:
            fail("data_inconsistent", "Entry metadata exceeds the record bound; cursor unchanged")
        if byte_count + size + 1 > MAX_PAGE_BYTES:
            has_more = True
            break
        emitted.append(record)
        byte_count += size + 1
    if records and not emitted:
        fail("data_inconsistent", "Entry cannot fit the page; cursor unchanged")
    output["entries"], output["has_more"] = emitted, has_more
    if live and not snapshot:
        position = emitted[-1]["server_sequence"] if has_more and emitted else meta["frontier"]
        if has_more and not emitted:
            fail("data_inconsistent", "Page cannot represent an entry; cursor unchanged")
        output["cursor"] = cursor_encode(
            {
                "v": 1,
                "scope": digest,
                "revision": meta["revision"],
                "position": position,
                "high": meta["frontier"] if has_more else None,
            }
        )
        output["captured_frontier"] = meta["frontier"]
        output["fresh_frontier"] = previous is None or previous.get("high") is None
        output["caught_up"] = output["fresh_frontier"] and not has_more
    elif not snapshot:
        output["next_offset"] = query.offset + len(emitted) if has_more else None
    if snapshot:
        output["snapshot"] = True
        output["include_retired"] = include_retired
        lanes: dict[tuple[str, str, str | None], dict[str, Any]] = {}
        for item in emitted:
            key = (item["canonical_record_id"], item["project_id"], item["session_id"])
            lane = lanes.setdefault(
                key,
                {
                    "device_id": item["device_id"],
                    "device_label": item["device_label"],
                    "project_id": item["project_id"],
                    "session_id": item["session_id"],
                    "latest_sequence": item["server_sequence"],
                    "last_seen_at": item["last_seen_at"],
                    "last_push_at": item["last_push_at"],
                    "entry_count_in_snapshot": 0,
                },
            )
            lane["entry_count_in_snapshot"] += 1
        output["lanes"] = list(lanes.values())
    output["query_ms"] = round((time.monotonic() - start) * 1000, 2)
    if len(encoded(output)) > MAX_PAGE_BYTES:
        fail("data_inconsistent", "Resolved scope exceeds the page bound; cursor unchanged")
    return output
