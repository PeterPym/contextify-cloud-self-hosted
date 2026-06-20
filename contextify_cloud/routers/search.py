"""Search endpoints - full-text search across cloud data.

Uses PostgreSQL tsvector + GIN index for fast ranked search with
ts_headline snippet extraction.
"""

import html
import logging
import re
import time
import uuid as uuid_mod
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from contextify_cloud.database import get_db
from contextify_cloud.middleware.auth import AuthContext
from contextify_cloud.middleware.endpoint_rate_limit import require_search_rate_limit
from contextify_cloud.models import Tenant
from contextify_cloud.schemas import SearchResponse, SearchResult
from contextify_cloud.services.tenant import get_tenant_schema
from contextify_cloud.services.user_scoping import build_user_scope_clause

logger = logging.getLogger(__name__)

_SCHEMA_NAME_RE = re.compile(r"^tenant_[a-z0-9_]+$")

router = APIRouter(prefix="/api/v1/search", tags=["search"])


@router.get("", response_model=SearchResponse)
async def search(
    q: str = Query(..., min_length=1, description="Search query"),
    project_id: str | None = Query(None, description="Filter by project"),
    team: bool = Query(
        False,
        description="Include a teammate's entries for this project when that teammate has "
        "shared their own entries for it (members only; requires project_id; per-contributor)",
    ),
    user_id: str | None = Query(None, description="Filter by user (admin only)"),
    since: str | None = Query(None, description="Filter entries after this date (YYYY-MM-DD)"),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    auth: Annotated[AuthContext, Depends(require_search_rate_limit)] = None,  # type: ignore[assignment]
    db: Annotated[AsyncSession, Depends(get_db)] = None,  # type: ignore[assignment]
) -> SearchResponse:
    """Full-text search across transcript entries.

    Uses PostgreSQL tsvector + GIN index for fast search.
    Results are ranked by ts_rank_cd relevance and include ts_headline
    snippets with <b>...</b> highlighting of matching terms. Snippet content
    is HTML-escaped to prevent XSS from user-provided transcript data.
    Results are scoped to the authenticated user's tenant.
    """
    start = time.monotonic()

    # Resolve tenant schema
    tenant = await db.execute(select(Tenant).where(Tenant.id == auth.tenant_id))
    tenant_obj = tenant.scalar_one_or_none()
    if not tenant_obj:
        raise HTTPException(status_code=404, detail="Tenant not found.")
    schema = get_tenant_schema(tenant_obj.slug)
    if not _SCHEMA_NAME_RE.match(schema):
        logger.error("Unsafe tenant schema name: %r", schema)
        raise HTTPException(status_code=500, detail="Internal configuration error.")

    # Build query filters
    params: dict[str, object] = {"query": q, "limit": limit, "offset": offset}

    where_clauses = ["e.search_vector @@ plainto_tsquery('english', :query)"]

    # Normalize project_id once: an empty/whitespace `?project_id=` binds as "" (not None).
    # The project WHERE fragment AND the ct-2250 team-widening gate below MUST key off the SAME
    # normalized value. Otherwise an empty project_id trips the widening gate (`"" is not None`
    # is True) while skipping the project bound (`if project_id:` is falsy) -- which would drop
    # member scoping entirely for a tenant-wide read. Treat blank as absent everywhere so the
    # gate and the filter can never disagree. Strip FIRST, then collapse to None: a
    # whitespace-only "  " must become None, not "" (the `x.strip() if x else None` ordering
    # leaves "  " -> "", which still trips the gate). (dual review-loop P0, ct-2250)
    project_id = (project_id or "").strip() or None
    if project_id:
        where_clauses.append("e.project_id = :project_id")
        params["project_id"] = project_id

    # Scope by user role using the shared utility (consistent with other endpoints).
    # Members/viewers can only see their own entries.
    # Owners/admins see all; they can optionally filter by user_id param.
    #
    # ct-2250 (per-user share): team-aware recall is gated PER CONTRIBUTOR, not per project and
    # not on corpus membership. Each user controls whether THEIR OWN entries for a project are
    # team-visible via a row in {schema}.project_team_shares (default: unshared/no row). A MEMBER
    # (not viewer, not owner/admin) who opts in (team=True) AND targets a specific project
    # (project_id) sees their OWN rows plus rows whose AUTHOR has shared that project -- and
    # nothing else. So one user's share exposes only that user's entries; no one else's data is
    # touched by it (no co-contributor exposure, no discovery/consent complexity). The share set
    # is read on every query, so un-share (DELETE) takes effect immediately. team defaults False
    # so existing callers are unchanged. Viewers/no-project/empty-project stay own-only;
    # owners/admins already see all via build_user_scope_clause.
    team_eligible = team and project_id is not None and auth.role == "member"
    if team_eligible:
        logger.info(
            "Team-aware search (per-user share): tenant=%s user=%s project=%s",
            auth.tenant_id, auth.user_id, project_id,
        )
        # Own rows OR rows whose author shared THIS project. Bound, not a tenant-wide widen.
        where_clauses.append(
            "(e.uploaded_by_user_id = :scope_user_id OR e.uploaded_by_user_id IN "
            f"(SELECT user_id FROM {schema}.project_team_shares WHERE project_id = :share_pid))"
        )
        params["scope_user_id"] = str(auth.user_id)
        params["share_pid"] = project_id
    else:
        scope_clause, scope_params = build_user_scope_clause(
            auth, column="e.uploaded_by_user_id", param_name="scope_user_id"
        )
        if scope_clause:
            where_clauses.append(scope_clause.removeprefix("AND ").strip())
            params.update(scope_params)
        elif user_id:
            # Full-access users can optionally filter by a specific user.
            # Validate as UUID to avoid DB errors on bad input.
            try:
                uuid_mod.UUID(user_id)
            except ValueError:
                raise HTTPException(
                    status_code=400, detail="Invalid user_id format. Expected a UUID."
                )
            where_clauses.append("e.uploaded_by_user_id = :scope_user_id")
            params["scope_user_id"] = user_id

    if since:
        try:
            since_dt = datetime.strptime(since, "%Y-%m-%d").replace(tzinfo=UTC)
        except ValueError:
            raise HTTPException(
                status_code=400, detail="Invalid date format for 'since'. Expected YYYY-MM-DD."
            )
        params["since_epoch"] = int(since_dt.timestamp())
        where_clauses.append("e.timestamp >= :since_epoch")

    where_sql = " AND ".join(where_clauses)

    # Count total matching results (for pagination metadata)
    count_sql = f"""
        SELECT COUNT(*)
        FROM {schema}.transcript_entries e
        WHERE {where_sql}
    """
    count_params = {k: v for k, v in params.items() if k not in ("limit", "offset")}
    count_result = await db.execute(text(count_sql), count_params)
    total = count_result.scalar() or 0

    # Fetch results with ranking and ts_headline snippet extraction.
    # ts_headline generates a short excerpt with sentinel markers around matched terms.
    # We use non-HTML sentinels (__HS__/__HE__) so we can HTML-escape the snippet
    # in Python before replacing sentinels with <b>/<\/b>, preventing XSS from
    # user-provided transcript content.
    search_sql = f"""
        SELECT e.id, e.content, e.kind, e.timestamp,
               ts_rank_cd(e.search_vector, plainto_tsquery('english', :query)) as score,
               ts_headline(
                   'english', coalesce(e.content, ''), plainto_tsquery('english', :query),
                   'StartSel=__HS__, StopSel=__HE__, MaxWords=60, MinWords=20, MaxFragments=3'
               ) as snippet,
               e.project_id, p.name as project_name,
               e.transcript_id,
               u.name as user_name, u.email as user_email,
               (e.uploaded_by_user_id = :auth_uid) as is_own
        FROM {schema}.transcript_entries e
        LEFT JOIN {schema}.projects p ON e.project_id = p.id
        LEFT JOIN public.users u ON e.uploaded_by_user_id = u.id
        WHERE {where_sql}
        ORDER BY score DESC, e.timestamp DESC
        LIMIT :limit OFFSET :offset
    """

    # Bind the caller id for the per-row is_own provenance flag (search query only; the
    # count query above does not reference it).
    params["auth_uid"] = str(auth.user_id)
    result = await db.execute(text(search_sql), params)
    rows = result.fetchall()

    results = []
    for row in rows:
        # Truncate full content for response (optional field for clients)
        content = row.content or ""
        if len(content) > 500:
            content = content[:500] + "..."

        # XSS-safe snippet: HTML-escape user content, then replace sentinels
        # with <b>/<\/b> tags for highlighting. This ensures user-provided
        # transcript content cannot inject markup or scripts.
        raw_snippet = row.snippet or ""
        safe_snippet = html.escape(raw_snippet)
        safe_snippet = safe_snippet.replace("__HS__", "<b>").replace("__HE__", "</b>")

        results.append(SearchResult(
            entry_id=row.id,
            kind=row.kind,
            timestamp=row.timestamp,
            project_id=row.project_id,
            transcript_id=row.transcript_id,
            snippet=safe_snippet,
            score=row.score,
            content=content,
            project_name=row.project_name,
            user_name=row.user_name,
            user_email=row.user_email,
            is_own=bool(row.is_own),
        ))

    elapsed_ms = (time.monotonic() - start) * 1000

    logger.info(
        "Search: tenant=%s user=%s role=%s query=%r results=%d total=%d ms=%.1f",
        auth.tenant_id, auth.user_id, auth.role, q, len(results), total, elapsed_ms,
    )

    return SearchResponse(
        results=results,
        total_count=total,
        limit=limit,
        offset=offset,
        has_more=(offset + limit) < total,
        query_ms=round(elapsed_ms, 2),
    )
