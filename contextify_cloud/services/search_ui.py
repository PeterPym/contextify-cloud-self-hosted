"""Search service for the dashboard web UI.

Wraps PostgreSQL full-text search for the dashboard, reusing the same
tenant-schema pattern as the activity service. Returns dataclass results
suitable for Jinja2 template rendering.

Uses ts_headline for snippet extraction with XSS-safe sentinel markers,
and ts_rank_cd for relevance ranking.
"""

import html
import logging
import time
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from contextify_cloud.middleware.auth import AuthContext
from contextify_cloud.services.tenant_schema import resolve_schema
from contextify_cloud.services.user_scoping import build_user_scope_clause

logger = logging.getLogger(__name__)


@dataclass
class SearchResultItem:
    """A single search result with highlighted snippet and metadata."""

    entry_id: str
    kind: str
    timestamp: int
    snippet: str  # HTML-safe snippet with <b> highlighting
    project_id: str
    project_name: str | None
    transcript_id: str | None
    user_name: str | None
    user_email: str | None
    score: float


@dataclass
class SearchFeedResult:
    """Paginated search results with metadata."""

    items: list[SearchResultItem]
    total_count: int
    has_more: bool
    query_ms: float


async def search_entries(
    auth: AuthContext,
    db: AsyncSession,
    *,
    query: str,
    limit: int = 20,
    offset: int = 0,
    project_id: str | None = None,
    project_ids: list[str] | None = None,
    since: str | None = None,
    until: str | None = None,
) -> SearchFeedResult:
    """Full-text search across transcript entries for the dashboard.

    Uses PostgreSQL tsvector + GIN index for fast ranked search with
    ts_headline snippet extraction. Results are scoped to the tenant
    and filtered by role-based visibility.

    Args:
        auth: The authenticated user context.
        db: The async database session.
        query: The search query string.
        limit: Maximum number of results to return (1-100).
        offset: Number of results to skip for pagination.
        project_id: Optional single project ID filter.
        project_ids: Optional list of project IDs for grouped views.
        since: Optional start date filter (YYYY-MM-DD).
        until: Optional end date filter (YYYY-MM-DD).

    Returns:
        SearchFeedResult with items, total_count, has_more, and query_ms.
    """
    start = time.monotonic()

    schema = await resolve_schema(auth, db)

    # Build WHERE clauses
    where_clauses = ["e.search_vector @@ plainto_tsquery('english', :query)"]
    params: dict[str, object] = {"query": query, "limit": limit, "offset": offset}

    # User scoping: members see only their own entries
    scope_clause, scope_params = build_user_scope_clause(
        auth, column="e.uploaded_by_user_id", param_name="scope_user_id"
    )
    if scope_clause:
        where_clauses.append(scope_clause.removeprefix("AND ").strip())
    params.update(scope_params)

    # Project filter
    if project_ids is not None:
        if not project_ids:
            where_clauses.append("1=0")
        else:
            placeholders = []
            for index, grouped_project_id in enumerate(project_ids):
                key = f"project_id_{index}"
                params[key] = grouped_project_id
                placeholders.append(f":{key}")
            where_clauses.append(f"e.project_id IN ({', '.join(placeholders)})")
    elif project_id:
        where_clauses.append("e.project_id = :project_id")
        params["project_id"] = project_id

    # Date range filters
    if since:
        from datetime import UTC, datetime

        try:
            since_dt = datetime.strptime(since, "%Y-%m-%d").replace(tzinfo=UTC)
            params["since_epoch"] = int(since_dt.timestamp())
            where_clauses.append("e.timestamp >= :since_epoch")
        except ValueError:
            pass  # Silently ignore invalid dates in UI

    if until:
        from datetime import UTC, datetime

        try:
            until_dt = datetime.strptime(until, "%Y-%m-%d").replace(tzinfo=UTC)
            # End of day: add 86400 seconds (one day)
            params["until_epoch"] = int(until_dt.timestamp()) + 86400
            where_clauses.append("e.timestamp < :until_epoch")
        except ValueError:
            pass  # Silently ignore invalid dates in UI

    where_sql = " AND ".join(where_clauses)

    # Count total matching results
    count_sql = f"""
        SELECT COUNT(*)
        FROM {schema}.transcript_entries e
        WHERE {where_sql}
    """
    count_params = {k: v for k, v in params.items() if k not in ("limit", "offset")}
    count_result = await db.execute(text(count_sql), count_params)
    total = count_result.scalar() or 0

    # Fetch results with ranking and snippet extraction.
    # Uses non-HTML sentinels (__HS__/__HE__) so we can HTML-escape the snippet
    # in Python before replacing sentinels with <b>/<\/b>, preventing XSS.
    search_sql = f"""
        SELECT e.id, e.kind, e.timestamp,
               ts_rank_cd(e.search_vector, plainto_tsquery('english', :query)) as score,
               ts_headline(
                   'english', coalesce(e.content, ''), plainto_tsquery('english', :query),
                   'StartSel=__HS__, StopSel=__HE__, MaxWords=60, MinWords=20, MaxFragments=3'
               ) as snippet,
               e.project_id, p.name as project_name,
               e.transcript_id,
               u.name as user_name, u.email as user_email
        FROM {schema}.transcript_entries e
        LEFT JOIN {schema}.projects p ON e.project_id = p.id
        LEFT JOIN public.users u ON e.uploaded_by_user_id = u.id
        WHERE {where_sql}
        ORDER BY score DESC, e.timestamp DESC
        LIMIT :limit OFFSET :offset
    """

    result = await db.execute(text(search_sql), params)
    rows = result.fetchall()

    items = []
    for row in rows:
        # XSS-safe snippet: HTML-escape user content, then replace sentinels
        raw_snippet = row.snippet or ""
        safe_snippet = html.escape(raw_snippet)
        safe_snippet = safe_snippet.replace("__HS__", "<b>").replace("__HE__", "</b>")

        items.append(SearchResultItem(
            entry_id=row.id,
            kind=row.kind,
            timestamp=row.timestamp,
            snippet=safe_snippet,
            project_id=row.project_id,
            project_name=row.project_name,
            transcript_id=row.transcript_id,
            user_name=row.user_name,
            user_email=row.user_email,
            score=row.score,
        ))

    elapsed_ms = (time.monotonic() - start) * 1000
    has_more = (offset + limit) < total

    logger.info(
        "Search UI: tenant=%s user=%s role=%s query_len=%d results=%d total=%d ms=%.1f",
        auth.tenant_id, auth.user_id, auth.role, len(query), len(items), total, elapsed_ms,
    )
    logger.debug("Search UI query: %r", query)

    return SearchFeedResult(
        items=items,
        total_count=total,
        has_more=has_more,
        query_ms=round(elapsed_ms, 2),
    )
