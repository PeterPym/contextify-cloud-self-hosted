"""Activity feed service for the team dashboard.

Queries TranscriptEntry records from tenant schemas with joined Project
and User info, supporting pagination, filtering, and role-based visibility.
"""

import logging
from dataclasses import dataclass
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from contextify_cloud.middleware.auth import AuthContext
from contextify_cloud.services.tenant_schema import resolve_schema
from contextify_cloud.services.user_scoping import build_user_scope_clause

logger = logging.getLogger(__name__)

# Valid kind values for filtering
VALID_KINDS = frozenset({"user", "assistant", "system", "summary"})


@dataclass
class ActivityItem:
    """A single activity feed entry with joined project and user info."""

    entry_id: str
    kind: str
    timestamp: int
    content_snippet: str
    project_id: str
    project_name: str | None
    user_name: str | None
    user_email: str | None


@dataclass
class ActivityFeedResult:
    """Paginated activity feed result."""

    items: list[ActivityItem]
    total_count: int
    has_more: bool


async def get_activity_feed(
    auth: AuthContext,
    db: AsyncSession,
    *,
    limit: int = 20,
    offset: int = 0,
    project_id: str | None = None,
    project_ids: list[str] | None = None,
    kind: str | None = None,
) -> ActivityFeedResult:
    """Fetch the activity feed for the authenticated user's tenant.

    Returns TranscriptEntry records in reverse chronological order, joined
    with Project and User info. Supports filtering by project and kind.

    Role-based visibility:
      - owner/admin: see all tenant activity
      - member/viewer: see only their own entries

    Args:
        auth: The authenticated user context.
        db: The async database session.
        limit: Maximum number of items to return (1-100).
        offset: Number of items to skip for pagination.
        project_id: Optional single project ID filter.
        project_ids: Optional list of project IDs for grouped views.
        kind: Optional entry kind filter (user, assistant, system, summary).

    Returns:
        ActivityFeedResult with items, total_count, and has_more flag.
    """
    schema = await resolve_schema(auth, db)

    # Build WHERE clauses
    where_clauses = ["1=1"]
    params: dict[str, object] = {"limit": limit, "offset": offset}

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

    # Kind filter
    if kind and kind in VALID_KINDS:
        where_clauses.append("e.kind = :kind")
        params["kind"] = kind

    where_sql = " AND ".join(where_clauses)

    # Count total matching entries (exclude pagination params)
    count_params = {k: v for k, v in params.items() if k not in ("limit", "offset")}
    count_result = await db.execute(
        text(
            f"SELECT COUNT(*) FROM {schema}.transcript_entries e "
            f"WHERE {where_sql}"
        ),
        count_params,
    )
    total_count = count_result.scalar() or 0

    # Fetch paginated entries with project and user info
    entries_params = {**params, "tenant_id": auth.tenant_id}
    entries_result = await db.execute(
        text(
            f"SELECT e.id, e.kind, e.timestamp, LEFT(e.content, 200) AS content, "
            f"e.project_id, p.name AS project_name, "
            f"u.name AS user_name, u.email AS user_email "
            f"FROM {schema}.transcript_entries e "
            f"LEFT JOIN {schema}.projects p ON e.project_id = p.id "
            f"LEFT JOIN public.users u "
            f"  ON u.id = e.uploaded_by_user_id "
            f"  AND u.tenant_id = :tenant_id "
            f"  AND u.removed_at IS NULL "
            f"WHERE {where_sql} "
            f"ORDER BY e.timestamp DESC "
            f"LIMIT :limit OFFSET :offset"
        ),
        entries_params,
    )

    items = []
    for row in entries_result.fetchall():
        items.append(ActivityItem(
            entry_id=row.id,
            kind=row.kind,
            timestamp=row.timestamp,
            content_snippet=row.content or "",
            project_id=row.project_id,
            project_name=row.project_name,
            user_name=row.user_name,
            user_email=row.user_email,
        ))

    has_more = (offset + limit) < total_count

    logger.info(
        "Activity feed: tenant=%s user=%s role=%s items=%d total=%d",
        auth.tenant_id, auth.user_id, auth.role, len(items), total_count,
    )

    return ActivityFeedResult(
        items=items,
        total_count=total_count,
        has_more=has_more,
    )


async def get_new_activity_entries(
    auth: AuthContext,
    db: AsyncSession,
    *,
    since_timestamp: int,
    exclude_ids: list[str] | None = None,
    project_id: str | None = None,
    project_ids: list[str] | None = None,
    kind: str | None = None,
    limit: int = 50,
) -> ActivityFeedResult:
    """Fetch activity entries newer than `since_timestamp`.

    Used by the live polling endpoint to return only new entries since
    the client last checked. Returns entries ordered by timestamp DESC
    with no offset (always starts from the newest).

    Uses a compound cursor: entries with timestamp > since_timestamp are
    always included. Entries with timestamp = since_timestamp are included
    only if their ID is not in exclude_ids. This prevents same-second
    entries from being missed while keeping X-New-Count accurate.

    Args:
        auth: The authenticated user context.
        db: The async database session.
        since_timestamp: Unix timestamp cursor.
        exclude_ids: Entry IDs at the watermark timestamp to exclude.
        project_id: Optional single project ID filter.
        project_ids: Optional list of project IDs for grouped views.
        kind: Optional entry kind filter (user, assistant, system, summary).
        limit: Maximum number of new items to return (1-50).

    Returns:
        ActivityFeedResult with new items, total_count, and has_more=True
        when the poll window overflowed `limit`.
    """
    schema = await resolve_schema(auth, db)

    # Build compound cursor: timestamp > T OR (timestamp = T AND id NOT IN excluded)
    if exclude_ids:
        excl_placeholders = []
        excl_params: dict[str, object] = {}
        for idx, eid in enumerate(exclude_ids[:100]):  # Cap to prevent query bloat
            key = f"excl_id_{idx}"
            excl_params[key] = eid
            excl_placeholders.append(f":{key}")
        cursor_clause = (
            f"(e.timestamp > :since_timestamp OR "
            f"(e.timestamp = :since_timestamp AND e.id NOT IN ({', '.join(excl_placeholders)})))"
        )
    else:
        cursor_clause = "e.timestamp > :since_timestamp"
        excl_params = {}

    where_clauses = [cursor_clause]
    params: dict[str, object] = {
        "since_timestamp": since_timestamp,
        "limit": limit,
        **excl_params,
    }

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

    # Kind filter
    if kind and kind in VALID_KINDS:
        where_clauses.append("e.kind = :kind")
        params["kind"] = kind

    where_sql = " AND ".join(where_clauses)

    # Count new entries
    count_params = {k: v for k, v in params.items() if k != "limit"}
    count_result = await db.execute(
        text(
            f"SELECT COUNT(*) FROM {schema}.transcript_entries e "
            f"WHERE {where_sql}"
        ),
        count_params,
    )
    total_count = count_result.scalar() or 0

    if total_count == 0:
        return ActivityFeedResult(items=[], total_count=0, has_more=False)

    # Fetch new entries with project and user info
    entries_params = {**params, "tenant_id": auth.tenant_id}
    entries_result = await db.execute(
        text(
            f"SELECT e.id, e.kind, e.timestamp, LEFT(e.content, 200) AS content, "
            f"e.project_id, p.name AS project_name, "
            f"u.name AS user_name, u.email AS user_email "
            f"FROM {schema}.transcript_entries e "
            f"LEFT JOIN {schema}.projects p ON e.project_id = p.id "
            f"LEFT JOIN public.users u "
            f"  ON u.id = e.uploaded_by_user_id "
            f"  AND u.tenant_id = :tenant_id "
            f"  AND u.removed_at IS NULL "
            f"WHERE {where_sql} "
            f"ORDER BY e.timestamp DESC "
            f"LIMIT :limit"
        ),
        entries_params,
    )

    items = []
    for row in entries_result.fetchall():
        items.append(ActivityItem(
            entry_id=row.id,
            kind=row.kind,
            timestamp=row.timestamp,
            content_snippet=row.content or "",
            project_id=row.project_id,
            project_name=row.project_name,
            user_name=row.user_name,
            user_email=row.user_email,
        ))

    logger.info(
        "New activity entries: tenant=%s user=%s since=%d count=%d",
        auth.tenant_id, auth.user_id, since_timestamp, len(items),
    )

    return ActivityFeedResult(
        items=items,
        total_count=total_count,
        has_more=total_count > len(items),
    )


async def get_project_options(
    auth: AuthContext,
    db: AsyncSession,
) -> list[tuple[str, str]]:
    """Fetch project ID/name pairs for the filter dropdown.

    Returns a list of (project_id, project_name) tuples, sorted by name.
    Respects role-based visibility.
    """
    schema = await resolve_schema(auth, db)

    scope_clause, scope_params = build_user_scope_clause(
        auth, column="e.uploaded_by_user_id", param_name="scope_user_id"
    )

    if auth.has_full_access:
        result = await db.execute(
            text(
                f"SELECT id, COALESCE(name, id) AS name "
                f"FROM {schema}.projects "
                f"ORDER BY name"
            )
        )
    else:
        # Members only see projects they have entries in
        result = await db.execute(
            text(
                f"SELECT DISTINCT p.id, COALESCE(p.name, p.id) AS name "
                f"FROM {schema}.projects p "
                f"INNER JOIN {schema}.transcript_entries e ON p.id = e.project_id "
                f"WHERE e.uploaded_by_user_id = :scope_user_id "
                f"ORDER BY name"
            ),
            scope_params,
        )

    return [(row.id, row.name) for row in result.fetchall()]


def _pick_group_display_name(
    group_id: str,
    rows: list[Any],
) -> str:
    """Pick the best display name for a logical project group.

    Prefers the primary (non-worktree) row's repo_name or project_name,
    since worktree rows often have suffixed names like "contextify-wb3".
    Appends a worktree count annotation for multi-member groups.
    """
    # First pass: look for a non-worktree row with a repo_name
    base_name = group_id
    for row in rows:
        if not row.is_worktree and row.repo_name:
            base_name = row.repo_name
            break
    else:
        # Second pass: any non-worktree row with a project_name
        for row in rows:
            if not row.is_worktree and row.project_name:
                base_name = row.project_name
                break
        else:
            # Third pass: any row with a repo_name (even worktree)
            for row in rows:
                if row.repo_name:
                    base_name = row.repo_name
                    break
            else:
                # Fourth pass: any project_name
                for row in rows:
                    if row.project_name:
                        base_name = row.project_name
                        break

    if len(rows) > 1:
        return f"{base_name} ({len(rows)} worktrees)"
    return base_name


async def get_grouped_project_options(
    auth: AuthContext,
    db: AsyncSession,
) -> list[tuple[str, str]]:
    """Fetch worktree-consolidated project options for the filter dropdown.

    Groups worktree siblings under their logical project ID using the same
    grouping logic as the Projects page. Returns (logical_project_id, display_name)
    tuples sorted by display_name.
    """
    from contextify_cloud.services.projects import (
        build_logical_project_groups,
        fetch_visible_project_rows,
    )

    visible_projects = await fetch_visible_project_rows(auth, db)
    groups = build_logical_project_groups(visible_projects)

    consolidated: list[tuple[str, str]] = []
    singles: list[tuple[str, str]] = []
    for group_id, group in groups.items():
        name = _pick_group_display_name(group_id, group.rows)
        if len(group.rows) > 1:
            consolidated.append((group_id, name))
        else:
            singles.append((group_id, name))

    consolidated.sort(key=lambda x: x[1].lower())
    singles.sort(key=lambda x: x[1].lower())

    options: list[tuple[str, str]] = consolidated
    if consolidated and singles:
        options.append(("__separator__", "───"))
    options.extend(singles)
    return options


async def resolve_project_filter(
    auth: AuthContext,
    db: AsyncSession,
    project_id: str | None,
) -> list[str] | None:
    """Resolve a logical project ID to its member project IDs.

    If the project_id matches a logical group (repo_group_key or repo_identity),
    returns all member project_ids. If it matches a single project directly,
    returns [project_id]. Returns None if no filter is set.
    """
    if not project_id:
        return None

    from contextify_cloud.services.projects import (
        build_logical_project_groups,
        fetch_visible_project_rows,
    )

    visible_projects = await fetch_visible_project_rows(auth, db)
    groups = build_logical_project_groups(visible_projects)

    if project_id in groups:
        return [row.project_id for row in groups[project_id].rows]

    # Check aliases
    for group in groups.values():
        if project_id in group.aliases:
            return [row.project_id for row in group.rows]

    # Back-compat for legacy deep links that still use a physical project_id,
    # but only when that project is actually visible to this auth context.
    visible_project_ids = {row.project_id for row in visible_projects}
    if project_id in visible_project_ids:
        return [project_id]
    return []


async def resolve_project_filter_with_options(
    auth: AuthContext,
    db: AsyncSession,
    project_id: str | None,
) -> tuple[list[tuple[str, str]], list[str] | None]:
    """Fetch grouped project options and resolve filter in a single DB round trip.

    Returns (dropdown_options, resolved_project_ids) by fetching visible projects
    once and deriving both values from the same dataset.
    """
    from contextify_cloud.services.projects import (
        build_logical_project_groups,
        fetch_visible_project_rows,
    )

    visible_projects = await fetch_visible_project_rows(auth, db)
    groups = build_logical_project_groups(visible_projects)

    # Build dropdown options (consolidated first, then separator, then singles)
    consolidated: list[tuple[str, str]] = []
    singles: list[tuple[str, str]] = []
    for group_id, group in groups.items():
        name = _pick_group_display_name(group_id, group.rows)
        if len(group.rows) > 1:
            consolidated.append((group_id, name))
        else:
            singles.append((group_id, name))
    consolidated.sort(key=lambda x: x[1].lower())
    singles.sort(key=lambda x: x[1].lower())
    options: list[tuple[str, str]] = consolidated
    if consolidated and singles:
        options.append(("__separator__", "───"))
    options.extend(singles)

    # Resolve filter
    if not project_id:
        return options, None

    if project_id in groups:
        return options, [row.project_id for row in groups[project_id].rows]

    for group in groups.values():
        if project_id in group.aliases:
            return options, [row.project_id for row in group.rows]

    visible_project_ids = {row.project_id for row in visible_projects}
    if project_id in visible_project_ids:
        return options, [project_id]
    return options, []
