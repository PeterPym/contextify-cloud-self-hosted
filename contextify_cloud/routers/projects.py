"""Project listing endpoints - browse projects and activity."""

import logging
import re
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from contextify_cloud.database import get_db
from contextify_cloud.middleware.auth import AuthContext, require_scope
from contextify_cloud.models import Tenant
from contextify_cloud.schemas import (
    ProjectActivityEntry,
    ProjectActivityResponse,
    ProjectContributor,
    ProjectContributorsResponse,
    ProjectDetail,
    ProjectSummary,
)
from contextify_cloud.services.tenant import get_tenant_schema
from contextify_cloud.services.user_scoping import build_user_scope_clause

logger = logging.getLogger(__name__)

_SCHEMA_NAME_RE = re.compile(r"^tenant_[a-z0-9_]+$")

router = APIRouter(prefix="/api/v1/projects", tags=["projects"])


async def _resolve_schema(
    auth: AuthContext, db: AsyncSession
) -> str:
    """Resolve the tenant schema name for the authenticated user."""
    tenant = await db.execute(select(Tenant).where(Tenant.id == auth.tenant_id))
    tenant_obj = tenant.scalar_one_or_none()
    if not tenant_obj:
        raise HTTPException(status_code=404, detail="Tenant not found.")
    schema = get_tenant_schema(tenant_obj.slug)
    if not _SCHEMA_NAME_RE.match(schema):
        logger.error("Unsafe tenant schema name: %r", schema)
        raise HTTPException(status_code=500, detail="Internal configuration error.")
    return schema


async def _ensure_project_visible(
    *, auth: AuthContext, db: AsyncSession, schema: str, project_id: str
) -> None:
    """For non-full-access roles, verify the user has at least one entry in this project.

    Prevents project enumeration by members: they cannot distinguish
    "project exists but not visible" from "project does not exist".
    Full-access roles skip this check.

    Note: visibility is determined by transcript_entries, not transcripts.
    A member who has transcripts but no entries for a project will see 404.
    This is intentional: entries are the unit of user-contributed data.
    """
    if auth.has_full_access:
        return
    visible = await db.execute(
        text(
            f"SELECT 1 FROM {schema}.transcript_entries "
            "WHERE project_id = :project_id AND uploaded_by_user_id = :scope_user_id "
            "LIMIT 1"
        ),
        {"project_id": project_id, "scope_user_id": str(auth.user_id)},
    )
    if not visible.first():
        raise HTTPException(status_code=404, detail="Project not found.")


@router.get("", response_model=list[ProjectSummary])
async def list_projects(
    auth: Annotated[AuthContext, Depends(require_scope("sync", "search"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[ProjectSummary]:
    """List all projects for the authenticated tenant.

    Returns projects with aggregate stats: transcript count, entry count,
    and last activity timestamp.
    """
    schema = await _resolve_schema(auth, db)

    # User scoping: members only see projects they've contributed entries to.
    # Owners/admins see all projects.
    scope_clause, scope_params = build_user_scope_clause(
        auth, column="uploaded_by_user_id", param_name="scope_user_id"
    )

    # For members, the entry subquery filters by user, and we use INNER JOIN
    # so projects with zero entries from this user are excluded.
    # For full-access roles, scope_clause is empty and we use LEFT JOIN as before.
    entry_join = "LEFT JOIN" if auth.has_full_access else "INNER JOIN"

    # Transcript count subquery: for members, count only transcripts that have
    # at least one entry belonging to this user (scoped via JOIN through entries).
    # For full-access roles, count all transcripts in the project directly.
    if auth.has_full_access:
        transcript_count_subquery = f"""
            LEFT JOIN (
                SELECT project_id, COUNT(*) AS transcript_count
                FROM {schema}.transcripts
                GROUP BY project_id
            ) t_counts ON p.id = t_counts.project_id"""
    else:
        transcript_count_subquery = f"""
            LEFT JOIN (
                SELECT t.project_id, COUNT(DISTINCT t.id) AS transcript_count
                FROM {schema}.transcripts t
                INNER JOIN {schema}.transcript_entries e ON t.id = e.transcript_id
                WHERE e.uploaded_by_user_id = :scope_user_id
                GROUP BY t.project_id
            ) t_counts ON p.id = t_counts.project_id"""

    result = await db.execute(text(f"""
        SELECT
            p.id,
            p.name,
            p.root_path,
            COALESCE(t_counts.transcript_count, 0) AS transcript_count,
            COALESCE(e_counts.entry_count, 0) AS entry_count,
            e_counts.last_activity
        FROM {schema}.projects p
        {transcript_count_subquery}
        {entry_join} (
            SELECT project_id, COUNT(*) AS entry_count, MAX(timestamp) AS last_activity
            FROM {schema}.transcript_entries
            WHERE 1=1 {scope_clause}
            GROUP BY project_id
        ) e_counts ON p.id = e_counts.project_id
        ORDER BY COALESCE(e_counts.last_activity, 0) DESC, p.name ASC
    """), scope_params)

    rows = result.fetchall()
    projects = []
    for row in rows:
        projects.append(ProjectSummary(
            id=row.id,
            name=row.name,
            root_path=row.root_path,
            transcript_count=row.transcript_count,
            entry_count=row.entry_count,
            last_activity=row.last_activity,
        ))

    logger.info(
        "List projects: tenant=%s user=%s count=%d",
        auth.tenant_id, auth.user_id, len(projects),
    )

    return projects


@router.get("/{project_id}", response_model=ProjectDetail)
async def get_project(
    project_id: str,
    auth: Annotated[AuthContext, Depends(require_scope("sync", "search"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ProjectDetail:
    """Get a single project with detailed stats.

    Returns project info including transcript count, entry count,
    last activity timestamp, and list of providers used.
    """
    schema = await _resolve_schema(auth, db)

    # For non-full-access roles, verify visibility before exposing any data.
    # Full-access roles use the standard project lookup.
    if auth.has_full_access:
        proj_result = await db.execute(text(f"""
            SELECT id, name, root_path FROM {schema}.projects WHERE id = :project_id
        """), {"project_id": project_id})
        proj_row = proj_result.first()
        if not proj_row:
            raise HTTPException(status_code=404, detail="Project not found.")
    else:
        await _ensure_project_visible(auth=auth, db=db, schema=schema, project_id=project_id)
        proj_result = await db.execute(text(f"""
            SELECT id, name, root_path FROM {schema}.projects WHERE id = :project_id
        """), {"project_id": project_id})
        proj_row = proj_result.first()
        if not proj_row:
            raise HTTPException(status_code=404, detail="Project not found.")

    # Fetch aggregate stats (scoped by user role)
    scope_clause, scope_params = build_user_scope_clause(
        auth, column="e.uploaded_by_user_id", param_name="scope_user_id"
    )
    stats_params: dict[str, object] = {"project_id": project_id, **scope_params}
    stats_result = await db.execute(text(f"""
        SELECT
            COALESCE(COUNT(DISTINCT t.id), 0) AS transcript_count,
            COALESCE(COUNT(e.id), 0) AS entry_count,
            MAX(e.timestamp) AS last_activity
        FROM {schema}.transcripts t
        LEFT JOIN {schema}.transcript_entries e ON t.id = e.transcript_id
        WHERE t.project_id = :project_id {scope_clause}
    """), stats_params)
    stats_row = stats_result.first()

    # Fetch distinct providers (scoped by user role to prevent leaking
    # provider info from other users' transcripts)
    providers_scope_clause, providers_scope_params = build_user_scope_clause(
        auth, column="e.uploaded_by_user_id", param_name="scope_user_id"
    )
    # Providers come from transcripts joined with entries for user scoping
    if auth.has_full_access:
        providers_result = await db.execute(text(f"""
            SELECT DISTINCT provider FROM {schema}.transcripts
            WHERE project_id = :project_id
            ORDER BY provider
        """), {"project_id": project_id})
    else:
        providers_result = await db.execute(text(f"""
            SELECT DISTINCT t.provider
            FROM {schema}.transcripts t
            INNER JOIN {schema}.transcript_entries e ON t.id = e.transcript_id
            WHERE t.project_id = :project_id {providers_scope_clause}
            ORDER BY t.provider
        """), {"project_id": project_id, **providers_scope_params})
    providers = [row.provider for row in providers_result.fetchall()]

    logger.info(
        "Get project: tenant=%s user=%s project=%s",
        auth.tenant_id, auth.user_id, project_id,
    )

    return ProjectDetail(
        id=proj_row.id,
        name=proj_row.name,
        root_path=proj_row.root_path,
        transcript_count=stats_row.transcript_count if stats_row else 0,
        entry_count=stats_row.entry_count if stats_row else 0,
        last_activity=stats_row.last_activity if stats_row else None,
        providers=providers,
    )


@router.get("/{project_id}/activity", response_model=ProjectActivityResponse)
async def get_project_activity(
    project_id: str,
    auth: Annotated[AuthContext, Depends(require_scope("sync", "search"))],
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=100, description="Max entries per page")] = 20,
    offset: Annotated[int, Query(ge=0, description="Number of entries to skip")] = 0,
    kinds: Annotated[
        str | None,
        Query(description="Comma-separated kind filter, e.g. 'user,assistant'"),
    ] = None,
) -> ProjectActivityResponse:
    """Get recent activity entries for a project.

    Returns paginated entries with content snippets (first 200 chars).
    Supports filtering by entry kind (user, assistant, system, summary).
    """
    schema = await _resolve_schema(auth, db)

    # Verify project exists and is visible to this user
    if auth.has_full_access:
        proj_check = await db.execute(text(f"""
            SELECT id FROM {schema}.projects WHERE id = :project_id
        """), {"project_id": project_id})
        if not proj_check.first():
            raise HTTPException(status_code=404, detail="Project not found.")
    else:
        await _ensure_project_visible(auth=auth, db=db, schema=schema, project_id=project_id)

    # Build kind filter (with user scoping)
    scope_clause, scope_params = build_user_scope_clause(
        auth, column="e.uploaded_by_user_id", param_name="scope_user_id"
    )
    where_clauses = ["e.project_id = :project_id"]
    params: dict[str, object] = {
        "project_id": project_id, "limit": limit, "offset": offset, **scope_params
    }

    # Add user scoping clause (empty for full-access roles)
    if scope_clause:
        # scope_clause starts with "AND " so strip it for use in where_clauses list
        where_clauses.append(scope_clause.removeprefix("AND ").strip())

    if kinds:
        kind_list = [k.strip() for k in kinds.split(",") if k.strip()]
        if kind_list:
            kind_placeholders = ", ".join(f":kind_{i}" for i in range(len(kind_list)))
            where_clauses.append(f"e.kind IN ({kind_placeholders})")
            for i, kind in enumerate(kind_list):
                params[f"kind_{i}"] = kind

    where_sql = " AND ".join(where_clauses)

    # Count total matching entries (exclude limit/offset which aren't in the count query)
    count_params = {k: v for k, v in params.items() if k not in ("limit", "offset")}
    count_result = await db.execute(text(f"""
        SELECT COUNT(*) FROM {schema}.transcript_entries e
        WHERE {where_sql}
    """), count_params)
    total_count = count_result.scalar() or 0

    # Fetch paginated entries
    entries_result = await db.execute(text(f"""
        SELECT e.id, e.kind, e.timestamp, e.content, e.transcript_id
        FROM {schema}.transcript_entries e
        WHERE {where_sql}
        ORDER BY e.timestamp DESC
        LIMIT :limit OFFSET :offset
    """), params)

    entries = []
    for row in entries_result.fetchall():
        content = row.content or ""
        snippet = content[:200] + "..." if len(content) > 200 else content
        entries.append(ProjectActivityEntry(
            id=row.id,
            kind=row.kind,
            timestamp=row.timestamp,
            content_snippet=snippet,
            transcript_id=row.transcript_id,
        ))

    has_more = (offset + limit) < total_count

    logger.info(
        "Project activity: tenant=%s user=%s project=%s entries=%d total=%d",
        auth.tenant_id, auth.user_id, project_id, len(entries), total_count,
    )

    return ProjectActivityResponse(
        entries=entries,
        total_count=total_count,
        has_more=has_more,
    )


def _quote_pg_identifier(identifier: str) -> str:
    """Validate and quote a PostgreSQL identifier (schema/table/column name)."""
    if not _SCHEMA_NAME_RE.fullmatch(identifier):
        logger.error("Invalid schema identifier: %r", identifier)
        raise HTTPException(
            status_code=500,
            detail="Internal configuration error.",
        )
    return f'"{identifier}"'


@router.get("/{project_id}/contributors", response_model=ProjectContributorsResponse)
async def get_project_contributors(
    project_id: str,
    auth: Annotated[AuthContext, Depends(require_scope("sync", "search"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ProjectContributorsResponse:
    """Get contributors for a project with entry counts.

    Owner/admin: see all contributors.
    Member/viewer: see only themselves if they contributed to this project.
    """
    schema = await _resolve_schema(auth, db)

    # Verify project exists and is visible
    await _ensure_project_visible(auth=auth, db=db, schema=schema, project_id=project_id)

    safe_schema = _quote_pg_identifier(schema)

    # Build query based on role
    scope_clause, scope_params = build_user_scope_clause(
        auth, column="e.uploaded_by_user_id", param_name="scope_user_id"
    )

    result = await db.execute(
        text(
            f"SELECT e.uploaded_by_user_id AS user_id, "
            f"u.email, u.name, u.role, "
            f"COUNT(*) AS entry_count, "
            f"MAX(e.timestamp) AS last_contribution "
            f"FROM {safe_schema}.transcript_entries e "
            f"LEFT JOIN public.users u "
            f"ON u.id = e.uploaded_by_user_id "
            f"AND u.tenant_id = :tenant_id "
            f"AND u.removed_at IS NULL "
            f"WHERE e.project_id = :project_id {scope_clause} "
            f"GROUP BY e.uploaded_by_user_id, u.email, u.name, u.role "
            f"ORDER BY entry_count DESC"
        ),
        {"project_id": project_id, "tenant_id": auth.tenant_id, **scope_params},
    )

    items = [
        ProjectContributor(
            user_id=str(row.user_id) if row.user_id is not None else "",
            email=row.email,
            name=row.name,
            role=row.role,
            entry_count=row.entry_count,
            last_contribution=row.last_contribution,
        )
        for row in result.fetchall()
    ]

    logger.info(
        "Project contributors: tenant=%s project=%s count=%d",
        auth.tenant_id, project_id, len(items),
    )

    return ProjectContributorsResponse(items=items)
