"""Project explorer service for the dashboard.

Queries projects with stats and contributor info from tenant schemas.
Supports role-based visibility: owners/admins see all projects,
members see only projects they have entries in.
"""

import logging
from dataclasses import dataclass, field

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from contextify_cloud.middleware.auth import AuthContext
from contextify_cloud.services.tenant_schema import resolve_schema
from contextify_cloud.services.user_scoping import build_user_scope_clause

logger = logging.getLogger(__name__)


@dataclass
class ProjectCard:
    """A grouped project card for the project list view."""

    project_id: str
    project_name: str | None
    entry_count: int
    last_activity: int | None
    worktree_count: int = 1


@dataclass
class Contributor:
    """A user who has synced data to a project."""

    user_id: str
    user_name: str | None
    user_email: str | None
    entry_count: int
    last_activity: int | None


@dataclass
class WorktreeProject:
    """A raw project/worktree inside a logical project grouping."""

    project_id: str
    project_name: str | None
    root_path: str
    worktree_name: str | None
    entry_count: int
    transcript_count: int
    last_activity: int | None


@dataclass
class ProjectDetailResult:
    """Full project detail with stats, contributors, and optional worktree drill-down."""

    project_id: str
    project_name: str | None
    entry_count: int
    transcript_count: int
    last_activity: int | None
    contributors: list[Contributor]
    root_path: str | None = None
    worktrees: list[WorktreeProject] = field(default_factory=list)
    is_logical_group: bool = False


@dataclass
class VisibleProjectRow:
    """A raw project row enriched with stats and grouping metadata."""

    project_id: str
    project_name: str | None
    root_path: str
    repo_group_key: str | None
    repo_identity: str | None
    repo_name: str | None
    worktree_name: str | None
    is_worktree: bool
    entry_count: int
    transcript_count: int
    last_activity: int | None


@dataclass
class LogicalProjectGroup:
    """Canonical logical project plus any legacy aliases that still resolve to it."""

    project_id: str
    rows: list[VisibleProjectRow] = field(default_factory=list)
    aliases: set[str] = field(default_factory=set)


def logical_project_id(
    repo_group_key: str | None,
    repo_identity: str | None,
    project_id: str,
) -> str:
    """Return the stable logical-project key used by grouped dashboard views."""
    return repo_group_key or repo_identity or project_id


def build_logical_project_groups(
    visible_projects: list[VisibleProjectRow],
) -> dict[str, LogicalProjectGroup]:
    """Group rows while bridging partially migrated repo_group_key state."""
    bridged_repo_group_keys: dict[str, set[str]] = {}
    for row in visible_projects:
        if row.repo_identity and row.repo_group_key:
            bridged_repo_group_keys.setdefault(row.repo_identity, set()).add(row.repo_group_key)

    groups: dict[str, LogicalProjectGroup] = {}
    for row in visible_projects:
        effective_group_key = row.repo_group_key
        if row.repo_identity:
            known_group_keys = bridged_repo_group_keys.get(row.repo_identity, set())
            if len(known_group_keys) == 1:
                effective_group_key = next(iter(known_group_keys))
            elif len(known_group_keys) > 1:
                effective_group_key = row.repo_identity

        grouped_project_id = logical_project_id(
            effective_group_key,
            row.repo_identity,
            row.project_id,
        )
        group = groups.setdefault(
            grouped_project_id,
            LogicalProjectGroup(project_id=grouped_project_id),
        )
        group.rows.append(row)

        if row.repo_identity and row.repo_identity != grouped_project_id:
            group.aliases.add(row.repo_identity)
        if row.repo_group_key and row.repo_group_key != grouped_project_id:
            group.aliases.add(row.repo_group_key)

    return groups


async def fetch_visible_project_rows(
    auth: AuthContext,
    db: AsyncSession,
) -> list[VisibleProjectRow]:
    """Fetch per-project stats with enough metadata for logical grouping."""
    schema = await resolve_schema(auth, db)

    scope_clause, scope_params = build_user_scope_clause(
        auth, column="e.uploaded_by_user_id", param_name="scope_user_id"
    )
    entry_join = "LEFT JOIN" if auth.has_full_access else "INNER JOIN"

    result = await db.execute(
        text(
            f"SELECT p.id, COALESCE(p.name, p.id) AS name, p.root_path, "
            f"p.repo_group_key, p.repo_identity, p.repo_name, p.worktree_name, p.is_worktree, "
            f"COALESCE(stats.entry_count, 0) AS entry_count, "
            f"COALESCE(stats.transcript_count, 0) AS transcript_count, "
            f"stats.last_activity "
            f"FROM {schema}.projects p "
            f"{entry_join} ("
            f"  SELECT project_id, COUNT(*) AS entry_count, "
            f"  COUNT(DISTINCT transcript_id) AS transcript_count, "
            f"  MAX(timestamp) AS last_activity "
            f"  FROM {schema}.transcript_entries e "
            f"  WHERE 1=1 {scope_clause} "
            f"  GROUP BY project_id"
            f") stats ON p.id = stats.project_id "
            f"ORDER BY COALESCE(stats.last_activity, 0) DESC, "
            f"COALESCE(p.repo_name, p.name, p.id) ASC"
        ),
        scope_params,
    )

    rows: list[VisibleProjectRow] = []
    for row in result.fetchall():
        row_project_id = row.id if hasattr(row, "id") else row.project_id
        row_project_name = row.name if hasattr(row, "name") else getattr(row, "project_name", None)
        rows.append(
            VisibleProjectRow(
                project_id=row_project_id,
                project_name=row_project_name,
                root_path=getattr(row, "root_path", ""),
                repo_group_key=getattr(row, "repo_group_key", None),
                repo_identity=getattr(row, "repo_identity", None),
                repo_name=getattr(row, "repo_name", None),
                worktree_name=getattr(row, "worktree_name", None),
                is_worktree=bool(getattr(row, "is_worktree", False)),
                entry_count=row.entry_count,
                transcript_count=getattr(row, "transcript_count", 0) or 0,
                last_activity=row.last_activity,
            )
        )

    return rows


async def get_project_cards(
    auth: AuthContext,
    db: AsyncSession,
) -> list[ProjectCard]:
    """Fetch grouped project cards with entry counts and last activity."""
    visible_projects = await fetch_visible_project_rows(auth, db)

    cards = []
    for grouped_project_id, group in build_logical_project_groups(visible_projects).items():
        rows = group.rows
        representative = max(
            rows,
            key=lambda row: (row.last_activity or 0, row.entry_count, row.project_id),
        )
        cards.append(
            ProjectCard(
                project_id=grouped_project_id,
                project_name=representative.repo_name or representative.project_name,
                entry_count=sum(row.entry_count for row in rows),
                last_activity=max((row.last_activity or 0) for row in rows) or None,
                worktree_count=len(rows),
            )
        )

    cards.sort(
        key=lambda card: (
            -(card.last_activity or 0),
            (card.project_name or card.project_id).lower(),
        )
    )

    logger.info(
        "Project cards: tenant=%s user=%s role=%s count=%d",
        auth.tenant_id, auth.user_id, auth.role, len(cards),
    )

    return cards


async def get_project_detail(
    auth: AuthContext,
    db: AsyncSession,
    *,
    project_id: str,
) -> ProjectDetailResult | None:
    """Fetch raw single-project detail with stats and contributor list."""
    schema = await resolve_schema(auth, db)

    if not auth.has_full_access:
        visible = await db.execute(
            text(
                f"SELECT 1 FROM {schema}.transcript_entries "
                f"WHERE project_id = :project_id "
                f"AND uploaded_by_user_id = :scope_user_id "
                f"LIMIT 1"
            ),
            {"project_id": project_id, "scope_user_id": str(auth.user_id)},
        )
        if not visible.first():
            return None

    proj_result = await db.execute(
        text(
            f"SELECT id, COALESCE(name, id) AS name, root_path "
            f"FROM {schema}.projects WHERE id = :project_id"
        ),
        {"project_id": project_id},
    )
    proj_row = proj_result.first()
    if not proj_row:
        return None

    scope_clause, scope_params = build_user_scope_clause(
        auth, column="e.uploaded_by_user_id", param_name="scope_user_id"
    )
    stats_params: dict[str, object] = {"project_id": project_id, **scope_params}

    stats_result = await db.execute(
        text(
            f"SELECT COUNT(DISTINCT e.transcript_id) AS transcript_count, "
            f"COUNT(e.id) AS entry_count, "
            f"MAX(e.timestamp) AS last_activity "
            f"FROM {schema}.transcript_entries e "
            f"WHERE e.project_id = :project_id {scope_clause}"
        ),
        stats_params,
    )
    stats_row = stats_result.first()

    contributors = await _get_contributors(
        auth,
        db,
        schema=schema,
        project_ids=[project_id],
    )

    logger.info(
        "Project detail: tenant=%s user=%s project=%s contributors=%d",
        auth.tenant_id, auth.user_id, project_id, len(contributors),
    )

    return ProjectDetailResult(
        project_id=proj_row.id,
        project_name=proj_row.name,
        entry_count=stats_row.entry_count if stats_row else 0,
        transcript_count=stats_row.transcript_count if stats_row else 0,
        last_activity=stats_row.last_activity if stats_row else None,
        contributors=contributors,
        root_path=getattr(proj_row, "root_path", None),
    )


async def get_logical_project_detail(
    auth: AuthContext,
    db: AsyncSession,
    *,
    logical_group_id: str,
) -> ProjectDetailResult | None:
    """Fetch grouped detail for a logical project, preserving raw worktree drill-down."""
    visible_projects = await fetch_visible_project_rows(auth, db)
    grouped_projects = build_logical_project_groups(visible_projects)
    group = grouped_projects.get(logical_group_id)
    if not group:
        group = next(
            (
                candidate
                for candidate in grouped_projects.values()
                if logical_group_id in candidate.aliases
            ),
            None,
        )
    if not group:
        return None
    grouped_rows = group.rows

    grouped_rows.sort(
        key=lambda row: (
            -(row.last_activity or 0),
            (row.repo_name or row.project_name or row.project_id).lower(),
        )
    )
    representative = grouped_rows[0]
    schema = await resolve_schema(auth, db)
    contributors = await _get_contributors(
        auth,
        db,
        schema=schema,
        project_ids=[row.project_id for row in grouped_rows],
    )

    worktrees = [
        WorktreeProject(
            project_id=row.project_id,
            project_name=row.project_name,
            root_path=row.root_path,
            worktree_name=row.worktree_name,
            entry_count=row.entry_count,
            transcript_count=row.transcript_count,
            last_activity=row.last_activity,
        )
        for row in grouped_rows
    ]

    logger.info(
        "Logical project detail: tenant=%s user=%s group=%s worktrees=%d",
        auth.tenant_id, auth.user_id, logical_group_id, len(worktrees),
    )

    return ProjectDetailResult(
        project_id=group.project_id,
        project_name=representative.repo_name or representative.project_name,
        entry_count=sum(row.entry_count for row in grouped_rows),
        transcript_count=sum(row.transcript_count for row in grouped_rows),
        last_activity=max((row.last_activity or 0) for row in grouped_rows) or None,
        contributors=contributors,
        root_path=representative.root_path if len(worktrees) == 1 else None,
        worktrees=worktrees,
        is_logical_group=len(worktrees) > 1,
    )


async def _get_contributors(
    auth: AuthContext,
    db: AsyncSession,
    *,
    schema: str,
    project_ids: list[str],
) -> list[Contributor]:
    placeholders = []
    params: dict[str, object] = {}
    for index, project_id in enumerate(project_ids):
        key = f"project_id_{index}"
        params[key] = project_id
        placeholders.append(f":{key}")

    scope_clause, scope_params = build_user_scope_clause(
        auth, column="e.uploaded_by_user_id", param_name="scope_user_id"
    )
    contributors_scope = "" if auth.has_full_access else scope_clause
    if not auth.has_full_access:
        params.update(scope_params)

    contributors_result = await db.execute(
        text(
            f"SELECT e.uploaded_by_user_id, "
            f"u.name AS user_name, u.email AS user_email, "
            f"COUNT(e.id) AS entry_count, "
            f"MAX(e.timestamp) AS last_activity "
            f"FROM {schema}.transcript_entries e "
            f"LEFT JOIN public.users u ON e.uploaded_by_user_id = u.id "
            f"WHERE e.project_id IN ({', '.join(placeholders)}) {contributors_scope} "
            f"GROUP BY e.uploaded_by_user_id, u.name, u.email "
            f"ORDER BY entry_count DESC"
        ),
        params,
    )

    contributors = []
    for row in contributors_result.fetchall():
        contributors.append(
            Contributor(
                user_id=str(row.uploaded_by_user_id),
                user_name=row.user_name,
                user_email=row.user_email,
                entry_count=row.entry_count,
                last_activity=row.last_activity,
            )
        )
    return contributors
