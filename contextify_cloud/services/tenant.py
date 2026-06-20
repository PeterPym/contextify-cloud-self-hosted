"""Tenant provisioning service.

Creates per-tenant PostgreSQL schemas with tables mirroring the Contextify
SQLite schema, plus multi-user columns (uploaded_by_user_id, etc.).

Schema-per-tenant isolation notes:
- Each tenant gets a dedicated PostgreSQL schema (tenant_{slug}).
- All queries targeting tenant data must use fully-qualified table names
  (e.g., tenant_acme.transcript_entries) rather than relying on search_path.
- The get_tenant_schema() function returns the qualified schema name.
- Never set search_path at the session level to a tenant schema; always
  use explicit schema prefixes. This prevents cross-tenant data leakage
  from mis-scoped queries.
- For schema migrations, use apply_tenant_migration() which iterates all
  tenant schemas safely.
"""

import asyncio
import logging
import re

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from contextify_cloud.middleware.auth import generate_api_key, hash_api_key
from contextify_cloud.models import ApiKey, Tenant, User

logger = logging.getLogger(__name__)

# Strict validation for schema names to prevent SQL injection
_SCHEMA_NAME_RE = re.compile(r"^tenant_[a-z0-9_]+$")
_ENSURED_COMPAT_SCHEMAS: set[str] = set()
_ENSURE_COMPAT_LOCK = asyncio.Lock()

_TENANT_SCHEMA_COMPAT_SQL = (
    """
    ALTER TABLE {schema}.projects
        ADD COLUMN IF NOT EXISTS repo_group_key TEXT
    """,
    """
    ALTER TABLE {schema}.projects
        ADD COLUMN IF NOT EXISTS repo_identity TEXT
    """,
    """
    ALTER TABLE {schema}.projects
        ADD COLUMN IF NOT EXISTS repo_origin_normalized TEXT
    """,
    """
    ALTER TABLE {schema}.projects
        ADD COLUMN IF NOT EXISTS git_common_dir TEXT
    """,
    """
    ALTER TABLE {schema}.projects
        ADD COLUMN IF NOT EXISTS is_worktree BOOLEAN NOT NULL DEFAULT false
    """,
    """
    ALTER TABLE {schema}.projects
        ADD COLUMN IF NOT EXISTS default_branch TEXT
    """,
    """
    ALTER TABLE {schema}.projects
        ADD COLUMN IF NOT EXISTS vcs_provider TEXT
    """,
    """
    ALTER TABLE {schema}.projects
        ADD COLUMN IF NOT EXISTS worktree_name TEXT
    """,
    """
    ALTER TABLE {schema}.projects
        ADD COLUMN IF NOT EXISTS repo_name TEXT
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_projects_repo_group_key
        ON {schema}.projects(repo_group_key)
    """,
    """
    CREATE TABLE IF NOT EXISTS {schema}.project_team_shares (
        user_id UUID NOT NULL REFERENCES public.users(id),
        project_id TEXT NOT NULL REFERENCES {schema}.projects(id) ON DELETE CASCADE,
        created_at BIGINT NOT NULL,
        PRIMARY KEY (user_id, project_id)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_project_team_shares_project
        ON {schema}.project_team_shares(project_id)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_projects_repo_identity
        ON {schema}.projects(repo_identity)
    """,
    """
    CREATE TABLE IF NOT EXISTS {schema}.transcript_tags (
        transcript_id TEXT NOT NULL REFERENCES {schema}.transcripts(id) ON DELETE CASCADE,
        tag TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        PRIMARY KEY (transcript_id, tag)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_transcript_tags_tag
        ON {schema}.transcript_tags(tag, transcript_id)
    """,
)

# SQL template for per-tenant schema.
# {schema} is replaced with the sanitized tenant slug.
TENANT_SCHEMA_SQL = """
CREATE SCHEMA IF NOT EXISTS {schema};

CREATE TABLE IF NOT EXISTS {schema}.projects (
    id TEXT PRIMARY KEY,
    name TEXT,
    root_path TEXT NOT NULL,
    repo_group_key TEXT,
    repo_identity TEXT,
    repo_origin_normalized TEXT,
    git_common_dir TEXT,
    is_worktree BOOLEAN NOT NULL DEFAULT false,
    default_branch TEXT,
    vcs_provider TEXT,
    worktree_name TEXT,
    repo_name TEXT,
    created_by_user_id UUID REFERENCES public.users(id),
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

-- ct-2250: PER-USER team-share consent. A row here means "this user shares THEIR OWN
-- entries for this project with the team". Team-aware recall surfaces a teammate's row
-- only if that teammate (the row's uploaded_by_user_id) has a share record here for the
-- project. Each user controls only their own entries -- no one else's toggle touches your
-- data -- so there is no co-contributor exposure, no discovery-surface requirement, and no
-- viewer asymmetry. Default state is unshared (absence of a row). Un-share = DELETE the row.
CREATE TABLE IF NOT EXISTS {schema}.project_team_shares (
    user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES {schema}.projects(id) ON DELETE CASCADE,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (user_id, project_id)
);

CREATE INDEX IF NOT EXISTS idx_project_team_shares_project
    ON {schema}.project_team_shares(project_id);

CREATE INDEX IF NOT EXISTS idx_projects_repo_group_key
    ON {schema}.projects(repo_group_key);

CREATE INDEX IF NOT EXISTS idx_projects_repo_identity
    ON {schema}.projects(repo_identity);

CREATE TABLE IF NOT EXISTS {schema}.transcripts (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES {schema}.projects(id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    provider TEXT NOT NULL CHECK (provider IN ('claude.code', 'codex.cli', 'other')),
    provider_session_id TEXT,
    uploaded_by_user_id UUID NOT NULL REFERENCES public.users(id),
    device_id UUID REFERENCES public.devices(id),
    line_count INTEGER NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE(project_id, file_path, uploaded_by_user_id)
);

CREATE TABLE IF NOT EXISTS {schema}.transcript_entries (
    id TEXT PRIMARY KEY,
    transcript_id TEXT NOT NULL REFERENCES {schema}.transcripts(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES {schema}.projects(id) ON DELETE CASCADE,
    session_id TEXT,
    provider TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('user', 'assistant', 'system', 'summary')),
    timestamp BIGINT NOT NULL,
    content TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    display_in_timeline BOOLEAN NOT NULL DEFAULT true,
    git_branch TEXT,
    git_commit TEXT,
    cwd TEXT,
    uploaded_by_user_id UUID NOT NULL REFERENCES public.users(id),
    uploaded_by_device_id TEXT,
    uploaded_by_device_name TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    server_sequence BIGINT NOT NULL,
    search_vector TSVECTOR GENERATED ALWAYS AS (
        to_tsvector('english', coalesce(content, ''))
    ) STORED
);

-- Sequence for monotonic server_sequence assignment
CREATE SEQUENCE IF NOT EXISTS {schema}.entry_server_seq;

-- Set default for server_sequence to auto-assign
ALTER TABLE {schema}.transcript_entries
    ALTER COLUMN server_sequence SET DEFAULT nextval('{schema}.entry_server_seq');

CREATE INDEX IF NOT EXISTS idx_entries_project_time
    ON {schema}.transcript_entries(project_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_entries_search
    ON {schema}.transcript_entries USING GIN(search_vector);
CREATE INDEX IF NOT EXISTS idx_entries_content_sha
    ON {schema}.transcript_entries(content_sha256);
CREATE INDEX IF NOT EXISTS idx_entries_user
    ON {schema}.transcript_entries(uploaded_by_user_id);
CREATE INDEX IF NOT EXISTS idx_entries_kind
    ON {schema}.transcript_entries(kind) WHERE kind IN ('user', 'assistant');
CREATE INDEX IF NOT EXISTS idx_entries_server_seq
    ON {schema}.transcript_entries(server_sequence);

CREATE TABLE IF NOT EXISTS {schema}.transcript_metadata (
    transcript_id TEXT PRIMARY KEY REFERENCES {schema}.transcripts(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    topics JSONB NOT NULL DEFAULT '[]',
    confidence REAL NOT NULL,
    generated_at BIGINT NOT NULL,
    model TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS {schema}.timeline_summaries (
    id TEXT PRIMARY KEY,
    entry_id TEXT NOT NULL REFERENCES {schema}.transcript_entries(id) ON DELETE CASCADE,
    content_sha256 TEXT NOT NULL,
    window_sha256 TEXT NOT NULL,
    present_form TEXT NOT NULL,
    past_form TEXT NOT NULL,
    disposition TEXT,
    generated_at BIGINT NOT NULL,
    UNIQUE(content_sha256, window_sha256)
);

CREATE TABLE IF NOT EXISTS {schema}.tool_invocations (
    id TEXT PRIMARY KEY,
    entry_id TEXT NOT NULL REFERENCES {schema}.transcript_entries(id) ON DELETE CASCADE,
    transcript_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    tool_key TEXT,
    status TEXT DEFAULT 'unknown',
    started_at BIGINT,
    completed_at BIGINT,
    metadata_json JSONB,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_invocations_entry
    ON {schema}.tool_invocations(entry_id);
CREATE INDEX IF NOT EXISTS idx_invocations_tool
    ON {schema}.tool_invocations(tool_name);

CREATE TABLE IF NOT EXISTS {schema}.assistant_usage (
    entry_id TEXT NOT NULL REFERENCES {schema}.transcript_entries(id) ON DELETE CASCADE,
    request_id TEXT NOT NULL,
    model TEXT NOT NULL,
    input_tokens INTEGER NOT NULL,
    output_tokens INTEGER NOT NULL,
    cache_creation_tokens INTEGER NOT NULL DEFAULT 0,
    cache_read_tokens INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(entry_id, request_id)
);

CREATE TABLE IF NOT EXISTS {schema}.transcript_tags (
    transcript_id TEXT NOT NULL REFERENCES {schema}.transcripts(id) ON DELETE CASCADE,
    tag TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (transcript_id, tag)
);

CREATE INDEX IF NOT EXISTS idx_transcript_tags_tag
    ON {schema}.transcript_tags(tag, transcript_id);
"""


def _sanitize_slug(slug: str) -> str:
    """Sanitize a tenant slug for use as a PostgreSQL schema name.

    Only allows lowercase alphanumeric and underscores.
    Raises ValueError if the result would be empty after sanitization.
    """
    sanitized = "".join(c if c.isalnum() or c == "_" else "_" for c in slug.lower())
    if not sanitized or sanitized[0].isdigit():
        sanitized = "t_" + sanitized
    # Truncate to PostgreSQL identifier limit (63 chars minus 'tenant_' prefix)
    sanitized = sanitized[:56]
    return sanitized


def _validate_schema_name(schema_name: str) -> None:
    """Validate a schema name to prevent SQL injection.

    Schema names are used in string-formatted SQL (not parameterizable in
    PostgreSQL), so we must strictly validate them.
    """
    if not _SCHEMA_NAME_RE.match(schema_name):
        raise ValueError(
            f"Invalid schema name: {schema_name!r}. "
            "Must match pattern: tenant_[a-z0-9_]+"
        )


async def create_tenant_schema(db: AsyncSession, slug: str) -> None:
    """Create the per-tenant schema with all tables.

    Uses fully-qualified table names (never sets search_path).
    """
    schema_name = f"tenant_{_sanitize_slug(slug)}"
    _validate_schema_name(schema_name)

    sql = TENANT_SCHEMA_SQL.replace("{schema}", schema_name)

    # Execute each statement separately (some drivers don't support multi-statement)
    for statement in sql.split(";"):
        statement = statement.strip()
        if statement:
            await db.execute(text(statement))

    logger.info("Created tenant schema: %s", schema_name)


async def list_tenant_schemas(db: AsyncSession) -> list[str]:
    """List all tenant schemas in the database.

    Useful for running migrations across all tenants.
    """
    result = await db.execute(
        text(
            "SELECT schema_name FROM information_schema.schemata "
            "WHERE schema_name LIKE 'tenant_%'"
        )
    )
    schemas = [row[0] for row in result.fetchall()]
    # Validate each schema name for safety
    for s in schemas:
        _validate_schema_name(s)
    return schemas


async def ensure_tenant_schema_compat(db: AsyncSession, schema_name: str) -> None:
    """Apply additive tenant-schema compatibility changes once per process."""
    if not isinstance(db, AsyncSession):
        return

    _validate_schema_name(schema_name)

    if schema_name in _ENSURED_COMPAT_SCHEMAS:
        return

    async with _ENSURE_COMPAT_LOCK:
        if schema_name in _ENSURED_COMPAT_SCHEMAS:
            return

        for statement in _TENANT_SCHEMA_COMPAT_SQL:
            await db.execute(text(statement.replace("{schema}", schema_name)))

        _ENSURED_COMPAT_SCHEMAS.add(schema_name)
        logger.info("Ensured tenant schema compatibility for %s", schema_name)


async def provision_tenant(
    db: AsyncSession,
    name: str,
    slug: str,
    email: str,
    user_name: str | None = None,
    create_default_api_key: bool = True,
) -> tuple[Tenant, User, str | None]:
    """Provision a new tenant with owner user and API key.

    Returns (tenant, user, raw_api_key).
    """
    # Create tenant
    tenant = Tenant(name=name, slug=_sanitize_slug(slug))
    db.add(tenant)
    await db.flush()

    # Create owner user
    user = User(
        tenant_id=tenant.id,
        email=email,
        name=user_name or email.split("@")[0],
        role="owner",
    )
    db.add(user)
    await db.flush()

    raw_key: str | None = None
    if create_default_api_key:
        # Generate API key (new format: ctx_<key_id>_<secret>)
        raw_key, key_id, secret = generate_api_key()
        api_key = ApiKey(
            user_id=user.id,
            tenant_id=tenant.id,
            key_id=key_id,
            key_hash=hash_api_key(secret),
            key_prefix=f"ctx_{key_id}...",
            name="Default",
        )
        db.add(api_key)

    # Create tenant schema
    await create_tenant_schema(db, tenant.slug)

    await db.flush()

    logger.info(
        "Provisioned tenant %s (id=%s) with owner %s",
        tenant.slug, tenant.id, user.email,
    )

    return tenant, user, raw_key


def get_tenant_schema(slug: str) -> str:
    """Get the PostgreSQL schema name for a tenant.

    Always use this function to derive schema names. Never construct
    schema names manually. The result is validated against a strict
    regex to prevent SQL injection.
    """
    schema_name = f"tenant_{_sanitize_slug(slug)}"
    _validate_schema_name(schema_name)
    return schema_name
