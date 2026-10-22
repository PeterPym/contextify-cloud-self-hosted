"""Bounded integrity lookup, with the same author visibility as ordinary sync."""

import uuid
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator
from pydantic_core import PydanticCustomError
from sqlalchemy import Text, bindparam, text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.ext.asyncio import AsyncSession

from contextify_cloud.middleware.auth import AuthContext
from contextify_cloud.services.tenant_schema import resolve_schema
from contextify_cloud.services.user_scoping import build_user_scope_clause


class CoverageEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1, max_length=256)
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    project_id: str = Field(min_length=1, max_length=256)
    # The same canonical repo key used by push, when a local ID is an alias.
    repo_group_key: str | None = Field(None, min_length=1, max_length=512)
    source_device_id: str = Field(min_length=1, max_length=256)
    # Null permits authoritative recovery of unknown legacy authorship.
    source_user_id: uuid.UUID | None = None


class CoverageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    entries: list[CoverageEntry] = Field(max_length=200)

    @model_validator(mode="after")
    def unique_ids(self) -> Self:
        if len({e.id for e in self.entries}) != len(self.entries):
            raise PydanticCustomError("coverage_invalid", "Coverage entry IDs must be unique")
        return self


class CoverageResult(BaseModel):
    id: str
    outcome: Literal["matching", "missing", "conflicting", "unresolved"]
    canonical_project_id: str | None = None
    source_user_id: uuid.UUID | None = None
    source_device_id: str | None = None
    tenant_id: uuid.UUID | None = None


class CoverageResponse(BaseModel):
    retirement_coverage_version: int = 1
    entries: list[CoverageResult]


async def coverage(
    db: AsyncSession,
    auth: AuthContext,
    payload: CoverageRequest,
) -> CoverageResponse:
    schema = await resolve_schema(auth, db)
    if not payload.entries:
        return CoverageResponse(entries=[])
    scope, params = build_user_scope_clause(auth, column="e.uploaded_by_user_id")
    # One statement/snapshot for rows, visibility and canonical project mapping.
    # Hidden rows are distinguished from missing without returning their metadata.
    rows = (
        (
            await db.execute(
                text(f"""
        WITH requested AS (
            SELECT * FROM unnest(:ids, :projects, :keys) AS r(id, project_id, repo_group_key)
        )
        SELECT r.id, e.id IS NOT NULL AS present,
               (1=1 {scope}) AS visible,
               e.content_sha256, e.project_id, e.uploaded_by_user_id,
               e.uploaded_by_device_id,
               COALESCE((SELECT p.id FROM {schema}.projects p WHERE p.id=r.project_id),
                        (SELECT p.id FROM {schema}.projects p
                         WHERE p.repo_group_key=r.repo_group_key
                         ORDER BY p.created_at ASC, p.id LIMIT 1), r.project_id) AS canonical
        FROM requested r LEFT JOIN {schema}.transcript_entries e ON e.id=r.id
    """).bindparams(*(bindparam(name, type_=ARRAY(Text)) for name in ("ids", "projects", "keys"))),
                {
                    "ids": [e.id for e in payload.entries],
                    "projects": [e.project_id for e in payload.entries],
                    "keys": [e.repo_group_key for e in payload.entries],
                    **params,
                },
            )
        )
        .mappings()
        .all()
    )
    by_id = {e.id: e for e in payload.entries}
    results = []
    for row in rows:
        entry = by_id[row["id"]]
        result = CoverageResult(id=entry.id, outcome="unresolved")
        if not row["present"]:
            result.outcome = "missing"
        elif row["visible"]:
            if (
                row["content_sha256"] != entry.content_sha256
                or row["project_id"] != row["canonical"]
            ):
                result.outcome = "conflicting"
            elif (
                row["uploaded_by_device_id"] == entry.source_device_id
                and row["uploaded_by_user_id"] is not None
                and (
                    entry.source_user_id is None
                    or row["uploaded_by_user_id"] == entry.source_user_id
                )
            ):
                result.outcome = "matching"
                result.canonical_project_id = row["canonical"]
                result.source_user_id = row["uploaded_by_user_id"]
                result.source_device_id = row["uploaded_by_device_id"]
                result.tenant_id = auth.tenant_id
        results.append(result)
    return CoverageResponse(entries=results)
