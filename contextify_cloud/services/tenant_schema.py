"""Shared tenant schema resolution for dashboard services.

Resolves the PostgreSQL schema name for a tenant from the authenticated
user's context. Used by activity, projects, and search services.
"""

import logging
import re

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from contextify_cloud.middleware.auth import AuthContext
from contextify_cloud.models import Tenant
from contextify_cloud.services.tenant import ensure_tenant_schema_compat, get_tenant_schema

logger = logging.getLogger(__name__)

_SCHEMA_NAME_RE = re.compile(r"^tenant_[a-z0-9_]+$")


async def resolve_schema(auth: AuthContext, db: AsyncSession) -> str:
    """Resolve and validate the tenant schema name."""
    tenant = await db.execute(select(Tenant).where(Tenant.id == auth.tenant_id))
    tenant_obj = tenant.scalar_one_or_none()
    if not tenant_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found.",
        )
    schema = get_tenant_schema(tenant_obj.slug)
    if not _SCHEMA_NAME_RE.fullmatch(schema):
        logger.error("Unsafe tenant schema name: %r", schema)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal configuration error.",
        )
    if isinstance(db, AsyncSession):
        await ensure_tenant_schema_compat(db, schema)
    return schema
