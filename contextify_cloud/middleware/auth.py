"""API key authentication middleware.

Key format: ctx_<key_id>_<secret>
  - key_id: 16 hex chars (64 bits), used for DB lookup (public, safe to log)
  - secret: 24 hex chars, verified via bcrypt (never logged)

This follows the reviewer recommendation to separate identification from
authentication: lookup by key_id, verify by comparing bcrypt hashes of the
secret portion only. This prevents prefix-based enumeration attacks and
makes key identification O(1) instead of scanning.

key_id uses 64 bits of entropy (16 hex chars) to avoid collision risk
across environments. Since key_id is non-secret, extra length is free.
"""

import asyncio
import logging
import secrets
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

import bcrypt
from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from contextify_cloud.database import get_db
from contextify_cloud.middleware.logging import tenant_id_var, user_id_var
from contextify_cloud.models import ApiKey, User

logger = logging.getLogger(__name__)

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# Key format constants
KEY_PREFIX = "ctx"
KEY_ID_LENGTH = 16  # hex chars for lookup (64 bits entropy)
KEY_SECRET_LENGTH = 24  # hex chars for verification


class AuthContext:
    """Resolved authentication context from a valid API key.

    The role field reflects the user's role in the tenant:
      - owner/admin: full access, can see all data across all users, all mutations
      - member: can push/sync, but only sees data where uploaded_by_user_id matches
      - viewer: read-only, user-scoped. Can search and browse but cannot push,
        create invitations, or manage billing. API keys restricted to search scope.

    If no user record is found, authentication is rejected (fail-closed)
    rather than granting full access.
    """

    # Roles that have visibility into all tenant data (no user-scoping)
    FULL_ACCESS_ROLES = frozenset({"owner", "admin"})

    def __init__(
        self,
        user_id: uuid.UUID,
        tenant_id: uuid.UUID,
        scopes: list[str],
        key_id: str,
        role: str = "member",
        account_id: uuid.UUID | None = None,
        session_id: uuid.UUID | None = None,
    ):
        self.user_id = user_id
        self.tenant_id = tenant_id
        self.scopes = scopes
        self.key_id = key_id  # Public key_id, safe to log and use for idempotency
        self.role = role
        self.account_id = account_id
        self.session_id = session_id

    @property
    def has_full_access(self) -> bool:
        """Whether this user can see all data in the tenant (no user-scoping)."""
        return self.role in self.FULL_ACCESS_ROLES


def hash_api_key(raw_secret: str) -> str:
    """Hash the secret portion of an API key using bcrypt."""
    return bcrypt.hashpw(raw_secret.encode(), bcrypt.gensalt()).decode()


def verify_api_key(raw_secret: str, hashed: str) -> bool:
    """Verify the secret portion of an API key against its bcrypt hash."""
    return bcrypt.checkpw(raw_secret.encode(), hashed.encode())


def generate_api_key() -> tuple[str, str, str]:
    """Generate a new API key.

    Returns (full_key, key_id, secret).
    Format: ctx_<key_id>_<secret>
      - key_id: 16 hex chars for DB lookup (stored in plain text, 64 bits entropy)
      - secret: 24 hex chars for verification (stored as bcrypt hash)
    """
    key_id = secrets.token_hex(KEY_ID_LENGTH // 2)  # 16 hex chars (64 bits)
    secret = secrets.token_hex(KEY_SECRET_LENGTH // 2)  # 24 hex chars
    full_key = f"{KEY_PREFIX}_{key_id}_{secret}"
    return full_key, key_id, secret


def parse_api_key(raw_key: str) -> tuple[str, str] | None:
    """Parse an API key into (key_id, secret).

    Returns None if the format is invalid.
    """
    parts = raw_key.split("_", 2)
    if len(parts) != 3 or parts[0] != KEY_PREFIX:
        return None
    key_id, secret = parts[1], parts[2]
    if len(key_id) != KEY_ID_LENGTH or len(secret) != KEY_SECRET_LENGTH:
        return None
    return key_id, secret


async def resolve_api_key(
    request: Request,
    api_key: Annotated[str | None, Security(api_key_header)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> AuthContext:
    """Validate an API key and return the auth context.

    This is a FastAPI dependency used on protected endpoints.
    Accepts API keys via two header formats:
      - X-API-Key: ctx_<key_id>_<secret>
      - Authorization: Bearer ctx_<key_id>_<secret>

    Lookup is by key_id (O(1)), verification is by bcrypt comparison of secret.
    """
    # Check Authorization: Bearer header as fallback when X-API-Key is absent
    if not api_key:
        auth_header = request.headers.get("authorization")
        if auth_header and auth_header.lower().startswith("bearer "):
            api_key = auth_header[7:].strip()

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key. Include X-API-Key or Authorization: Bearer header.",
        )

    parsed = parse_api_key(api_key)
    if not parsed:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key format. Expected: ctx_<key_id>_<secret>.",
        )

    key_id, secret = parsed

    # O(1) lookup by key_id, then verify secret via bcrypt
    result = await db.execute(
        select(ApiKey).where(ApiKey.key_id == key_id)
    )
    candidate = result.scalar_one_or_none()

    if not candidate:
        logger.warning("Auth failed for key_id=%s (not found)", key_id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
        )

    # Run bcrypt verification in a thread to avoid blocking the event loop
    # (bcrypt is CPU-intensive and can stall async concurrency under load).
    key_valid = await asyncio.to_thread(verify_api_key, secret, candidate.key_hash)
    if not key_valid:
        logger.warning("Auth failed for key_id=%s", key_id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
        )

    # Check if key is revoked
    if candidate.revoked_at is not None:
        logger.warning("Revoked key used: key_id=%s", key_id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key has been revoked.",
        )

    # Check expiry
    if candidate.expires_at and candidate.expires_at < datetime.now(UTC):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key has expired.",
        )

    # Update last_used_at
    await db.execute(
        update(ApiKey)
        .where(ApiKey.id == candidate.id)
        .values(last_used_at=datetime.now(UTC))
    )

    # Fetch user role for data scoping.
    # Fail closed: if the user record is missing, reject the request rather
    # than granting full access. This prevents privilege escalation if user
    # rows are accidentally deleted.
    user_result = await db.execute(
        select(User.role).where(User.id == candidate.user_id)
    )
    user_role = user_result.scalar_one_or_none()
    if not user_role:
        logger.error(
            "User record missing for key_id=%s user_id=%s", key_id, candidate.user_id
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
        )

    # Set contextvars for structured logging enrichment
    tenant_id_var.set(str(candidate.tenant_id))
    user_id_var.set(str(candidate.user_id))
    # Also store on request.state for MetricsMiddleware (BaseHTTPMiddleware
    # does not reliably propagate contextvar changes back upstream).
    request.state.tenant_id = str(candidate.tenant_id)
    request.state.user_id = str(candidate.user_id)
    request.state.key_id = key_id

    return AuthContext(
        user_id=candidate.user_id,
        tenant_id=candidate.tenant_id,
        scopes=candidate.scopes,
        key_id=key_id,
        role=user_role,
    )


def require_scope(*scopes: str) -> Any:
    """Dependency factory that checks for at least one of the required scopes.

    When multiple scopes are provided, the key must have at least one of them
    (logical OR). For example, require_scope("sync", "search") allows keys
    with either "sync" or "search" scope.

    Raises RuntimeError at import time if called with no scopes (misconfiguration guard).
    """
    if not scopes:
        raise RuntimeError("require_scope() requires at least one scope")

    async def check_scope(auth: Annotated[AuthContext, Depends(resolve_api_key)]) -> AuthContext:
        if not any(s in auth.scopes for s in scopes):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"API key missing required scope: {', '.join(scopes)}",
            )
        return auth

    return check_scope


def require_role(*allowed_roles: str) -> Any:
    """Dependency factory that restricts access to specific roles (e.g., owner, admin)."""

    async def check_role(auth: Annotated[AuthContext, Depends(resolve_api_key)]) -> AuthContext:
        if auth.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient role. Required: {', '.join(allowed_roles)}",
            )
        return auth

    return check_role
