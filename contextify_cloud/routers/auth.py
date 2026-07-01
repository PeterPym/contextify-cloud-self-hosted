"""Authentication and registration endpoints.

Public registration is disabled by default and must be explicitly enabled via
ENABLE_REGISTRATION for local/self-serve setups.
"""

import asyncio
import logging
import secrets
import uuid as uuid_mod
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from contextify_cloud.config import settings
from contextify_cloud.database import get_db
from contextify_cloud.middleware.auth import (
    AuthContext,
    generate_api_key,
    hash_api_key,
    parse_api_key,
    require_scope,
    resolve_api_key,
    verify_api_key,
)
from contextify_cloud.middleware.jwt_auth import create_jwt_token
from contextify_cloud.models import ApiKey, Tenant, User
from contextify_cloud.schemas import (
    ApiKeyCreate,
    ApiKeyResponse,
    ApiKeyRotateResponse,
    ApiKeyUpdateRequest,
    BrowserHandoffRequest,
    BrowserHandoffResponse,
    LoginRequest,
    LoginResponse,
    RegisterRequest,
    RegisterResponse,
)
from contextify_cloud.services.audit import log_event
from contextify_cloud.services.browser_handoff import issue_browser_handoff_token
from contextify_cloud.services.funnel_events import emit_funnel_event
from contextify_cloud.services.tenant import (
    _sanitize_slug,
    provision_tenant,
    tenant_is_internal,
)
from contextify_cloud.services.tenant_guard import check_tenant_active

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

ALLOWED_SCOPES = {"sync", "search"}
KEY_MANAGEMENT_SCOPE = "sync"


def _ensure_registration_enabled() -> None:
    if not settings.enable_registration:
        logger.info("Registration blocked: public registration is disabled")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")


def _require_key_management_scope(auth: AuthContext) -> None:
    if KEY_MANAGEMENT_SCOPE not in auth.scopes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API key does not have permission to manage API keys.",
        )


def _validate_child_key_scopes(auth: AuthContext, scopes: list[str]) -> None:
    _require_key_management_scope(auth)
    requested = set(scopes)
    allowed = set(auth.scopes)
    if not requested.issubset(allowed):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="New API key scopes must be a subset of the caller key scopes.",
        )


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(_ensure_registration_enabled)],
)
async def register(
    request: RegisterRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> RegisterResponse:
    """Register a new account and tenant."""
    # Compute canonical slug using the same sanitization as tenant provisioning.
    # Previously register() built a slug with hyphens while provision_tenant()
    # stored one with underscores via _sanitize_slug, causing the uniqueness
    # check here to pass against a different slug than what was actually stored.
    slug = _sanitize_slug(request.team_name)

    existing = await db.execute(select(Tenant).where(Tenant.slug == slug))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Team name '{request.team_name}' is already taken.",
        )

    tenant, user, raw_key = await provision_tenant(
        db=db,
        name=request.team_name,
        slug=slug,
        email=request.email,
        user_name=request.name,
    )
    if raw_key is None:
        raise RuntimeError("API registration expected provision_tenant to create an API key")

    # Show key_id portion as the display prefix (safe to display/log)
    key_id_portion = raw_key.split("_")[1] if "_" in raw_key else raw_key[:8]

    logger.info(
        "Registered tenant=%s user=%s key_id=%s",
        tenant.slug, request.email, key_id_portion,
    )

    return RegisterResponse(
        tenant_id=tenant.id,
        user_id=user.id,
        api_key=raw_key,
        api_key_prefix=f"ctx_{key_id_portion}...",
    )


@router.post("/login", response_model=LoginResponse)
async def login(
    request: LoginRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> LoginResponse:
    """Authenticate with email + API key and return a JWT access token.

    JSON-based login endpoint for programmatic clients. Validates the
    API key format, verifies the secret via bcrypt, and checks that
    the email matches the key's owner.
    """
    parsed = parse_api_key(request.api_key)
    if not parsed:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key format.",
        )

    key_id, secret = parsed

    # Look up the API key by key_id
    result = await db.execute(
        select(ApiKey).where(ApiKey.key_id == key_id)
    )
    candidate = result.scalar_one_or_none()

    if not candidate:
        logger.info("Login failed: key_id=%s not found", key_id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or API key.",
        )

    # Cheap checks before bcrypt (avoid CPU cost for invalid keys)
    if candidate.revoked_at is not None:
        logger.info("Login failed: key_id=%s revoked", key_id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This API key has been revoked.",
        )

    if candidate.expires_at and candidate.expires_at < datetime.now(UTC):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This API key has expired.",
        )

    # Verify the secret via bcrypt (offload to thread)
    key_valid = await asyncio.to_thread(verify_api_key, secret, candidate.key_hash)
    if not key_valid:
        logger.info("Login failed: key_id=%s bad secret", key_id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or API key.",
        )

    # Verify the user is active and belongs to the same tenant as the key
    user_result = await db.execute(
        select(User).where(
            User.id == candidate.user_id,
            User.tenant_id == candidate.tenant_id,
            User.removed_at.is_(None),
        )
    )
    user = user_result.scalar_one_or_none()

    if not user or user.email.strip().casefold() != request.email.strip().casefold():
        logger.info("Login failed: email mismatch for key_id=%s", key_id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or API key.",
        )

    # Cache ORM attributes before commit so they remain available even
    # with SQLAlchemy's default expire_on_commit=True.
    user_id = user.id
    user_email = user.email
    user_role = user.role
    candidate_tenant_id = candidate.tenant_id

    # Rotate session nonce to invalidate any prior JWTs for this key.
    # SELECT ... FOR UPDATE serializes concurrent logins for the same key.
    await db.execute(
        select(ApiKey.id).where(ApiKey.id == candidate.id).with_for_update()
    )
    new_nonce = secrets.token_hex(16)
    await db.execute(
        update(ApiKey)
        .where(ApiKey.id == candidate.id)
        .values(session_nonce=new_nonce)
    )
    # Persist the nonce before minting the JWT so that a rollback cannot
    # leave the token referencing a nonce that was never committed.
    await db.commit()

    # Create JWT with the new nonce
    token = create_jwt_token(
        user_id=user_id,
        tenant_id=candidate_tenant_id,
        role=user_role,
        key_id=key_id,
        nonce=new_nonce,
    )

    logger.info("Login success: user=%s key_id=%s", user_email, key_id)

    return LoginResponse(
        access_token=token,
        token_type="bearer",
        user_id=user_id,
        tenant_id=candidate_tenant_id,
        role=user_role,
    )


@router.post("/browser-handoff", response_model=BrowserHandoffResponse)
async def create_browser_handoff(
    http_request: Request,
    request: BrowserHandoffRequest,
    auth: Annotated[AuthContext, Depends(require_scope("sync"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> BrowserHandoffResponse:
    """Mint a short-lived one-time browser handoff URL for native clients."""
    await check_tenant_active(db, auth.tenant_id)
    result = await issue_browser_handoff_token(
        db,
        auth=auth,
        target_path=request.target_path,
        device_id=request.device_id,
        device_name=request.device_name,
        request=http_request,
    )
    return BrowserHandoffResponse(
        handoff_url=result.handoff_url,
        expires_at=result.expires_at,
        email=result.email,
        tenant_name=result.tenant_name,
        target_path=result.target_path,
    )


@router.post("/api-keys", response_model=ApiKeyResponse)
async def create_api_key(
    http_request: Request,
    request: ApiKeyCreate,
    auth: Annotated[AuthContext, Depends(resolve_api_key)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ApiKeyResponse:
    """Generate a new API key for the authenticated user.

    The caller key must itself have key-management capability, and newly
    created key scopes must be a subset of the caller key's scopes.
    """
    await check_tenant_active(db, auth.tenant_id)

    # Validate scopes against whitelist (defense-in-depth)
    unknown = [s for s in request.scopes if s not in ALLOWED_SCOPES]
    if unknown:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=(
                f"Unknown scopes: {', '.join(unknown)}."
                f" Allowed: {', '.join(sorted(ALLOWED_SCOPES))}"
            ),
        )

    # Enforce viewer scope restriction: viewers can only create search-only keys
    scopes = request.scopes
    if auth.role == "viewer":
        scopes = ["search"]
        logger.info(
            "Viewer scope restriction: user=%s requested scopes=%s, forced to ['search']",
            auth.user_id, request.scopes,
        )
    _validate_child_key_scopes(auth, scopes)

    raw_key, key_id, secret = generate_api_key()
    api_key = ApiKey(
        user_id=auth.user_id,
        tenant_id=auth.tenant_id,
        key_id=key_id,
        key_hash=hash_api_key(secret),
        key_prefix=f"ctx_{key_id}...",
        name=request.name,
        scopes=scopes,
    )
    db.add(api_key)
    await db.flush()

    await log_event(
        db,
        tenant_id=auth.tenant_id,
        user_id=auth.user_id,
        action="key.create",
        resource_type="api_key",
        resource_id=str(api_key.id),
        detail={"key_id": key_id, "name": request.name, "scopes": scopes},
        ip_address=http_request.client.host if http_request.client else None,
    )

    logger.info("Created API key key_id=%s for user=%s", key_id, auth.user_id)

    # Return the full raw key in the response (shown only once)
    return ApiKeyResponse(
        id=api_key.id,
        key_prefix=raw_key,  # Full key, only time it's shown
        name=api_key.name,
        scopes=api_key.scopes,
        created_at=api_key.created_at,
    )


@router.get("/api-keys", response_model=list[ApiKeyResponse])
async def list_api_keys(
    auth: Annotated[AuthContext, Depends(resolve_api_key)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[ApiKeyResponse]:
    """List all API keys for the authenticated user (excludes revoked)."""
    result = await db.execute(
        select(ApiKey).where(
            ApiKey.tenant_id == auth.tenant_id,
            ApiKey.user_id == auth.user_id,
            ApiKey.revoked_at.is_(None),
        )
    )
    keys = result.scalars().all()

    return [
        ApiKeyResponse(
            id=k.id,
            key_prefix=k.key_prefix,
            name=k.name,
            scopes=k.scopes,
            created_at=k.created_at,
            last_used_at=k.last_used_at,
        )
        for k in keys
    ]


@router.delete("/api-keys/{api_key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(
    http_request: Request,
    api_key_id: str,
    auth: Annotated[AuthContext, Depends(resolve_api_key)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    """Revoke an API key (soft delete - sets revoked_at timestamp).

    Preserves audit trail. Revoked keys are rejected at auth time.
    """
    await check_tenant_active(db, auth.tenant_id)
    _require_key_management_scope(auth)

    result = await db.execute(
        select(ApiKey).where(
            ApiKey.id == uuid_mod.UUID(api_key_id),
            ApiKey.tenant_id == auth.tenant_id,
            ApiKey.user_id == auth.user_id,
            ApiKey.revoked_at.is_(None),
        )
    )
    key = result.scalar_one_or_none()
    if not key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found.")

    await db.execute(
        update(ApiKey)
        .where(ApiKey.id == key.id)
        .values(revoked_at=datetime.now(UTC))
    )

    await log_event(
        db,
        tenant_id=auth.tenant_id,
        user_id=auth.user_id,
        action="key.revoke",
        resource_type="api_key",
        resource_id=str(key.id),
        detail={"key_id": key.key_id},
        ip_address=http_request.client.host if http_request.client else None,
    )

    logger.info("Revoked API key key_id=%s by user=%s", key.key_id, auth.user_id)

    # ct-2106: churn_signal only when this revoke leaves NO active keys, the user has
    # fully disconnected all CLI access (strong disengagement). Rotations (revoke one
    # of several, or revoke-then-recreate) keep >=1 active key and do NOT fire. The
    # revoke UPDATE above ran in this same session, so this count sees revoked_at set
    # on this key. No-op unless the hosted backend is registered.
    remaining_active = (
        await db.execute(
            select(func.count(ApiKey.id)).where(
                ApiKey.tenant_id == auth.tenant_id,
                ApiKey.revoked_at.is_(None),
            )
        )
    ).scalar() or 0
    if remaining_active == 0:
        tenant = (
            await db.execute(select(Tenant).where(Tenant.id == auth.tenant_id))
        ).scalar_one_or_none()
        await emit_funnel_event(
            "churn_signal",
            distinct_id=str(auth.tenant_id),
            properties={"churn_kind": "key_revoke"},
            is_internal=tenant_is_internal(tenant),
        )


@router.put("/api-keys/{api_key_id}", response_model=ApiKeyResponse)
async def rename_api_key(
    http_request: Request,
    api_key_id: uuid_mod.UUID,
    request: ApiKeyUpdateRequest,
    auth: Annotated[AuthContext, Depends(resolve_api_key)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ApiKeyResponse:
    """Rename an API key.

    Updates the display name for an existing, non-revoked API key
    belonging to the authenticated user.
    """
    await check_tenant_active(db, auth.tenant_id)
    _require_key_management_scope(auth)

    result = await db.execute(
        select(ApiKey).where(
            ApiKey.id == api_key_id,
            ApiKey.tenant_id == auth.tenant_id,
            ApiKey.user_id == auth.user_id,
            ApiKey.revoked_at.is_(None),
        )
    )
    key = result.scalar_one_or_none()
    if not key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found.")

    await db.execute(
        update(ApiKey)
        .where(ApiKey.id == key.id)
        .values(name=request.name)
    )

    await log_event(
        db,
        tenant_id=auth.tenant_id,
        user_id=auth.user_id,
        action="key.rename",
        resource_type="api_key",
        resource_id=str(key.id),
        detail={"key_id": key.key_id, "new_name": request.name},
        ip_address=http_request.client.host if http_request.client else None,
    )

    logger.info("Renamed API key key_id=%s by user=%s", key.key_id, auth.user_id)

    return ApiKeyResponse(
        id=key.id,
        key_prefix=key.key_prefix,
        name=request.name,
        scopes=key.scopes,
        created_at=key.created_at,
        last_used_at=key.last_used_at,
    )


@router.post("/api-keys/{api_key_id}/rotate", response_model=ApiKeyRotateResponse)
async def rotate_api_key(
    http_request: Request,
    api_key_id: uuid_mod.UUID,
    auth: Annotated[AuthContext, Depends(resolve_api_key)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ApiKeyRotateResponse:
    """Rotate an API key by revoking the old one and creating a new one.

    The new key inherits the name and scopes of the old key.
    Returns the full new key (shown only once).
    """
    await check_tenant_active(db, auth.tenant_id)
    _require_key_management_scope(auth)

    # Find the existing key
    result = await db.execute(
        select(ApiKey).where(
            ApiKey.id == api_key_id,
            ApiKey.tenant_id == auth.tenant_id,
            ApiKey.user_id == auth.user_id,
            ApiKey.revoked_at.is_(None),
        ).with_for_update()
    )
    old_key = result.scalar_one_or_none()
    if not old_key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found.")
    if not set(old_key.scopes).issubset(set(auth.scopes)):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot rotate a key with scopes outside the caller key scopes.",
        )

    # Revoke old key
    revoke_result = await db.execute(
        update(ApiKey)
        .where(ApiKey.id == old_key.id, ApiKey.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC))
    )
    if getattr(revoke_result, "rowcount", 1) != 1:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found.")

    # Generate new key with an explicit session nonce
    raw_key, new_key_id, secret = generate_api_key()
    new_nonce = secrets.token_hex(16)
    new_api_key = ApiKey(
        user_id=auth.user_id,
        tenant_id=auth.tenant_id,
        key_id=new_key_id,
        key_hash=hash_api_key(secret),
        key_prefix=f"ctx_{new_key_id}...",
        name=old_key.name,
        scopes=old_key.scopes,
        session_nonce=new_nonce,
    )
    db.add(new_api_key)
    await db.flush()

    await log_event(
        db,
        tenant_id=auth.tenant_id,
        user_id=auth.user_id,
        action="key.rotate",
        resource_type="api_key",
        resource_id=str(new_api_key.id),
        detail={
            "old_key_id": old_key.key_id,
            "new_key_id": new_key_id,
            "name": old_key.name,
        },
        ip_address=http_request.client.host if http_request.client else None,
    )

    logger.info(
        "Rotated API key old_key_id=%s -> new_key_id=%s by user=%s",
        old_key.key_id, new_key_id, auth.user_id,
    )

    return ApiKeyRotateResponse(
        api_key=raw_key,
        api_key_prefix=f"ctx_{new_key_id}...",
        id=new_api_key.id,
        name=new_api_key.name,
        scopes=new_api_key.scopes,
        created_at=new_api_key.created_at,
    )
