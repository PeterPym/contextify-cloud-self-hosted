"""JWT-based session authentication for the web dashboard.

This module provides cookie-based JWT authentication for browser sessions.
It is separate from the API key auth in auth.py, which handles programmatic
access via X-API-Key / Authorization: Bearer headers.

Flow:
1. User logs in with email + password on /cloud/login
2. Server creates a user_sessions row, creates a JWT, sets it as an HttpOnly cookie
3. Subsequent requests to /cloud/* include the cookie automatically
4. resolve_jwt_session() extracts and validates the JWT, returning AuthContext
"""

import logging
import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from typing import NotRequired, TypedDict, cast

import jwt
from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from contextify_cloud.config import settings
from contextify_cloud.database import get_db
from contextify_cloud.middleware.auth import AuthContext
from contextify_cloud.models import Account, User, UserSession

logger = logging.getLogger(__name__)

JWT_ALGORITHM = "HS256"
JWT_COOKIE_NAME = "ctx_session"

_VALID_ROLES = {"owner", "admin", "member", "viewer"}


class JwtPayload(TypedDict):
    """Decoded JWT payload.

    Only sub/tid/role/exp/iat are guaranteed by decode_jwt_token. The
    other fields are claim-set-dependent:
      - kid is present on legacy API-key-derived JWTs (no longer accepted
        by resolve_jwt_session, kept for decode compatibility)
      - sid/aid/sv/nonce are present on browser-session JWTs and required
        by resolve_jwt_session before issuing an AuthContext
    """

    sub: str
    tid: str
    role: str
    exp: int
    iat: int
    kid: NotRequired[str]
    nonce: NotRequired[str]
    sid: NotRequired[str]
    aid: NotRequired[str]
    sv: NotRequired[int]


def create_browser_session_token(
    *,
    account_id: uuid.UUID,
    session_id: uuid.UUID,
    user_id: uuid.UUID,
    tenant_id: uuid.UUID,
    role: str,
    nonce: str,
    session_version: int,
) -> str:
    """Create a JWT cookie token backed by a user_sessions row."""
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "aid": str(account_id),
        "sid": str(session_id),
        "tid": str(tenant_id),
        "role": role,
        "nonce": nonce,
        "sv": session_version,
        "exp": now + timedelta(hours=settings.jwt_token_expire_hours),
        "iat": now,
    }
    return jwt.encode(payload, settings.api_secret_key, algorithm=JWT_ALGORITHM)


def create_jwt_token(
    user_id: uuid.UUID,
    tenant_id: uuid.UUID,
    role: str,
    key_id: str,
    nonce: str,
) -> str:
    """Create a signed JWT token for a browser session.

    Args:
        user_id: The authenticated user's UUID.
        tenant_id: The tenant UUID the user belongs to.
        role: The user's role in the tenant (owner, admin, member, viewer).
        key_id: The API key_id used to authenticate (safe to embed, non-secret).
        nonce: The session_nonce from the API key row. Embedded in the JWT
            and validated on each request to enable server-side session revocation.

    Returns:
        A signed JWT string.
    """
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "tid": str(tenant_id),
        "role": role,
        "kid": key_id,
        "nonce": nonce,
        "exp": now + timedelta(hours=settings.jwt_token_expire_hours),
        "iat": now,
    }
    return jwt.encode(payload, settings.api_secret_key, algorithm=JWT_ALGORITHM)


def decode_jwt_token(token: str) -> JwtPayload:
    """Validate and decode a JWT token.

    Args:
        token: The raw JWT string.

    Returns:
        The decoded payload with all required claims.

    Raises:
        jwt.ExpiredSignatureError: If the token has expired.
        jwt.InvalidTokenError: If the token is tampered with or malformed.
    """
    payload = jwt.decode(
        token,
        settings.api_secret_key,
        algorithms=[JWT_ALGORITHM],
        options={"require": ["sub", "tid", "role", "exp", "iat"]},
    )
    if not isinstance(payload, dict):
        raise jwt.InvalidTokenError("JWT payload must be a JSON object")
    return cast(JwtPayload, payload)


async def get_jwt_check_db() -> AsyncGenerator[AsyncSession]:
    """DB session for JWT key revocation checks.

    Separate from get_db so tests can override this independently without
    disrupting the FakeSession result sequence used by route handlers.
    In production, yields a real DB session. Tests may override this with a
    request-scoped fake DB session that exercises the same validation contract.
    """
    async for session in get_db():
        yield session


async def resolve_jwt_session(
    request: Request,
    jwt_db: AsyncSession = Depends(get_jwt_check_db),
) -> AuthContext:
    """FastAPI dependency that resolves a JWT session cookie to an AuthContext.

    Reads the ctx_session cookie from the request, decodes the JWT, and
    returns an AuthContext with the same shape as API key auth. This allows
    dashboard routes to use the same authorization patterns as API routes.

    Performs a lightweight DB check to ensure the underlying API key has not
    been revoked (e.g., when a team member is removed). This ensures removed
    users lose dashboard access immediately rather than at JWT expiry.

    If the cookie is missing or the token is invalid, redirects to /cloud/login
    with a 303 status code (appropriate for browser navigation).

    The DB check uses a separate dependency (get_jwt_check_db) so it can be
    independently overridden in tests without disrupting FakeSession sequences.
    """
    token = request.cookies.get(JWT_COOKIE_NAME)
    if not token:
        logger.debug("No JWT session cookie, redirecting to login")
        raise HTTPException(
            status_code=303,
            headers={"Location": "/cloud/login"},
            detail="Not authenticated",
        )

    try:
        payload = decode_jwt_token(token)
    except jwt.ExpiredSignatureError:
        logger.info("Expired JWT session, redirecting to login")
        raise HTTPException(
            status_code=303,
            headers={"Location": "/cloud/login"},
            detail="Session expired",
        )
    except jwt.InvalidTokenError:
        logger.warning("Invalid JWT session token, redirecting to login")
        raise HTTPException(
            status_code=303,
            headers={"Location": "/cloud/login"},
            detail="Invalid session",
        )

    try:
        user_id = uuid.UUID(payload["sub"])
        tenant_id = uuid.UUID(payload["tid"])
        role = payload["role"]
        key_id = payload.get("kid", "")
        session_id = payload.get("sid")
        account_id = payload.get("aid")
        nonce = payload.get("nonce")
    except (KeyError, TypeError, ValueError) as e:
        logger.warning("Invalid JWT session claims: %s", e)
        raise HTTPException(
            status_code=303,
            headers={"Location": "/cloud/login"},
            detail="Invalid session",
        )

    if role not in _VALID_ROLES:
        logger.warning("Invalid role in JWT session: %r", role)
        raise HTTPException(
            status_code=303,
            headers={"Location": "/cloud/login"},
            detail="Invalid session",
        )

    if not session_id:
        logger.info("Rejecting legacy API-key-derived dashboard session")
        raise HTTPException(
            status_code=303,
            headers={"Location": "/cloud/login"},
            detail="Session invalidated",
        )

    if not nonce:
        # Browser-session tokens always include a nonce. A missing nonce
        # means the token is malformed or pre-migration; reject before
        # touching the DB rather than letting the str != None compare
        # silently invalidate.
        logger.warning("Browser-session JWT missing nonce claim")
        raise HTTPException(
            status_code=303,
            headers={"Location": "/cloud/login"},
            detail="Invalid session",
        )

    session_uuid: uuid.UUID
    account_uuid: uuid.UUID
    try:
        session_uuid = uuid.UUID(str(session_id))
        account_uuid = uuid.UUID(str(account_id))
    except (TypeError, ValueError) as e:
        logger.warning("Invalid browser session claims: %s", e)
        raise HTTPException(
            status_code=303,
            headers={"Location": "/cloud/login"},
            detail="Invalid session",
        )

    if jwt_db is None:
        logger.error(
            "JWT session DB validation unavailable because jwt_db is None "
            "(session=%s tenant=%s user=%s); this should never happen in production",
            session_uuid,
            tenant_id,
            user_id,
        )
        raise HTTPException(
            status_code=303,
            headers={"Location": "/cloud/login"},
            detail="Session invalidated",
        )

    try:
        result = await jwt_db.execute(
            select(UserSession, Account, User)
            .join(Account, Account.id == UserSession.account_id)
            .join(User, User.id == UserSession.user_id)
            .where(
                UserSession.id == session_uuid,
                UserSession.account_id == account_uuid,
                UserSession.tenant_id == tenant_id,
                UserSession.user_id == user_id,
                UserSession.revoked_at.is_(None),
                UserSession.expires_at > datetime.now(UTC),
                # Allow-list: Account.status enum is
                # ('active', 'password_unset', 'disabled'). Only 'active'
                # accounts can complete login_with_password, so any other
                # status on a live session is anomalous.
                Account.status == "active",
                # Defense-in-depth: ensure the user row's own tenant
                # and account IDs match the JWT claims, not just the
                # UserSession row's foreign keys.
                User.tenant_id == tenant_id,
                User.account_id == account_uuid,
                User.removed_at.is_(None),
            )
        )
        row = result.first()
        if row is None:
            logger.info("Browser session not found or revoked: session=%s", session_uuid)
            raise HTTPException(
                status_code=303,
                headers={"Location": "/cloud/login"},
                detail="Session invalidated",
            )
        db_session, account, user = row
        if nonce != db_session.session_nonce:
            logger.info("Browser session nonce mismatch: session=%s", session_uuid)
            raise HTTPException(
                status_code=303,
                headers={"Location": "/cloud/login"},
                detail="Session invalidated",
            )
        if payload.get("sv") != account.session_version:
            logger.info("Browser session version mismatch: account=%s", account.id)
            raise HTTPException(
                status_code=303,
                headers={"Location": "/cloud/login"},
                detail="Session invalidated",
            )
        db_role = user.role
        if db_role not in _VALID_ROLES:
            logger.warning(
                "Invalid role on browser-session user row: user=%s role=%r",
                user.id,
                db_role,
            )
            raise HTTPException(
                status_code=303,
                headers={"Location": "/cloud/login"},
                detail="Session invalidated",
            )
        role = db_role
    except HTTPException:
        raise
    except Exception:
        logger.warning(
            "Browser session check failed, denying session (tenant=%s user=%s)",
            tenant_id,
            user_id,
            exc_info=True,
        )
        raise HTTPException(
            status_code=303,
            headers={"Location": "/cloud/login"},
            detail="Session invalidated",
        )

    key_id = f"session:{str(session_uuid)[:8]}"

    # Set contextvars for structured logging enrichment (consistent with API key auth)
    from contextify_cloud.middleware.logging import tenant_id_var, user_id_var

    tenant_id_var.set(str(tenant_id))
    user_id_var.set(str(user_id))
    # Also store on request.state for MetricsMiddleware (BaseHTTPMiddleware
    # does not reliably propagate contextvar changes back upstream).
    request.state.tenant_id = str(tenant_id)
    request.state.user_id = str(user_id)
    request.state.key_id = key_id

    return AuthContext(
        user_id=user_id,
        tenant_id=tenant_id,
        scopes=["sync", "search"],  # Dashboard sessions get standard scopes
        key_id=key_id,
        role=role,
        account_id=uuid.UUID(str(account_id)) if account_id else None,
        session_id=uuid.UUID(str(session_id)) if session_id else None,
    )


async def resolve_optional_jwt_session(
    request: Request,
    jwt_db: AsyncSession = Depends(get_jwt_check_db),
) -> AuthContext | None:
    """Like resolve_jwt_session but returns None for unauthenticated requests.

    Used by routes that render different content for signed-in vs anonymous
    callers (e.g., GET /cloud/device renders the magic-link signup/sign-in
    form for anonymous users and the device-code entry form for signed-in
    users). Catches the 303-redirect HTTPException raised by the strict
    variant and returns None instead. Other errors propagate.
    """
    try:
        return await resolve_jwt_session(request, jwt_db)
    except HTTPException as exc:
        if exc.status_code == 303:
            return None
        raise
