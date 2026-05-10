"""Native app to browser session handoff."""

import hashlib
import logging
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, Request, status
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from contextify_cloud.config import settings
from contextify_cloud.middleware.auth import AuthContext
from contextify_cloud.middleware.jwt_auth import create_browser_session_token
from contextify_cloud.models import (
    Account,
    ApiKey,
    BrowserHandoffToken,
    Tenant,
    User,
)
from contextify_cloud.services.browser_auth import (
    BrowserLoginResult,
    _browser_login_result,
    create_user_session,
)
from contextify_cloud.services.safe_redirects import safe_cloud_path
from contextify_cloud.utils.email import hash_ip_for_logs

logger = logging.getLogger(__name__)


class BrowserHandoffError(Exception):
    """Expected browser-handoff failure."""


@dataclass(frozen=True)
class BrowserHandoffIssueResult:
    handoff_url: str
    expires_at: datetime
    email: str
    tenant_name: str
    target_path: str


@dataclass(frozen=True)
class BrowserHandoffConsumeResult:
    login: BrowserLoginResult
    session_token: str
    target_path: str


def _hash_handoff_token(raw_token: str) -> str:
    payload = f"browser-handoff-v1:{settings.api_secret_key}:{raw_token}".encode()
    return hashlib.sha256(payload).hexdigest()


def _hash_user_agent(user_agent: str | None) -> str | None:
    if not user_agent:
        return None
    payload = f"{user_agent}|{settings.api_secret_key}".encode()
    return hashlib.sha256(payload).hexdigest()


def _client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    peer_ip = request.client.host if request.client else None
    if peer_ip in {"127.0.0.1", "::1"} and forwarded:
        return forwarded.split(",", 1)[0].strip() or peer_ip
    return peer_ip


def _handoff_base_url() -> str:
    return settings.email_base_url.rstrip("/")


def _build_handoff_url(raw_token: str) -> str:
    return f"{_handoff_base_url()}/cloud/login/handoff?token={raw_token}"


async def issue_browser_handoff_token(
    db: AsyncSession,
    *,
    auth: AuthContext,
    target_path: str,
    device_id: str | None,
    device_name: str | None,
    request: Request,
) -> BrowserHandoffIssueResult:
    """Create a short-lived one-time token for native-to-browser handoff."""
    if not settings.enable_browser_handoff:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")

    safe_target = safe_cloud_path(target_path)
    if safe_target is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="target_path must be a local /cloud path.",
        )

    result = await db.execute(
        select(ApiKey, User, Account, Tenant)
        .join(
            User,
            and_(ApiKey.user_id == User.id, ApiKey.tenant_id == User.tenant_id),
        )
        .join(Account, Account.id == User.account_id)
        .join(Tenant, Tenant.id == ApiKey.tenant_id)
        .where(
            ApiKey.key_id == auth.key_id,
            ApiKey.revoked_at.is_(None),
            User.id == auth.user_id,
            User.tenant_id == auth.tenant_id,
            User.removed_at.is_(None),
            Account.status != "disabled",
            Tenant.status == "active",
        )
    )
    row = result.first()
    if row is None:
        logger.warning(
            "Browser handoff rejected for key_id=%s user=%s tenant=%s",
            auth.key_id,
            auth.user_id,
            auth.tenant_id,
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key.")

    api_key, user, account, tenant = row
    now = datetime.now(UTC)
    expires_at = now + timedelta(seconds=settings.browser_handoff_token_ttl_seconds)
    raw_token = secrets.token_urlsafe(32)
    handoff = BrowserHandoffToken(
        id=uuid.uuid4(),
        token_hash=_hash_handoff_token(raw_token),
        account_id=account.id,
        tenant_id=tenant.id,
        user_id=user.id,
        api_key_id=api_key.id,
        target_path=safe_target,
        device_id=device_id,
        device_name=device_name,
        created_ip_hash=hash_ip_for_logs(_client_ip(request)),
        user_agent_hash=_hash_user_agent(request.headers.get("user-agent")),
        expires_at=expires_at,
    )
    db.add(handoff)
    await db.commit()

    logger.info(
        "Browser handoff issued: token_id=%s key_id=%s tenant=%s target=%s",
        handoff.id,
        auth.key_id,
        tenant.id,
        safe_target,
    )
    return BrowserHandoffIssueResult(
        handoff_url=_build_handoff_url(raw_token),
        expires_at=expires_at,
        email=account.email_display,
        tenant_name=tenant.name,
        target_path=safe_target,
    )


async def lookup_browser_handoff_account(
    db: AsyncSession,
    *,
    raw_token: str,
) -> tuple[uuid.UUID, str] | None:
    """Return account/target for a currently usable token without consuming it."""
    if not raw_token or len(raw_token) < 8:
        return None
    result = await db.execute(
        select(BrowserHandoffToken.account_id, BrowserHandoffToken.target_path).where(
            BrowserHandoffToken.token_hash == _hash_handoff_token(raw_token),
            BrowserHandoffToken.consumed_at.is_(None),
            BrowserHandoffToken.expires_at > datetime.now(UTC),
        )
    )
    row = result.first()
    if row is None:
        return None
    account_id, target_path = row
    return account_id, target_path


async def consume_browser_handoff_token(
    db: AsyncSession,
    *,
    raw_token: str,
    request: Request,
) -> BrowserHandoffConsumeResult:
    """Consume a browser handoff token and create a normal browser session."""
    if not settings.enable_browser_handoff:
        raise BrowserHandoffError("handoff_disabled")
    if not raw_token or len(raw_token) < 8:
        raise BrowserHandoffError("token_invalid")

    now = datetime.now(UTC)
    result = await db.execute(
        select(BrowserHandoffToken, Account, User, Tenant, ApiKey)
        .join(Account, Account.id == BrowserHandoffToken.account_id)
        .join(
            User,
            and_(
                User.id == BrowserHandoffToken.user_id,
                User.account_id == BrowserHandoffToken.account_id,
                User.tenant_id == BrowserHandoffToken.tenant_id,
            ),
        )
        .join(
            ApiKey,
            and_(
                ApiKey.id == BrowserHandoffToken.api_key_id,
                ApiKey.user_id == BrowserHandoffToken.user_id,
                ApiKey.tenant_id == BrowserHandoffToken.tenant_id,
            ),
        )
        .join(Tenant, Tenant.id == BrowserHandoffToken.tenant_id)
        .where(
            BrowserHandoffToken.token_hash == _hash_handoff_token(raw_token),
            BrowserHandoffToken.consumed_at.is_(None),
            BrowserHandoffToken.expires_at > now,
            Account.status != "disabled",
            User.removed_at.is_(None),
            Tenant.status == "active",
            ApiKey.revoked_at.is_(None),
            or_(ApiKey.expires_at.is_(None), ApiKey.expires_at > now),
            ApiKey.scopes.contains(["sync"]),
        )
        .with_for_update()
    )
    row = result.first()
    if row is None:
        raise BrowserHandoffError("token_invalid")

    handoff, account, user, tenant, _api_key = row
    handoff.consumed_at = now
    handoff.consumed_ip_hash = hash_ip_for_logs(_client_ip(request))
    if account.status == "password_unset":
        account.status = "active"

    session = await create_user_session(
        db,
        account=account,
        user=user,
        tenant=tenant,
        request_ip=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    account.last_login_at = now
    login = _browser_login_result(account=account, user=user, tenant=tenant, session=session)
    session_token = create_browser_session_token(
        account_id=login.account_id,
        session_id=login.session_id,
        user_id=login.user_id,
        tenant_id=login.tenant_id,
        role=login.role,
        nonce=login.session_nonce,
        session_version=login.session_version,
    )
    await db.commit()

    logger.info(
        "Browser handoff consumed: token_id=%s tenant=%s target=%s",
        handoff.id,
        tenant.id,
        handoff.target_path,
    )
    return BrowserHandoffConsumeResult(
        login=login,
        session_token=session_token,
        target_path=handoff.target_path,
    )
