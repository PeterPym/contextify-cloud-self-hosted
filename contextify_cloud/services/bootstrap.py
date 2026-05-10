"""Self-hosted first-admin bootstrap service."""

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from contextify_cloud.config import settings
from contextify_cloud.models import Account, Tenant, User
from contextify_cloud.services.browser_auth import (
    BrowserAuthError,
    BrowserLoginResult,
    _browser_login_result,
    create_user_session,
    hash_password,
)
from contextify_cloud.services.tenant import _sanitize_slug, provision_tenant
from contextify_cloud.utils.email import normalize_email

logger = logging.getLogger(__name__)

_BOOTSTRAP_ADVISORY_LOCK_ID = 16480684


class BootstrapUnavailableError(Exception):
    """Raised when first-admin bootstrap is disabled or already locked."""


@dataclass(frozen=True)
class BootstrapAdminResult:
    login: BrowserLoginResult
    account: Account
    tenant: Tenant
    user: User


async def acquire_bootstrap_lock(db: AsyncSession) -> None:
    """Serialize first-admin creation attempts within the database."""
    await db.execute(text("SELECT pg_advisory_xact_lock(:lock_id)"), {
        "lock_id": _BOOTSTRAP_ADVISORY_LOCK_ID,
    })


async def first_admin_exists(db: AsyncSession) -> bool:
    """Return True once any active owner/admin exists in the instance."""
    result = await db.execute(
        select(func.count(User.id)).where(
            User.removed_at.is_(None),
            User.role.in_(("owner", "admin")),
        )
    )
    return (result.scalar() or 0) > 0


async def create_first_admin(
    db: AsyncSession,
    *,
    email: str,
    password: str,
    name: str,
    team_name: str,
    request_ip: str | None,
    user_agent: str | None,
) -> BootstrapAdminResult:
    """Create the initial self-hosted owner account and browser session."""
    if not settings.self_hosted:
        raise BootstrapUnavailableError("First-admin setup is only available in self-hosted mode.")

    await acquire_bootstrap_lock(db)
    if await first_admin_exists(db):
        raise BootstrapUnavailableError("This server already has an admin account.")

    email_clean = email.strip()
    normalized = normalize_email(email_clean)
    if not normalized or "@" not in normalized:
        raise BrowserAuthError("Enter a valid email address.")
    if len(password) < 10:
        raise BrowserAuthError("Password must be at least 10 characters.")

    display_name = name.strip() or email_clean.split("@")[0]
    tenant_display_name = team_name.strip() or "Contextify Self-Hosted"
    tenant_slug = _sanitize_slug(tenant_display_name)

    existing_account = await db.execute(
        select(Account).where(Account.email_normalized == normalized)
    )
    if existing_account.scalar_one_or_none() is not None:
        raise BrowserAuthError("An account with this email already exists.")

    existing_tenant = await db.execute(select(Tenant).where(Tenant.slug == tenant_slug))
    if existing_tenant.scalar_one_or_none() is not None:
        raise BrowserAuthError(f"Team name '{tenant_display_name}' is already taken.")

    now = datetime.now(UTC)
    account = Account(
        email_normalized=normalized,
        email_display=email_clean,
        password_hash=await asyncio.to_thread(hash_password, password),
        email_verified_at=now,
        status="active",
        tos_accepted_at=now,
        tos_version=settings.tos_version,
        tos_ip=request_ip,
        tos_user_agent=user_agent,
        created_at=now,
        updated_at=now,
    )
    db.add(account)
    await db.flush()

    tenant, user, _ = await provision_tenant(
        db=db,
        name=tenant_display_name,
        slug=tenant_slug,
        email=email_clean,
        user_name=display_name,
        create_default_api_key=False,
    )
    user.account_id = account.id
    await db.flush()

    session = await create_user_session(
        db,
        account=account,
        user=user,
        tenant=tenant,
        request_ip=request_ip,
        user_agent=user_agent,
    )

    logger.info(
        "Self-hosted first admin created: account=%s tenant=%s user=%s",
        account.id,
        tenant.id,
        user.id,
    )
    return BootstrapAdminResult(
        login=_browser_login_result(
            account=account,
            user=user,
            tenant=tenant,
            session=session,
        ),
        account=account,
        tenant=tenant,
        user=user,
    )
