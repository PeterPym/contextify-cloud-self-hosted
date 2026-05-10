"""Browser auth services for email/password dashboard login."""

import asyncio
import base64
import hashlib
import hmac
import logging
import secrets
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import bcrypt
from sqlalchemy import or_, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from contextify_cloud.config import settings
from contextify_cloud.database import async_session_factory
from contextify_cloud.models import (
    Account,
    AuthToken,
    DeviceAuthorization,
    Tenant,
    User,
    UserSession,
)
from contextify_cloud.services.email import (
    send_email_change_confirmation,
    send_email_verification,
    send_password_reset,
    send_welcome_email,
)
from contextify_cloud.services.tenant import _sanitize_slug, provision_tenant
from contextify_cloud.utils.email import (
    hash_email_for_logs,
    hash_ip_for_logs,
    normalize_email,
)

logger = logging.getLogger(__name__)

AuthTokenSender = Callable[[str, str], Awaitable[bool]]


class BrowserAuthError(Exception):
    """Expected user-facing auth failure."""


@dataclass(frozen=True)
class BrowserLoginResult:
    account_id: uuid.UUID
    session_id: uuid.UUID
    user_id: uuid.UUID
    tenant_id: uuid.UUID
    role: str
    session_nonce: str
    session_version: int
    email_normalized: str
    tenant_slug: str


def _browser_login_result(
    *,
    account: Account,
    user: User,
    tenant: Tenant,
    session: UserSession,
) -> BrowserLoginResult:
    """Snapshot session claim fields before commit expires ORM attributes."""
    return BrowserLoginResult(
        account_id=account.id,
        session_id=session.id,
        user_id=user.id,
        tenant_id=tenant.id,
        role=user.role,
        session_nonce=session.session_nonce,
        session_version=account.session_version or 1,
        email_normalized=account.email_normalized,
        tenant_slug=tenant.slug,
    )


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())


def _hash_token(raw_token: str) -> str:
    payload = f"{settings.api_secret_key}:{raw_token}".encode()
    return hashlib.sha256(payload).hexdigest()


def generate_auth_token() -> str:
    return secrets.token_urlsafe(32)


def _raw_token_for_auth_token(token_id: uuid.UUID, purpose: str) -> str:
    """Reconstruct a raw auth token without storing plaintext in the database."""
    payload = f"auth-token-v1:{token_id}:{purpose}".encode()
    signature = hmac.new(
        settings.api_secret_key.encode(),
        payload,
        hashlib.sha256,
    ).digest()
    token_bytes = token_id.bytes + signature
    return base64.urlsafe_b64encode(token_bytes).decode().rstrip("=")


def _delivery_error_summary(workflow: str, sent_to: str) -> str:
    return f"{workflow} delivery failed for {sent_to}"


async def _lock_auth_token_replacement(
    db: AsyncSession,
    *,
    account: Account | None,
    email: str,
    purpose: str,
) -> None:
    identity = f"account:{account.id}" if account else f"email:{normalize_email(email)}"
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))").bindparams(
            key=f"auth-token:{purpose}:{identity}"
        )
    )


async def _revoke_account_tokens(
    db: AsyncSession,
    *,
    account_id: uuid.UUID,
    purposes: tuple[str, ...],
) -> None:
    """Revoke outstanding account-scoped auth tokens for the given purposes.

    Used after identity changes (password reset/change, email change) so prior-
    issued links cannot be replayed against the post-change account.
    """
    if not purposes:
        return
    await db.execute(
        update(AuthToken)
        .where(
            AuthToken.account_id == account_id,
            AuthToken.purpose.in_(purposes),
            AuthToken.consumed_at.is_(None),
        )
        .values(consumed_at=datetime.now(UTC))
    )


async def create_auth_token(
    db: AsyncSession,
    *,
    account: Account | None,
    email: str,
    purpose: str,
    expires_in: timedelta,
    metadata: dict[str, object] | None = None,
) -> str:
    _token, raw_token = await create_auth_token_record(
        db,
        account=account,
        email=email,
        purpose=purpose,
        expires_in=expires_in,
        metadata=metadata,
    )
    return raw_token


async def create_auth_token_record(
    db: AsyncSession,
    *,
    account: Account | None,
    email: str,
    purpose: str,
    expires_in: timedelta,
    metadata: dict[str, object] | None = None,
    skip_prior_invalidation: bool = False,
) -> tuple[AuthToken, str]:
    """Insert a new ``AuthToken`` row, optionally invalidating prior ones.

    By default, any prior unconsumed AuthToken with the same
    ``(purpose, account_id)`` or ``(purpose, email_normalized)`` pair is
    consumed first so a fresh issuance supersedes the old one. Pass
    ``skip_prior_invalidation=True`` when the caller wants to apply a
    narrower scope (e.g. the device-flow helper invalidates per
    ``device_authorization_id`` rather than per email — ct-1512 finding
    B4 — to avoid clobbering a parallel device flow on the same inbox).
    """
    now = datetime.now(UTC)
    await _lock_auth_token_replacement(
        db,
        account=account,
        email=email,
        purpose=purpose,
    )
    if not skip_prior_invalidation:
        replacement = update(AuthToken).where(
            AuthToken.purpose == purpose,
            AuthToken.consumed_at.is_(None),
        )
        if account is not None:
            # Account-scoped invalidation covers email_change tokens whose target
            # email differs across requests.
            replacement = replacement.where(AuthToken.account_id == account.id)
        else:
            replacement = replacement.where(
                AuthToken.email_normalized == normalize_email(email)
            )
        await db.execute(replacement.values(consumed_at=now))
    token_id = uuid.uuid4()
    raw_token = _raw_token_for_auth_token(token_id, purpose)
    token = AuthToken(
        id=token_id,
        account_id=account.id if account else None,
        email_normalized=normalize_email(email),
        purpose=purpose,
        token_hash=_hash_token(raw_token),
        sent_to=email.strip(),
        metadata_json=metadata,
        expires_at=now + expires_in,
        delivery_status="pending",
        delivery_attempts=0,
        delivery_next_attempt_at=now,
    )
    db.add(token)
    await db.flush()
    return token, raw_token


async def _record_auth_token_delivery_result(
    db: AsyncSession,
    *,
    token: AuthToken,
    sent: bool,
    error_summary: str | None,
) -> tuple[str, int]:
    now = datetime.now(UTC)
    attempts = (token.delivery_attempts or 0) + 1
    token.delivery_attempts = attempts
    if sent:
        token.delivery_status = "sent"
        token.delivery_sent_at = now
        token.delivery_next_attempt_at = None
        token.delivery_last_error = None
    else:
        exhausted = attempts >= settings.auth_email_delivery_max_attempts
        token.delivery_status = "exhausted" if exhausted else "failed"
        token.delivery_sent_at = None
        token.delivery_next_attempt_at = (
            None if exhausted
            else now + timedelta(seconds=settings.auth_email_retry_delay_seconds)
        )
        token.delivery_last_error = error_summary
    status = token.delivery_status
    attempt_count = token.delivery_attempts
    await db.commit()
    return status, attempt_count


async def deliver_auth_token_email(
    db: AsyncSession,
    *,
    token: AuthToken,
    raw_token: str,
    sender: AuthTokenSender,
    workflow: str,
) -> bool:
    """Send one auth-token email and persist retryable delivery state."""
    token_id = token.id
    purpose = token.purpose
    sent_to = token.sent_to
    workflow_name = workflow

    try:
        sent = await sender(sent_to, raw_token)
    except Exception as exc:
        sent = False
        logger.error(
            "Auth token email sender crashed: token_id=%s purpose=%s workflow=%s "
            "error_type=%s event=auth_email_sender_exception",
            token_id,
            purpose,
            workflow_name,
            exc.__class__.__name__,
        )

    error_summary = None if sent else _delivery_error_summary(workflow, token.sent_to)
    status = token.delivery_status
    attempts = token.delivery_attempts or 0
    try:
        status, attempts = await _record_auth_token_delivery_result(
            db,
            token=token,
            sent=sent,
            error_summary=error_summary,
        )
    except Exception:
        await db.rollback()
        logger.exception(
            "Auth token delivery state update failed: token_id=%s purpose=%s sent=%s "
            "event=auth_email_delivery_state_commit_failed",
            token_id,
            purpose,
            sent,
        )
    if sent:
        logger.info(
            "Auth token email delivered: token_id=%s purpose=%s attempts=%s",
            token_id,
            purpose,
            attempts,
        )
    else:
        logger.warning(
            "Auth token email delivery failed: token_id=%s purpose=%s status=%s attempts=%s",
            token_id,
            purpose,
            status,
            attempts,
        )
        if status == "exhausted":
            logger.error(
                "Auth token email delivery exhausted: token_id=%s purpose=%s "
                "attempts=%s event=auth_email_outbox_exhausted",
                token_id,
                purpose,
                attempts,
            )

    # Funnel-stage emission (ct-1512 finding B7): the service layer owns
    # the ``device_flow_email_sent`` / ``device_flow_error`` events for
    # any device-flow / login-magic-link delivery so route handlers do
    # not double-emit the same funnel stage.
    if purpose in _DEVICE_FLOW_EMISSION_PURPOSES:
        device_authorization_id = _device_authorization_id_from_token(token)
        if sent:
            _emit_device_flow_email_sent(
                purpose=purpose,
                token_id=token_id,
                email_normalized=token.email_normalized or "",
                device_authorization_id=device_authorization_id,
                endpoint=workflow,
            )
        else:
            _emit_device_flow_error(
                error_code="email_delivery_failed",
                purpose=purpose,
                token_id=token_id,
                endpoint=workflow,
                email_normalized=token.email_normalized or "",
                device_authorization_id=device_authorization_id,
            )
    return sent


_DEVICE_FLOW_EMISSION_PURPOSES: tuple[str, ...] = (
    "device_login_existing_user",
    "device_signup_new_user",
    "login_magic_link",
)


# ── Background async-send for device-flow / login-magic-link tokens ────
#
# ct-1512 Shard C-fix2 C-2: silent-skip branches must not return faster
# than real-issuance branches, otherwise the email-provider HTTP latency
# dominates and reveals account state. The fix is to push the actual
# Resend call off the request hot-path into a fire-and-forget asyncio
# task. Both real and sentinel branches schedule a task; the sentinel
# task is a structurally-identical no-op (it touches the DB row, finds
# the ``is_sentinel`` flag, exits early without calling Resend). The
# request returns immediately after token commit + task spawn, so the
# email-provider HTTP latency no longer affects request timing.
#
# We deliberately do NOT route device-flow / login-magic-link tokens
# through the existing ``run_auth_email_outbox_once`` sweeper because
# the sweeper has no way to reconstruct the OTP plaintext (only the
# salted hash is stored on metadata). Storing OTP plaintext on the
# token row to enable outbox retry would be a security regression
# (every persisted ``pending`` token would expose its OTP for the
# attempt window). Instead, sender callable + OTP are captured in the
# task's closure for the lifetime of the in-process retry. If the
# in-process send fails, the user simply requests a new email — the
# UX cost is acceptable because device-flow tokens are short-lived
# (10 min) and a resend is one click away.


# Test hook: tests that use a per-test PostgreSQL schema set this to
# their schema-bound async_sessionmaker so the spawned task can find the
# freshly-issued token row. Production never touches this — it stays
# ``None`` and the helper falls back to ``async_session_factory``.
_test_session_factory_override: Callable[[], Any] | None = None


def set_async_send_session_factory_override(
    factory: Callable[[], Any] | None,
) -> None:
    """Test hook to override the session factory used by async sends.

    The conftest auto-fixture installs this with the per-test schema-bound
    sessionmaker so ``_async_send_device_flow_email`` re-loads the token
    from the same schema the request handler wrote to. Production code
    must not call this. ``factory=None`` reverts to ``async_session_factory``.
    """
    global _test_session_factory_override
    _test_session_factory_override = factory


async def _async_send_device_flow_email(
    *,
    token_id: uuid.UUID,
    raw_token: str,
    sender: AuthTokenSender,
    workflow: str,
) -> None:
    """Send a device-flow email asynchronously in a fresh DB session.

    Spawned via ``asyncio.create_task`` from the ``email-init`` request
    handler so the request can return without awaiting Resend's HTTP
    call (ct-1512 Shard C-fix2 C-2 timing-oracle defense). Re-loads the
    AuthToken in a fresh session, refuses to send when the row is a
    sentinel, otherwise delegates to ``deliver_auth_token_email``.

    Crashes (network errors, sender exceptions) are logged but never
    re-raised — the task is fire-and-forget, so an unhandled exception
    would otherwise show up in the asyncio default exception handler
    without context. The token's ``delivery_status`` reflects the final
    outcome (``sent`` / ``failed`` / ``exhausted``).
    """
    factory = _test_session_factory_override or async_session_factory
    try:
        async with factory() as db:
            token = await db.get(AuthToken, token_id)
            if token is None:
                logger.warning(
                    "Async device-flow email send: token disappeared "
                    "before send token_id=%s workflow=%s",
                    token_id,
                    workflow,
                )
                return
            metadata = token.metadata_json or {}
            if metadata.get("is_sentinel") is True:
                # Sentinel branch: structurally-identical DB-touching
                # work but no Resend call. ``delivery_status`` was
                # already stamped to ``exhausted`` at issue time so the
                # outbox sweeper also skips this row.
                logger.info(
                    "Async device-flow email send: sentinel skipped "
                    "token_id=%s purpose=%s workflow=%s",
                    token_id,
                    token.purpose,
                    workflow,
                )
                return
            await deliver_auth_token_email(
                db,
                token=token,
                raw_token=raw_token,
                sender=sender,
                workflow=workflow,
            )
    except Exception:
        logger.exception(
            "Async device-flow email send crashed: token_id=%s workflow=%s",
            token_id,
            workflow,
        )


_pending_device_flow_email_tasks: set["asyncio.Task[None]"] = set()


async def spawn_device_flow_email_send(
    *,
    token_id: uuid.UUID,
    raw_token: str,
    sender: AuthTokenSender,
    workflow: str,
) -> "asyncio.Task[None]":
    """Schedule ``_async_send_device_flow_email`` as a fire-and-forget task.

    Declared ``async`` so tests can replace this helper with a synchronous
    awaiter that runs the send to completion before returning.
    """
    # asyncio holds only a weak ref to created tasks; without a strong ref
    # the GC may cancel the task before the Resend call completes.
    task = asyncio.create_task(
        _async_send_device_flow_email(
            token_id=token_id,
            raw_token=raw_token,
            sender=sender,
            workflow=workflow,
        )
    )
    _pending_device_flow_email_tasks.add(task)
    task.add_done_callback(_pending_device_flow_email_tasks.discard)
    return task


_pending_welcome_email_tasks: set["asyncio.Task[None]"] = set()


async def _send_welcome_email_after_device_signup(
    *,
    to_email: str,
    name: str | None,
    email_normalized: str,
    user_agent: str | None,
) -> None:
    """Send a non-critical welcome email after device-flow signup finalize.

    The auth/device transaction has already committed before this helper is
    spawned, so email-provider/template failures must only be logged — never
    raised, since raising would only surface in the asyncio task's exception
    state and never to the user.
    """
    try:
        sent = await send_welcome_email(
            to_email,
            name,
            user_agent=user_agent,
        )
    except Exception:
        logger.exception(
            "Welcome email send crashed after device-flow signup: account_id_hash=%s",
            hash_email_for_logs(email_normalized),
        )
        return

    if not sent:
        logger.warning(
            "Welcome email send failed after device-flow signup: account_id_hash=%s",
            hash_email_for_logs(email_normalized),
        )


async def spawn_welcome_email_after_device_signup(
    *,
    to_email: str,
    name: str | None,
    email_normalized: str,
    user_agent: str | None,
) -> "asyncio.Task[None]":
    """Schedule the post-signup welcome email without delaying auth finalize.

    Mirrors ``spawn_device_flow_email_send`` so tests can replace this helper
    with a synchronous awaiter that runs the send to completion before the
    test continues. asyncio holds only a weak ref to created tasks; the
    strong-ref set prevents premature GC.
    """
    task = asyncio.create_task(
        _send_welcome_email_after_device_signup(
            to_email=to_email,
            name=name,
            email_normalized=email_normalized,
            user_agent=user_agent,
        )
    )
    _pending_welcome_email_tasks.add(task)
    task.add_done_callback(_pending_welcome_email_tasks.discard)
    return task


def _device_authorization_id_from_token(token: AuthToken) -> uuid.UUID | None:
    """Return the ``device_authorization_id`` stamped on a token, or None."""
    metadata = token.metadata_json or {}
    raw = metadata.get("device_authorization_id")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return uuid.UUID(raw)
    except ValueError:
        return None


async def _send_auth_token_by_purpose(token: AuthToken, raw_token: str) -> bool:
    if token.purpose == "password_reset":
        # Branch subject + body on whether the account has never set a
        # password (cloud-magic-link spec §13a). The flag is stamped at
        # `request_password_reset` time so the email subject is correct
        # for both immediate sends and outbox retries.
        metadata = token.metadata_json or {}
        is_passwordless = bool(metadata.get("is_passwordless"))
        return await send_password_reset(
            token.sent_to, raw_token, is_passwordless=is_passwordless
        )
    if token.purpose == "email_verify":
        return await send_email_verification(token.sent_to, raw_token)
    if token.purpose == "email_change":
        return await send_email_change_confirmation(token.sent_to, raw_token)
    logger.error(
        "Unsupported auth token delivery purpose: token_id=%s purpose=%s",
        token.id,
        token.purpose,
    )
    return False


@dataclass
class AuthEmailOutboxResult:
    attempted: int = 0
    sent: int = 0
    failed: int = 0
    exhausted: int = 0
    errors: list[str] = field(default_factory=list)


async def run_auth_email_outbox_once(*, batch_limit: int = 50) -> AuthEmailOutboxResult:
    """Retry due auth-token email deliveries."""
    result = AuthEmailOutboxResult()
    for _ in range(batch_limit):
        now = datetime.now(UTC)
        async with async_session_factory() as db:
            rows = await db.execute(
                select(AuthToken)
                .where(
                    AuthToken.consumed_at.is_(None),
                    AuthToken.expires_at > now,
                    AuthToken.delivery_status.in_(("pending", "failed")),
                    AuthToken.delivery_attempts < settings.auth_email_delivery_max_attempts,
                    or_(
                        AuthToken.delivery_next_attempt_at.is_(None),
                        AuthToken.delivery_next_attempt_at <= now,
                    ),
                )
                .order_by(AuthToken.created_at.asc())
                .limit(1)
                .with_for_update(skip_locked=True)
            )
            token = rows.scalar_one_or_none()
            if token is None:
                break
            locked_token = token

            result.attempted += 1
            token_id = locked_token.id
            purpose = locked_token.purpose
            attempts_before = locked_token.delivery_attempts or 0
            raw_token = _raw_token_for_auth_token(locked_token.id, locked_token.purpose)
            if locked_token.token_hash != _hash_token(raw_token):
                locked_token.delivery_attempts = attempts_before + 1
                locked_token.delivery_status = "exhausted"
                locked_token.delivery_next_attempt_at = None
                locked_token.delivery_last_error = (
                    "deterministic auth token cannot be reconstructed"
                )
                await db.commit()
                result.exhausted += 1
                logger.error(
                    "Auth token retry skipped: token_id=%s purpose=%s "
                    "reason=token_hash_mismatch event=auth_email_outbox_exhausted",
                    token_id,
                    purpose,
                )
                continue

            async def sender(
                _to: str,
                raw: str,
                *,
                token: AuthToken = locked_token,
            ) -> bool:
                return await _send_auth_token_by_purpose(token, raw)

            try:
                sent = await deliver_auth_token_email(
                    db,
                    token=locked_token,
                    raw_token=raw_token,
                    sender=sender,
                    workflow=f"retry:{purpose}",
                )
            except Exception as exc:
                await db.rollback()
                message = (
                    f"token_id={token_id} purpose={purpose} "
                    f"error_type={exc.__class__.__name__}"
                )
                result.errors.append(message)
                logger.exception("Auth token outbox retry crashed: %s", message)
                continue
            if sent:
                result.sent += 1
            elif locked_token.delivery_status == "exhausted":
                result.exhausted += 1
            else:
                result.failed += 1
    return result


async def consume_auth_token(
    db: AsyncSession,
    *,
    raw_token: str,
    purpose: str,
) -> AuthToken | None:
    now = datetime.now(UTC)
    result = await db.execute(
        update(AuthToken)
        .where(
            AuthToken.token_hash == _hash_token(raw_token),
            AuthToken.purpose == purpose,
            AuthToken.consumed_at.is_(None),
            AuthToken.expires_at > now,
        )
        .values(consumed_at=now)
        .returning(AuthToken)
    )
    token = result.scalar_one_or_none()
    return token


async def peek_password_reset_is_passwordless(
    db: AsyncSession, *, raw_token: str,
) -> bool:
    """Inspect a password-reset token without consuming it.

    Returns True if the linked account had ``password_hash IS NULL`` at
    the time the reset was requested (per ``request_password_reset``
    metadata stamp). Used by the reset/set landing page to adapt copy
    from "Reset your password" to "Set your password" per spec §13a.
    Falls back to False (legacy "Reset" copy) when the token is unknown,
    expired, already consumed, or carries no metadata.
    """
    now = datetime.now(UTC)
    result = await db.execute(
        select(AuthToken).where(
            AuthToken.token_hash == _hash_token(raw_token),
            AuthToken.purpose == "password_reset",
            AuthToken.consumed_at.is_(None),
            AuthToken.expires_at > now,
        )
    )
    token = result.scalar_one_or_none()
    if token is None:
        return False
    metadata = token.metadata_json or {}
    return bool(metadata.get("is_passwordless"))


async def _commit_consumed_token_failure(db: AsyncSession) -> bool:
    await db.commit()
    return False


async def register_with_password(
    db: AsyncSession,
    *,
    email: str,
    password: str,
    name: str,
    team_name: str,
    request_ip: str | None,
    user_agent: str | None,
) -> BrowserLoginResult:
    email_clean = email.strip()
    normalized = normalize_email(email_clean)
    if not normalized or "@" not in normalized:
        raise BrowserAuthError("Enter a valid email address.")
    if len(password) < 10:
        raise BrowserAuthError("Password must be at least 10 characters.")

    existing_account = await db.execute(
        select(Account).where(Account.email_normalized == normalized)
    )
    if existing_account.scalar_one_or_none() is not None:
        raise BrowserAuthError("An account with this email already exists.")

    slug = _sanitize_slug(team_name)
    existing_tenant = await db.execute(select(Tenant).where(Tenant.slug == slug))
    if existing_tenant.scalar_one_or_none() is not None:
        raise BrowserAuthError(f"Team name '{team_name}' is already taken.")

    now = datetime.now(UTC)
    account = Account(
        email_normalized=normalized,
        email_display=email_clean,
        password_hash=await asyncio.to_thread(hash_password, password),
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
        name=team_name,
        slug=slug,
        email=email_clean,
        user_name=name,
        create_default_api_key=False,
    )
    user.account_id = account.id
    await db.flush()

    verify_auth_token, verify_token = await create_auth_token_record(
        db,
        account=account,
        email=email_clean,
        purpose="email_verify",
        expires_in=timedelta(hours=24),
    )
    session = await create_user_session(
        db,
        account=account,
        user=user,
        tenant=tenant,
        request_ip=request_ip,
        user_agent=user_agent,
    )
    login_result = _browser_login_result(
        account=account,
        user=user,
        tenant=tenant,
        session=session,
    )
    await db.commit()

    await send_welcome_email(email_clean, name, user_agent=user_agent)
    logger.info(
        "Queued verification email for new account: token_id=%s account=%s",
        verify_auth_token.id,
        account.id,
    )
    return login_result


async def login_with_password(
    db: AsyncSession,
    *,
    email: str,
    password: str,
    request_ip: str | None,
    user_agent: str | None,
) -> BrowserLoginResult | None:
    normalized = normalize_email(email)
    result = await db.execute(
        select(Account, User, Tenant)
        .join(User, User.account_id == Account.id)
        .join(Tenant, Tenant.id == User.tenant_id)
        .where(
            Account.email_normalized == normalized,
            Account.status == "active",
            User.removed_at.is_(None),
        )
        .order_by(User.created_at.asc())
    )
    rows = result.all()
    if not rows:
        return None
    if len(rows) > 1 and not settings.allow_multi_membership_accounts:
        return None
    account, user, tenant = rows[0]
    if not account.password_hash:
        return None
    valid = await asyncio.to_thread(verify_password, password, account.password_hash)
    if not valid:
        return None
    session = await create_user_session(
        db,
        account=account,
        user=user,
        tenant=tenant,
        request_ip=request_ip,
        user_agent=user_agent,
    )
    account.last_login_at = datetime.now(UTC)
    login_result = _browser_login_result(
        account=account,
        user=user,
        tenant=tenant,
        session=session,
    )
    await db.commit()
    return login_result


async def create_user_session(
    db: AsyncSession,
    *,
    account: Account,
    user: User,
    tenant: Tenant,
    request_ip: str | None,
    user_agent: str | None,
) -> UserSession:
    session = UserSession(
        account_id=account.id,
        tenant_id=tenant.id,
        user_id=user.id,
        session_nonce=secrets.token_hex(16),
        expires_at=datetime.now(UTC) + timedelta(hours=settings.jwt_token_expire_hours),
        ip_address=request_ip,
        user_agent=user_agent,
        last_reauthenticated_at=datetime.now(UTC),
    )
    db.add(session)
    await db.flush()
    return session


async def request_password_reset(db: AsyncSession, *, email: str) -> None:
    normalized = normalize_email(email)
    result = await db.execute(
        select(Account).where(Account.email_normalized == normalized)
    )
    account = result.scalar_one_or_none()
    if account is None or account.status == "disabled":
        await _lock_auth_token_replacement(
            db,
            account=None,
            email=email,
            purpose="password_reset",
        )
        await db.commit()
        return
    # Stamp ``is_passwordless`` so the email subject + landing page can
    # adapt copy from "Reset" to "Set" for accounts that have never set a
    # password (cloud-magic-link spec §13a "Forgot-password copy adapts").
    is_passwordless = not account.password_hash
    token_row, _token = await create_auth_token_record(
        db,
        account=account,
        email=account.email_display,
        purpose="password_reset",
        expires_in=timedelta(hours=1),
        metadata={"is_passwordless": is_passwordless},
    )
    await db.commit()
    logger.info(
        "Queued password reset email: token_id=%s account=%s is_passwordless=%s",
        token_row.id,
        account.id,
        is_passwordless,
    )


async def reset_password(db: AsyncSession, *, raw_token: str, password: str) -> bool:
    if len(password) < 10:
        raise BrowserAuthError("Password must be at least 10 characters.")
    token = await consume_auth_token(db, raw_token=raw_token, purpose="password_reset")
    if token is None or token.account_id is None:
        if token is not None:
            return await _commit_consumed_token_failure(db)
        return False
    result = await db.execute(select(Account).where(Account.id == token.account_id))
    account = result.scalar_one_or_none()
    if account is None:
        return await _commit_consumed_token_failure(db)
    if getattr(account, "status", "active") == "disabled":
        return await _commit_consumed_token_failure(db)

    now = datetime.now(UTC)
    account.password_hash = await asyncio.to_thread(hash_password, password)
    if getattr(account, "status", "active") == "password_unset":
        account.status = "active"
    if getattr(account, "email_verified_at", None) is None:
        account.email_verified_at = now
    account.session_version += 1
    await db.execute(
        update(UserSession)
        .where(UserSession.account_id == account.id, UserSession.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    # Kill any sibling reset link and any in-flight email-change link so a
    # second reset attempt or a stale change-of-email cannot ride this reset.
    await _revoke_account_tokens(
        db,
        account_id=account.id,
        purposes=("password_reset", "email_change"),
    )
    await db.commit()
    return True


async def verify_email_token(db: AsyncSession, *, raw_token: str) -> bool:
    token = await consume_auth_token(db, raw_token=raw_token, purpose="email_verify")
    if token is None or token.account_id is None:
        if token is not None:
            return await _commit_consumed_token_failure(db)
        return False
    result = await db.execute(select(Account).where(Account.id == token.account_id))
    account = result.scalar_one_or_none()
    if account is None:
        return await _commit_consumed_token_failure(db)
    if account.status == "disabled":
        return await _commit_consumed_token_failure(db)
    account.email_verified_at = datetime.now(UTC)
    await db.commit()
    return True


async def resend_verification(db: AsyncSession, *, account_id: uuid.UUID) -> bool:
    result = await db.execute(select(Account).where(Account.id == account_id))
    account = result.scalar_one_or_none()
    if account is None or account.email_verified_at is not None:
        return False
    cooldown_cutoff = datetime.now(UTC) - timedelta(
        seconds=settings.auth_email_resend_cooldown_seconds
    )
    recent = await db.execute(
        select(AuthToken).where(
            AuthToken.account_id == account.id,
            AuthToken.purpose == "email_verify",
            AuthToken.created_at > cooldown_cutoff,
            AuthToken.delivery_status.in_(("pending", "sent")),
        ).limit(1)
    )
    if recent.scalar_one_or_none() is not None:
        raise BrowserAuthError("Please wait before requesting another verification email.")
    token_row, _token = await create_auth_token_record(
        db,
        account=account,
        email=account.email_display,
        purpose="email_verify",
        expires_in=timedelta(hours=24),
    )
    await db.commit()
    logger.info(
        "Queued verification email: token_id=%s account=%s",
        token_row.id,
        account.id,
    )
    return True


async def get_account_for_auth(
    db: AsyncSession,
    *,
    auth_account_id: uuid.UUID | None,
) -> Account | None:
    if auth_account_id is None:
        return None
    result = await db.execute(select(Account).where(Account.id == auth_account_id))
    return result.scalar_one_or_none()


async def require_verified_account(db: AsyncSession, *, account_id: uuid.UUID | None) -> Account:
    account = await get_account_for_auth(db, auth_account_id=account_id)
    if account is None or account.status == "disabled":
        raise BrowserAuthError("Account access is unavailable.")
    if account.email_verified_at is None:
        raise BrowserAuthError("Verify your email before continuing.")
    return account


async def require_recent_reauth(
    db: AsyncSession,
    *,
    session_id: uuid.UUID | None,
) -> UserSession:
    if session_id is None:
        raise BrowserAuthError("Sign in again before continuing.")
    cutoff = datetime.now(UTC) - timedelta(minutes=settings.reauth_window_minutes)
    result = await db.execute(
        select(UserSession).where(
            UserSession.id == session_id,
            UserSession.revoked_at.is_(None),
            UserSession.expires_at > datetime.now(UTC),
        )
    )
    session = result.scalar_one_or_none()
    if session is None or not session.last_reauthenticated_at:
        raise BrowserAuthError("Sign in again before continuing.")
    if session.last_reauthenticated_at < cutoff:
        raise BrowserAuthError("Sign in again before continuing.")
    return session


async def mark_reauthenticated(
    db: AsyncSession,
    *,
    account_id: uuid.UUID | None,
    session_id: uuid.UUID | None,
    password: str,
) -> bool:
    if account_id is None or session_id is None:
        return False
    account = await get_account_for_auth(db, auth_account_id=account_id)
    if account is None or not account.password_hash:
        return False
    valid = await asyncio.to_thread(verify_password, password, account.password_hash)
    if not valid:
        return False
    await db.execute(
        update(UserSession)
        .where(UserSession.id == session_id, UserSession.account_id == account.id)
        .values(last_reauthenticated_at=datetime.now(UTC))
    )
    await db.commit()
    return True


async def change_password(
    db: AsyncSession,
    *,
    account_id: uuid.UUID | None,
    current_password: str,
    new_password: str,
    keep_session_id: uuid.UUID | None,
) -> None:
    if len(new_password) < 10:
        raise BrowserAuthError("Password must be at least 10 characters.")
    account = await get_account_for_auth(db, auth_account_id=account_id)
    if account is None or not account.password_hash:
        raise BrowserAuthError("Account access is unavailable.")
    valid = await asyncio.to_thread(verify_password, current_password, account.password_hash)
    if not valid:
        raise BrowserAuthError("Current password is incorrect.")
    account.password_hash = await asyncio.to_thread(hash_password, new_password)
    # session_version is intentionally not bumped here so the caller's
    # keep_session_id remains valid; sibling sessions are revoked below.
    query = update(UserSession).where(
        UserSession.account_id == account.id,
        UserSession.revoked_at.is_(None),
    )
    if keep_session_id is not None:
        query = query.where(UserSession.id != keep_session_id)
    await db.execute(query.values(revoked_at=datetime.now(UTC)))
    await _revoke_account_tokens(
        db,
        account_id=account.id,
        purposes=("password_reset", "email_change"),
    )
    await db.commit()


async def set_account_password(
    db: AsyncSession,
    *,
    account_id: uuid.UUID | None,
    new_password: str,
    current_password: str | None,
    keep_session_id: uuid.UUID | None,
) -> None:
    """Set or change ``account.password_hash`` per spec §13a.

    Branches on ``account.password_hash IS NULL`` to decide whether a
    ``current_password`` challenge is required:

    * Passwordless accounts: ``current_password`` is ignored; the
      recent-reauth check enforced by the calling endpoint is the security
      gate (see ``require_recent_reauth``).
    * Accounts with a password set: ``current_password`` is required and
      verified against the stored hash.

    On success: hashes via ``hash_password``, bumps ``session_version``
    (invalidates other open browser sessions per existing pattern in
    ``reset_password``), refreshes ``last_reauthenticated_at`` on the
    keep-session (the password set itself is a fresh reauth event), and
    implicitly dismisses the post-signup toast for the same transaction
    if it has not been dismissed already.
    """
    if len(new_password) < 10:
        raise BrowserAuthError("Password must be at least 10 characters.")
    account = await get_account_for_auth(db, auth_account_id=account_id)
    if account is None:
        raise BrowserAuthError("Account access is unavailable.")
    if getattr(account, "status", "active") == "disabled":
        raise BrowserAuthError("Account access is unavailable.")

    is_passwordless = not account.password_hash
    if not is_passwordless:
        if not current_password:
            raise BrowserAuthError("Enter your current password.")
        valid = await asyncio.to_thread(
            verify_password, current_password, account.password_hash or ""
        )
        if not valid:
            raise BrowserAuthError("Current password is incorrect.")

    now = datetime.now(UTC)
    account.password_hash = await asyncio.to_thread(hash_password, new_password)
    # Bump session_version so siblings holding the JWT for this account are
    # invalidated on next request (mirrors reset_password). The current
    # browser session keeps its claims because the JWT itself is opaque to
    # session_version when validated against the server-side row, but we
    # additionally revoke sibling UserSessions below.
    account.session_version += 1
    if getattr(account, "status", "active") == "password_unset":
        # Setting a password promotes the account to fully-active per the
        # device-flow self-heal pattern in `_finalize_device_token`.
        account.status = "active"
    if account.password_prompt_dismissed_at is None:
        # Implicit dismissal of the discoverability toast: completing the
        # action it was prompting for naturally hides it (§13a, item 27c).
        account.password_prompt_dismissed_at = now

    sibling_sessions = update(UserSession).where(
        UserSession.account_id == account.id,
        UserSession.revoked_at.is_(None),
    )
    if keep_session_id is not None:
        sibling_sessions = sibling_sessions.where(UserSession.id != keep_session_id)
    await db.execute(sibling_sessions.values(revoked_at=now))

    if keep_session_id is not None:
        # The password set itself is a fresh reauth event; refresh the
        # keep-session's ``last_reauthenticated_at`` so a subsequent
        # sensitive action does not immediately re-challenge the user.
        await db.execute(
            update(UserSession)
            .where(
                UserSession.id == keep_session_id,
                UserSession.account_id == account.id,
            )
            .values(last_reauthenticated_at=now)
        )

    # Kill any in-flight password-reset / email-change links that could be
    # replayed against the post-change account (mirrors reset_password).
    await _revoke_account_tokens(
        db,
        account_id=account.id,
        purposes=("password_reset", "email_change"),
    )
    await db.commit()
    logger.info(
        "event=account_password_set account_id_hash=%s was_passwordless=%s",
        hashlib.sha256(
            f"{settings.api_secret_key}:{account.id}".encode()
        ).hexdigest(),
        is_passwordless,
    )


async def dismiss_password_prompt(
    db: AsyncSession,
    *,
    account_id: uuid.UUID | None,
) -> bool:
    """Set ``accounts.password_prompt_dismissed_at`` for the toast (§13a).

    Idempotent: a repeat dismiss for an already-dismissed account commits
    cleanly without changing the timestamp. Returns True if a row was
    updated this call (i.e. the toast had not been previously dismissed).
    """
    if account_id is None:
        return False
    now = datetime.now(UTC)
    result = await db.execute(
        update(Account)
        .where(
            Account.id == account_id,
            Account.password_prompt_dismissed_at.is_(None),
        )
        .values(password_prompt_dismissed_at=now)
    )
    await db.commit()
    rowcount = getattr(result, "rowcount", 0) or 0
    return bool(rowcount)


async def request_email_change(
    db: AsyncSession,
    *,
    account_id: uuid.UUID | None,
    new_email: str,
) -> str:
    account = await require_verified_account(db, account_id=account_id)
    email_clean = new_email.strip()
    normalized = normalize_email(email_clean)
    if not normalized or "@" not in normalized:
        raise BrowserAuthError("Enter a valid email address.")
    existing = await db.execute(select(Account).where(Account.email_normalized == normalized))
    if existing.scalar_one_or_none() is not None:
        raise BrowserAuthError("That email address is already in use.")
    token_row, _token = await create_auth_token_record(
        db,
        account=account,
        email=email_clean,
        purpose="email_change",
        expires_in=timedelta(hours=24),
        metadata={"target_email": email_clean},
    )
    await db.commit()
    logger.info(
        "Queued email change confirmation: token_id=%s account=%s",
        token_row.id,
        account.id,
    )
    return email_clean


async def confirm_email_change(db: AsyncSession, *, raw_token: str) -> bool:
    token = await consume_auth_token(db, raw_token=raw_token, purpose="email_change")
    if token is None or token.account_id is None:
        if token is not None:
            return await _commit_consumed_token_failure(db)
        return False
    target = (token.metadata_json or {}).get("target_email")
    if not isinstance(target, str) or not target:
        return await _commit_consumed_token_failure(db)
    normalized = normalize_email(target)
    existing = await db.execute(
        select(Account).where(
            Account.email_normalized == normalized,
            Account.id != token.account_id,
        )
    )
    if existing.scalar_one_or_none() is not None:
        return await _commit_consumed_token_failure(db)
    result = await db.execute(select(Account).where(Account.id == token.account_id))
    account = result.scalar_one_or_none()
    if account is None:
        return await _commit_consumed_token_failure(db)
    if getattr(account, "status", "active") == "disabled":
        return await _commit_consumed_token_failure(db)
    account.email_normalized = normalized
    account.email_display = target.strip()
    account.email_verified_at = datetime.now(UTC)
    account.session_version += 1
    await db.execute(
        update(User)
        .where(User.account_id == account.id)
        .values(email=account.email_display)
    )
    # After identity change, revoke every outstanding account-scoped token so
    # links sent to the old address (reset, verify, change) cannot mutate the
    # account afterwards.
    await _revoke_account_tokens(
        db,
        account_id=account.id,
        purposes=("password_reset", "email_verify", "email_change"),
    )
    await db.commit()
    return True


# --- Magic-link finalize helpers (ct-1561) ----------------------------------
#
# These helpers consume an already-verified AuthToken and produce a session
# (and, for the device flow, an authorized device_authorization row). They
# are the "heart" of the magic-link / OTP flows defined in spec §5.4 and
# §13b. Routing/HTTP concerns live in the route handlers (impls 4 and 5);
# the helpers expose a clean async Python API the routes can call.
#
# Coordination with ct-1515: the existing `_finalize_device_authorization`
# helper in `routers/dashboard.py` handles the State-C path where the
# upstream auth proof is an already-valid recent-reauth session. The new
# `_authorize_device_for_session` helper below performs just the lock-and-
# update on the device_authorization row, so both code paths share a single
# definition of what "authorize this device" means. ct-1515's wrapper is
# expected to migrate over to call this helper in a follow-up; this subtask
# does NOT modify the dashboard wrapper to keep the diff scoped.


_DEVICE_FINALIZE_PURPOSES: tuple[str, ...] = (
    "device_login_existing_user",
    "device_signup_new_user",
)


# ── Structured logging (cross-shard contract: ct-1512 finding B7) ────────
#
# The four ``device_flow_*`` events live in this module so funnel queries
# can rely on a single source-of-truth emission point per stage. Routes
# (Shard C scope) MUST NOT re-emit these events. Routes are still
# responsible for route-specific rejections (CSRF invalid, malformed
# request body, etc.) which are NOT part of the ``device_flow_*`` family.
#
# Field schema (per spec §9):
#   email_hash                     hash_email_for_logs(normalized_email)
#   account_status                 "existing"|"unknown"|"disabled"|"new"
#   client_ip_hash                 hash_ip_for_logs(client_ip)
#   account_id_hash                hash_email_for_logs(account.email_normalized)
#   purpose                        AuthToken.purpose
#   method                         "link" | "otp"
#   device_authorization_id        str(uuid) | None
#   time_to_completion_seconds     float | None
#   error_code                     stable string per spec §6 State E
#   token_id                       str(uuid)
#   endpoint                       e.g. "email-init", "verify-otp"


def _time_to_completion_seconds(token: AuthToken) -> float | None:
    """Return seconds between token issuance and finalize, or None."""
    issued_at = getattr(token, "created_at", None)
    if issued_at is None:
        return None
    delta = datetime.now(UTC) - issued_at
    return float(round(delta.total_seconds(), 3))


def _emit_device_flow_email_init(
    *,
    purpose: str,
    account_status: str,
    device_authorization_id: uuid.UUID | None,
    email_normalized: str,
    client_ip: str | None,
    token_id: uuid.UUID | None,
    endpoint: str,
) -> None:
    """Emit ``device_flow_email_init`` (start of token issuance)."""
    logger.info(
        "event=device_flow_email_init purpose=%s account_status=%s "
        "device_authorization_id=%s email_hash=%s client_ip_hash=%s "
        "token_id=%s endpoint=%s",
        purpose,
        account_status,
        device_authorization_id,
        hash_email_for_logs(email_normalized),
        hash_ip_for_logs(client_ip),
        token_id,
        endpoint,
    )


def _emit_device_flow_email_sent(
    *,
    purpose: str,
    token_id: uuid.UUID,
    email_normalized: str,
    device_authorization_id: uuid.UUID | None,
    endpoint: str,
) -> None:
    """Emit ``device_flow_email_sent`` (after successful sender return)."""
    logger.info(
        "event=device_flow_email_sent purpose=%s token_id=%s email_hash=%s "
        "device_authorization_id=%s endpoint=%s",
        purpose,
        token_id,
        hash_email_for_logs(email_normalized),
        device_authorization_id,
        endpoint,
    )


def _emit_device_flow_finalized(
    *,
    method: str,
    account: Account,
    device_authorization_id: uuid.UUID | None,
    was_new_signup: bool,
    time_to_completion_seconds: float | None,
    token_id: uuid.UUID,
    purpose: str,
) -> None:
    """Emit ``device_flow_finalized`` (success path of finalize)."""
    logger.info(
        "event=device_flow_finalized method=%s purpose=%s account_id_hash=%s "
        "device_authorization_id=%s was_new_signup=%s "
        "time_to_completion_seconds=%s token_id=%s",
        method,
        purpose,
        hash_email_for_logs(account.email_normalized),
        device_authorization_id,
        was_new_signup,
        time_to_completion_seconds,
        token_id,
    )


def _emit_device_flow_error(
    *,
    error_code: str,
    purpose: str | None = None,
    endpoint: str | None = None,
    method: str | None = None,
    email_normalized: str | None = None,
    account_id_hash: str | None = None,
    device_authorization_id: uuid.UUID | None = None,
    token_id: uuid.UUID | None = None,
    client_ip: str | None = None,
) -> None:
    """Emit ``device_flow_error`` (any non-success path).

    All fields except ``error_code`` are optional; absent fields are
    omitted from the log line so funnel queries match the spec §9 field
    schema without forcing every call site to populate every column.
    """
    parts = [f"event=device_flow_error error_code={error_code}"]
    if purpose is not None:
        parts.append(f"purpose={purpose}")
    if endpoint is not None:
        parts.append(f"endpoint={endpoint}")
    if method is not None:
        parts.append(f"method={method}")
    if email_normalized is not None:
        parts.append(f"email_hash={hash_email_for_logs(email_normalized)}")
    if account_id_hash is not None:
        parts.append(f"account_id_hash={account_id_hash}")
    if device_authorization_id is not None:
        parts.append(f"device_authorization_id={device_authorization_id}")
    if token_id is not None:
        parts.append(f"token_id={token_id}")
    if client_ip is not None:
        parts.append(f"client_ip_hash={hash_ip_for_logs(client_ip)}")
    logger.warning(" ".join(parts))


@dataclass(frozen=True)
class FinalizeResult:
    """Outcome of consuming a magic-link / OTP AuthToken.

    Mirrors the shape spec §5.4 calls out (account, session, device
    authorization) plus the ``was_new_signup`` breadcrumb that route
    handlers need to emit the ``method=link|otp`` log line in §10.

    ``session`` is None when the caller already had a matching session
    (the route handler reuses the existing ``ctx_session`` cookie). When
    not None, the caller is responsible for setting the session cookie.

    ``session_token`` is the raw signed JWT string the route MUST set as
    the ``ctx_session`` cookie value when it is non-None. It is populated
    in lockstep with ``session`` (i.e. when a new ``UserSession`` row was
    created by the finalize). When ``session`` is None (existing-session
    reuse path) ``session_token`` is also None — the route leaves the
    existing cookie alone.

    Cross-shard contract (ct-1512 Shard B → Shard C, finding B3): routes
    consuming this dataclass should prefer ``session_token`` for cookie
    minting over re-running ``create_browser_session_token`` on the
    individual fields, because session_version may have shifted between
    the helper's commit and the cookie-setting moment in the route.

    ``device_authorization_id`` is None for the no-device login flow.
    """

    account: Account
    user: User
    tenant: Tenant
    session: UserSession | None
    session_token: str | None
    device_authorization_id: uuid.UUID | None
    was_new_signup: bool


async def _self_heal_account(account: Account) -> None:
    """Normalize self-healing transitions on a successful magic-link finalize.

    Per spec §5.4: clicking a magic link / entering an OTP proves the user
    controls the inbox, so any account whose ``email_verified_at IS NULL``
    gets it set, and any legacy ``status='password_unset'`` row is promoted
    to ``'active'``. These are safe one-line fix-ups, not flow branches.
    Disabled accounts are NEVER promoted; the caller must reject those
    before invoking this helper.
    """
    now = datetime.now(UTC)
    if getattr(account, "status", "active") == "password_unset":
        account.status = "active"
    if getattr(account, "email_verified_at", None) is None:
        account.email_verified_at = now


async def _resolve_owner_user_for_account(
    db: AsyncSession,
    *,
    account: Account,
) -> tuple[User, Tenant]:
    """Return the (user, tenant) tuple a magic-link finalize should attach to.

    Mirrors the join logic in ``login_with_password``: the earliest non-
    removed ``User`` row for the account, plus its ``Tenant``. Raises
    ``BrowserAuthError`` when no membership exists (this should not
    happen for accounts created by this codebase, but defends against
    orphaned rows produced by manual data fixes).
    """
    result = await db.execute(
        select(User, Tenant)
        .join(Tenant, Tenant.id == User.tenant_id)
        .where(
            User.account_id == account.id,
            User.removed_at.is_(None),
        )
        .order_by(User.created_at.asc())
        .limit(1)
    )
    row = result.first()
    if row is None:
        raise BrowserAuthError("Account is not associated with any team.")
    user, tenant = row
    return user, tenant


async def _authorize_device_for_session(
    db: AsyncSession,
    *,
    device_authorization_id: uuid.UUID,
    user: User,
    tenant: Tenant,
) -> DeviceAuthorization:
    """Atomically transition a pending device_authorization to authorized.

    Locks the row with SELECT ... FOR UPDATE, re-checks
    ``status='pending'`` and not-expired (the row could have moved to
    ``authorized``/``denied``/``expired`` between the outer lookup and
    here), then sets ``status='authorized'`` along with the (user,
    tenant) link.

    Shared between ``_finalize_device_token`` (magic-link / OTP path) and
    the future migration of the ct-1515 ``_finalize_device_authorization``
    wrapper. Caller is responsible for the surrounding transaction (this
    helper does NOT commit).

    Raises ``BrowserAuthError`` when the row is no longer pending.
    """
    now = datetime.now(UTC)
    locked = await db.execute(
        select(DeviceAuthorization)
        .where(
            DeviceAuthorization.id == device_authorization_id,
            DeviceAuthorization.status == "pending",
            DeviceAuthorization.expires_at > now,
        )
        .with_for_update()
    )
    device_auth = locked.scalar_one_or_none()
    if device_auth is None:
        raise BrowserAuthError(
            "This setup code is no longer active. "
            "Return to Contextify and start sign-in again."
        )
    await db.execute(
        update(DeviceAuthorization)
        .where(DeviceAuthorization.id == device_auth.id)
        .values(
            status="authorized",
            user_id=user.id,
            tenant_id=tenant.id,
        )
    )
    return device_auth


async def _create_passwordless_account_with_tenant(
    db: AsyncSession,
    *,
    email_normalized: str,
    email_display: str,
    request_ip: str | None,
    user_agent: str | None,
) -> tuple[Account, User, Tenant]:
    """Verify-then-create the (Account, Tenant, User) trio for a new signup.

    Mirrors the relevant parts of ``register_with_password`` minus the
    password-hashing path: the magic-link signup flow is passwordless, so
    the account row is committed with ``password_hash=NULL`` and
    ``status='active'``. Email is treated as verified immediately: the
    user demonstrated inbox control by clicking the link / entering the
    OTP, which is the verify-then-create rationale from spec §4.

    Caller wraps this in a transaction; on partial-unique-index race the
    ``IntegrityError`` is caught one level up (in
    ``_finalize_device_token``) and the existing-account branch runs
    instead.
    """
    now = datetime.now(UTC)
    local_part = email_normalized.split("@", 1)[0] or "team"
    slug_seed = f"{local_part}-{secrets.token_hex(3)}"
    account = Account(
        email_normalized=email_normalized,
        email_display=email_display,
        password_hash=None,
        status="active",
        email_verified_at=now,
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
        name=local_part,
        slug=slug_seed,
        email=email_display,
        user_name=local_part,
        create_default_api_key=False,
    )
    user.account_id = account.id
    await db.flush()
    return account, user, tenant


async def _finalize_device_token(
    db: AsyncSession,
    *,
    raw_token: str,
    db_session_user: User | None = None,
    request_ip: str | None = None,
    user_agent: str | None = None,
    method: str = "link",
) -> FinalizeResult:
    """Consume a verified device-flow magic-link / OTP token.

    Implements spec §5.4. The function is the single place where the
    cloud server accepts a one-time AuthToken (purpose
    ``device_login_existing_user`` or ``device_signup_new_user``),
    materializes (or reuses) an Account+Tenant+User, atomically
    transitions the matching device_authorization row to ``authorized``,
    and issues a browser session.

    The caller (impls 4/5) is responsible for setting the ``ctx_session``
    cookie. Prefer ``FinalizeResult.session_token`` (the raw signed JWT
    string) over re-running ``create_browser_session_token``: the helper
    minted the token in the same DB snapshot it just committed, so the
    embedded ``session_version`` cannot drift between commit and the
    cookie-setting moment in the route.

    The structured ``device_flow_finalized`` event is emitted by the
    helper itself (cross-shard contract from ct-1512 finding B7); routes
    MUST NOT re-emit the same event. ``method`` MUST be ``"link"`` (magic
    link) or ``"otp"`` so the funnel funnel-stage logs distinguish the
    two completion paths.

    Atomicity: all mutations either commit together (final ``await
    db.commit()``) or roll back together. If the helper raises, the
    caller must roll back.

    Race-safe re-check: for ``device_signup_new_user``, the helper
    re-normalizes the signup email pulled from ``metadata_json`` and
    looks up the accounts table BEFORE attempting INSERT. If a concurrent
    transaction wins the partial unique index race
    (``uq_auth_tokens_active_signup_email``) or the
    ``accounts.email_normalized`` UNIQUE, the per-row INSERT is rolled
    back to a SAVEPOINT — the consumed-token UPDATE survives, so the
    outer commit cannot leave the token re-usable (ct-1512 finding B1).
    """
    token = await consume_auth_token(
        db,
        raw_token=raw_token,
        purpose="device_login_existing_user",
    )
    if token is None:
        token = await consume_auth_token(
            db,
            raw_token=raw_token,
            purpose="device_signup_new_user",
        )
    if token is None:
        _emit_device_flow_error(
            error_code="token_unknown",
            endpoint="finalize_device_token",
            method=method,
        )
        raise BrowserAuthError(
            "This sign-in link has expired or already been used. "
            "Return to Contextify and request a new one."
        )
    if token.purpose not in _DEVICE_FINALIZE_PURPOSES:
        # consume_auth_token gates on purpose, so this path is defensive.
        await _commit_consumed_token_failure(db)
        _emit_device_flow_error(
            error_code="purpose_invalid",
            purpose=token.purpose,
            token_id=token.id,
            endpoint="finalize_device_token",
            method=method,
        )
        raise BrowserAuthError("This sign-in link is not valid.")

    # ct-1512 Shard C-fix2 C-1: refuse to finalize sentinel tokens issued
    # by silent-skip branches even on the vanishingly improbable event of
    # an OTP collision against the random hash. The sentinel was never
    # emailed, so a "successful" finalize against it would be a bypass of
    # the disabled-account / unknown-email enumeration defense. The token
    # is now consumed (consume_auth_token committed the consume_at stamp)
    # and the route returns the same generic "link invalid" copy as any
    # other rejected token.
    metadata = token.metadata_json or {}
    if metadata.get("is_sentinel") is True:
        await _commit_consumed_token_failure(db)
        _emit_device_flow_error(
            error_code="token_unknown",
            purpose=token.purpose,
            token_id=token.id,
            endpoint="finalize_device_token",
            method=method,
        )
        raise BrowserAuthError(
            "This sign-in link has expired or already been used. "
            "Return to Contextify and request a new one."
        )

    raw_device_auth_id = metadata.get("device_authorization_id")
    if not isinstance(raw_device_auth_id, str):
        await _commit_consumed_token_failure(db)
        _emit_device_flow_error(
            error_code="device_authorization_missing",
            purpose=token.purpose,
            token_id=token.id,
            endpoint="finalize_device_token",
            method=method,
        )
        raise BrowserAuthError("This sign-in link is not valid.")
    try:
        device_authorization_id = uuid.UUID(raw_device_auth_id)
    except ValueError:
        await _commit_consumed_token_failure(db)
        _emit_device_flow_error(
            error_code="device_authorization_invalid",
            purpose=token.purpose,
            token_id=token.id,
            endpoint="finalize_device_token",
            method=method,
        )
        raise BrowserAuthError("This sign-in link is not valid.") from None

    # Snapshot identity fields before any potential rollback inside
    # _resolve_login_account / _resolve_signup_account expires the
    # token row's attributes (ct-1512 finding B2 rolls back on the
    # different-account guard).
    token_purpose_snapshot = token.purpose
    token_id_snapshot = token.id
    try:
        if token.purpose == "device_signup_new_user":
            account, user_obj, tenant, was_new_signup = await _resolve_signup_account(
                db,
                token=token,
                metadata=metadata,
                request_ip=request_ip,
                user_agent=user_agent,
            )
        else:
            account, user_obj, tenant = await _resolve_login_account(
                db,
                token=token,
                db_session_user=db_session_user,
            )
            was_new_signup = False
    except BrowserAuthError as exc:
        _emit_device_flow_error(
            error_code="account_resolve_rejected",
            purpose=token_purpose_snapshot,
            token_id=token_id_snapshot,
            endpoint="finalize_device_token",
            method=method,
        )
        raise exc

    await _self_heal_account(account)
    device_auth = await _authorize_device_for_session(
        db,
        device_authorization_id=device_authorization_id,
        user=user_obj,
        tenant=tenant,
    )

    session, session_token = await _resolve_or_reuse_session(
        db,
        account=account,
        user=user_obj,
        tenant=tenant,
        db_session_user=db_session_user,
        request_ip=request_ip,
        user_agent=user_agent,
    )
    # ct-1278: snapshot welcome-email arguments BEFORE commit so the post-
    # commit send is independent of any ORM-attribute expiration on the
    # committed Account/User rows. Gated on was_new_signup; existing-account
    # login (and the race-loser branch in _resolve_signup_account) leave
    # these as None.
    welcome_email_to = account.email_display if was_new_signup else None
    welcome_name = user_obj.name if was_new_signup else None
    welcome_email_norm = account.email_normalized if was_new_signup else None
    welcome_user_agent = user_agent if was_new_signup else None

    account.last_login_at = datetime.now(UTC)
    await db.commit()

    _emit_device_flow_finalized(
        method=method,
        account=account,
        device_authorization_id=device_auth.id,
        was_new_signup=was_new_signup,
        time_to_completion_seconds=_time_to_completion_seconds(token),
        token_id=token.id,
        purpose=token.purpose,
    )

    # ct-1278: send the standard welcome email on the magic-link / OTP /
    # device-flow signup path. Post-commit, post-funnel-emit, and
    # fire-and-forget: an email-provider/template failure must not turn an
    # already-finalized signup/device authorization into a route-level auth
    # failure, the funnel event must always fire, AND the user must not wait
    # on a Resend HTTP call before their auth-finalize response returns. The
    # signup and login branches above are mutually exclusive with
    # register_with_password, so there is no risk of double-sending.
    if welcome_email_to is not None:
        await spawn_welcome_email_after_device_signup(
            to_email=welcome_email_to,
            name=welcome_name,
            email_normalized=welcome_email_norm or "",
            user_agent=welcome_user_agent,
        )

    return FinalizeResult(
        account=account,
        user=user_obj,
        tenant=tenant,
        session=session,
        session_token=session_token,
        device_authorization_id=device_auth.id,
        was_new_signup=was_new_signup,
    )


async def _resolve_signup_account(
    db: AsyncSession,
    *,
    token: AuthToken,
    metadata: dict[str, object],
    request_ip: str | None,
    user_agent: str | None,
) -> tuple[Account, User, Tenant, bool]:
    """Materialize (or recover) the account for a signup magic-link finalize.

    Returns ``(account, user, tenant, was_new_signup)``. If a concurrent
    transaction already created the account for this normalized email
    (race-loser path), this helper rolls back the failed INSERT to a
    SAVEPOINT, re-fetches the existing account, and continues
    idempotently with ``was_new_signup=False``.

    SAVEPOINT semantics (ct-1512 finding B1): the outer
    ``_finalize_device_token`` already consumed the AuthToken row by the
    time this helper runs. If the race-loser INSERT failed and we
    ``await db.rollback()`` the WHOLE transaction, the consumed_at UPDATE
    on the token would also be unwound — but the outer caller would
    proceed to authorize the device + commit the session, leaving the
    token re-usable. Wrapping just the create-account step in
    ``async with db.begin_nested():`` (Postgres SAVEPOINT) means the
    failed INSERT can roll back without touching the token consume.
    """
    raw_signup_email = metadata.get("signup_email")
    if not isinstance(raw_signup_email, str) or not raw_signup_email:
        await _commit_consumed_token_failure(db)
        raise BrowserAuthError("This sign-in link is not valid.")
    normalized = normalize_email(raw_signup_email)
    if not normalized or "@" not in normalized:
        await _commit_consumed_token_failure(db)
        raise BrowserAuthError("This sign-in link is not valid.")

    existing = await db.execute(
        select(Account).where(Account.email_normalized == normalized)
    )
    account = existing.scalar_one_or_none()
    if account is not None:
        if getattr(account, "status", "active") == "disabled":
            await _commit_consumed_token_failure(db)
            raise BrowserAuthError(
                "Account access is unavailable. Contact support."
            )
        user, tenant = await _resolve_owner_user_for_account(db, account=account)
        return account, user, tenant, False

    try:
        async with db.begin_nested():
            account, user, tenant = await _create_passwordless_account_with_tenant(
                db,
                email_normalized=normalized,
                email_display=token.sent_to or raw_signup_email,
                request_ip=request_ip,
                user_agent=user_agent,
            )
        return account, user, tenant, True
    except IntegrityError:
        # Concurrent winner created the account between our SELECT and
        # INSERT (or won the partial unique index race on signup_email).
        # The SAVEPOINT above has already been rolled back by the
        # ``async with`` exit handler — the token consume from
        # ``_finalize_device_token`` survives, so the outer commit will
        # leave the token correctly consumed. Re-fetch the winning
        # account row and continue as the login branch.
        existing_after = await db.execute(
            select(Account).where(Account.email_normalized == normalized)
        )
        account = existing_after.scalar_one_or_none()
        if account is None:
            await _commit_consumed_token_failure(db)
            raise BrowserAuthError(
                "Sign-in could not be completed. Try again."
            ) from None
        if getattr(account, "status", "active") == "disabled":
            await _commit_consumed_token_failure(db)
            raise BrowserAuthError(
                "Account access is unavailable. Contact support."
            ) from None
        user, tenant = await _resolve_owner_user_for_account(db, account=account)
        return account, user, tenant, False


async def _resolve_login_account(
    db: AsyncSession,
    *,
    token: AuthToken,
    db_session_user: User | None,
) -> tuple[Account, User, Tenant]:
    """Resolve the (account, user, tenant) for a login-magic-link finalize.

    Used by both ``_finalize_device_token`` (purpose
    ``device_login_existing_user``) and ``_finalize_login_token`` (purpose
    ``login_magic_link``). Rejects when:
      - the linked account does not exist (orphaned token)
      - the account is disabled
      - the caller already has a session for a DIFFERENT account
        (per spec §4 different-account guard)
    """
    if token.account_id is None:
        await _commit_consumed_token_failure(db)
        raise BrowserAuthError("This sign-in link is not valid.")
    result = await db.execute(select(Account).where(Account.id == token.account_id))
    account = result.scalar_one_or_none()
    if account is None:
        await _commit_consumed_token_failure(db)
        raise BrowserAuthError("This sign-in link is not valid.")
    if getattr(account, "status", "active") == "disabled":
        await _commit_consumed_token_failure(db)
        raise BrowserAuthError("Account access is unavailable. Contact support.")

    if db_session_user is not None and db_session_user.account_id != account.id:
        # Different-device-different-account: the token resolves to A,
        # but the caller's existing session belongs to B. Reject rather
        # than silently swap accounts (spec §4).
        #
        # Recoverable rollback (ct-1512 finding B2): signing out and
        # retrying is the documented next step for this guard, so we
        # must NOT burn the link. Rolling back the consumed_at UPDATE
        # leaves the token in pending state so the user can retry the
        # same link after sign-out without seeing "already used".
        await db.rollback()
        raise BrowserAuthError(
            "You're signed in to a different account in this browser. "
            "Sign out and try again."
        )

    user, tenant = await _resolve_owner_user_for_account(db, account=account)
    return account, user, tenant


async def _resolve_or_reuse_session(
    db: AsyncSession,
    *,
    account: Account,
    user: User,
    tenant: Tenant,
    db_session_user: User | None,
    request_ip: str | None,
    user_agent: str | None,
) -> tuple[UserSession | None, str | None]:
    """Either create a fresh UserSession, or signal session reuse.

    Returns ``(None, None)`` when ``db_session_user`` already references
    the resolved account — the route handler keeps the existing
    ``ctx_session`` cookie. Returns ``(session, session_token)``
    otherwise: the freshly inserted ``UserSession`` plus the signed JWT
    cookie value the route should set into ``ctx_session``.

    Minting the JWT inside the helper (instead of re-running
    ``create_browser_session_token`` in the route) keeps cookie issuance
    aligned with the same ``session_version`` snapshot the helper just
    committed (ct-1512 finding B3).
    """
    if db_session_user is not None and db_session_user.account_id == account.id:
        return None, None
    session = await create_user_session(
        db,
        account=account,
        user=user,
        tenant=tenant,
        request_ip=request_ip,
        user_agent=user_agent,
    )
    # Imported lazily to avoid a circular import at module load time.
    from contextify_cloud.middleware.jwt_auth import create_browser_session_token
    session_token = create_browser_session_token(
        account_id=account.id,
        session_id=session.id,
        user_id=user.id,
        tenant_id=tenant.id,
        role=user.role,
        nonce=session.session_nonce,
        session_version=account.session_version or 1,
    )
    return session, session_token


async def _finalize_login_token(
    db: AsyncSession,
    *,
    raw_token: str,
    db_session_user: User | None = None,
    request_ip: str | None = None,
    user_agent: str | None = None,
    method: str = "link",
) -> FinalizeResult:
    """Consume a verified login-magic-link token (no device flow).

    Sister of ``_finalize_device_token`` for the dashboard sign-in flow
    described in spec §13b. Same atomicity and self-healing semantics,
    but does NOT touch any device_authorization row. Returns
    ``device_authorization_id=None`` and ``was_new_signup=False``.

    Like the device variant, ``method`` is logged in the
    ``device_flow_finalized`` event so the funnel can split magic-link
    vs OTP completion. The helper owns the emission; routes MUST NOT
    re-emit (ct-1512 finding B7).
    """
    token = await consume_auth_token(
        db,
        raw_token=raw_token,
        purpose="login_magic_link",
    )
    if token is None:
        _emit_device_flow_error(
            error_code="token_unknown",
            purpose="login_magic_link",
            endpoint="finalize_login_token",
            method=method,
        )
        raise BrowserAuthError(
            "This sign-in link has expired or already been used. "
            "Request a new one from the sign-in page."
        )

    # ct-1512 Shard C-fix2 C-1: refuse to finalize sentinel tokens issued
    # by silent-skip (disabled / unknown) login branches even on the
    # vanishingly improbable event of an OTP collision against the random
    # hash. The sentinel was never emailed; a "successful" finalize would
    # bypass the email-enumeration defense for /cloud/login.
    metadata = token.metadata_json or {}
    if metadata.get("is_sentinel") is True:
        await _commit_consumed_token_failure(db)
        _emit_device_flow_error(
            error_code="token_unknown",
            purpose=token.purpose,
            token_id=token.id,
            endpoint="finalize_login_token",
            method=method,
        )
        raise BrowserAuthError(
            "This sign-in link has expired or already been used. "
            "Request a new one from the sign-in page."
        )

    # Snapshot identity fields before any potential rollback inside
    # _resolve_login_account expires the token row's attributes
    # (ct-1512 finding B2 rolls back on the different-account guard).
    token_purpose_snapshot = token.purpose
    token_id_snapshot = token.id
    try:
        account, user_obj, tenant = await _resolve_login_account(
            db,
            token=token,
            db_session_user=db_session_user,
        )
    except BrowserAuthError as exc:
        _emit_device_flow_error(
            error_code="account_resolve_rejected",
            purpose=token_purpose_snapshot,
            token_id=token_id_snapshot,
            endpoint="finalize_login_token",
            method=method,
        )
        raise exc

    await _self_heal_account(account)

    session, session_token = await _resolve_or_reuse_session(
        db,
        account=account,
        user=user_obj,
        tenant=tenant,
        db_session_user=db_session_user,
        request_ip=request_ip,
        user_agent=user_agent,
    )
    account.last_login_at = datetime.now(UTC)
    await db.commit()

    _emit_device_flow_finalized(
        method=method,
        account=account,
        device_authorization_id=None,
        was_new_signup=False,
        time_to_completion_seconds=_time_to_completion_seconds(token),
        token_id=token.id,
        purpose=token.purpose,
    )

    return FinalizeResult(
        account=account,
        user=user_obj,
        tenant=tenant,
        session=session,
        session_token=session_token,
        device_authorization_id=None,
        was_new_signup=False,
    )
