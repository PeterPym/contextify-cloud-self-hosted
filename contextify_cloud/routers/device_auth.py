"""Device flow authorization endpoints (RFC 8628 + magic-link / OTP).

Implements the OAuth 2.0 Device Authorization Grant for CLI authentication.
The CLI requests a device code, displays a user code to the user, and polls
for completion while the user authorizes in their browser.

ct-1562 added the magic-link / OTP "verify-then-create" flow for users with
no browser session, no password, or no account at all (cloud-magic-link
spec §5.3, §13 done-when 3-7, 15-18, 22-23):

Endpoints:
  POST /api/v1/auth/device/code            - Request device + user codes (no auth)
  POST /api/v1/auth/device/token           - Poll for authorization result (no auth)
  POST /api/v1/auth/device/email-init      - Issue magic-link / OTP email (no auth)
  POST /api/v1/auth/device/verify-otp      - Validate typed OTP (no auth)
  GET  /cloud/device/email-link            - Magic-link interstitial (no auth)
  POST /cloud/device/email-link/confirm    - Consume magic link via form POST (no auth)

Cross-cutting:
  * CSRF: public-CSRF cookie pattern via ``contextify_cloud.middleware.public_csrf``
    (header for JSON POSTs, form field for the email-link confirm POST).
  * Rate limits: per-IP via ``UnauthRateLimitMiddleware``; per-token OTP
    lockout via ``services.device_email_flow.verify_device_otp_attempt``;
    per-device-code send cap via ``device_email_send_cap_reached``.
  * Structured logging: four event types (``device_flow_email_init``,
    ``device_flow_email_sent``, ``device_flow_finalized``,
    ``device_flow_error``) per spec §9.
"""

import logging
import secrets
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path as _Path
from typing import Annotated, Any
from urllib.parse import quote

from fastapi import APIRouter, Body, Depends, Form, HTTPException, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from contextify_cloud.config import settings
from contextify_cloud.database import get_db
from contextify_cloud.http_security import is_secure_request
from contextify_cloud.middleware.auth import generate_api_key, hash_api_key
from contextify_cloud.middleware.jwt_auth import JWT_COOKIE_NAME
from contextify_cloud.middleware.public_csrf import (
    public_csrf_form_valid,
    public_csrf_json_valid,
    public_csrf_token,
    set_public_csrf_cookie,
)
from contextify_cloud.models import Account, ApiKey, AuthToken, DeviceAuthorization, Tenant, User
from contextify_cloud.schemas import (
    DeviceCodeRequest,
    DeviceCodeResponse,
    DeviceEmailInitRequest,
    DeviceTokenRequest,
    DeviceTokenResponse,
    DeviceVerifyOtpFailure,
    DeviceVerifyOtpRequest,
    DeviceVerifyOtpSuccess,
)
from contextify_cloud.services.attribution import (
    AcquisitionAttribution,
    attribution_from_request,
    attribution_to_metadata,
)
from contextify_cloud.services.audit import log_event
from contextify_cloud.services.browser_auth import (
    BrowserAuthError,
    FinalizeResult,
    _finalize_device_token,
    spawn_device_flow_email_send,
)
from contextify_cloud.services.device_auth_codes import hash_device_code, hash_user_code
from contextify_cloud.services.device_email_flow import (
    device_email_send_cap_reached,
    issue_device_email_token,
    issue_sentinel_email_token,
    lock_device_authorization_for_send,
    reconstruct_raw_token,
    resolve_device_authorization,
    verify_device_otp_attempt,
)
from contextify_cloud.services.email import (
    send_device_signin_existing_user,
    send_device_signup_new_user,
)
from contextify_cloud.services.tenant_guard import check_tenant_active
from contextify_cloud.utils.email import (
    display_device_name,
    hash_email_for_logs,
    hash_ip_for_logs,
    mask_email,
    normalize_email,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth/device", tags=["device-auth"])

# Separate router for the browser-side ``/cloud/device/email-link`` endpoints
# (different prefix from the JSON API). Registered alongside ``router`` in
# ``contextify_cloud.main``.
cloud_device_router = APIRouter(prefix="/cloud/device", tags=["device-auth"])

_TEMPLATE_DIR = _Path(__file__).resolve().parent.parent / "templates"
_templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))


def device_error(error: str, description: str, status_code: int = 400) -> JSONResponse:
    """Return a flat RFC 8628-compliant error response.

    FastAPI's HTTPException wraps detail in {"detail": ...}, but RFC 8628
    requires flat {"error": "...", "error_description": "..."} at the top level.
    """
    return JSONResponse(
        status_code=status_code,
        content={"error": error, "error_description": description},
        headers={"Cache-Control": "no-store"},
    )


# Alphabet for user codes: excludes confusable characters (0/O, 1/I/L)
_USER_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
_USER_CODE_LENGTH = 8  # 8 chars -> XXXX-XXXX format


def _generate_user_code() -> str:
    """Generate a human-readable user code in XXXX-XXXX format.

    Uses a 31-character alphabet that excludes confusable characters
    (0/O, 1/I/L). 8 characters from 31-char alphabet provides ~39.6 bits
    of entropy (31^8), sufficient for a 15-minute window.
    """
    chars = "".join(secrets.choice(_USER_CODE_ALPHABET) for _ in range(_USER_CODE_LENGTH))
    return f"{chars[:4]}-{chars[4:]}"


def _generate_device_code() -> str:
    """Generate a 64-character hex device code."""
    return secrets.token_hex(32)


def _redact_user_code(user_code: str) -> str:
    """Return a log-safe prefix for a device user code."""
    return f"{user_code[:4]}-..." if len(user_code) >= 4 else "..."


@router.post("/code", response_model=DeviceCodeResponse)
async def request_device_code(
    request: Request,
    body: DeviceCodeRequest,
    db: AsyncSession = Depends(get_db),
) -> DeviceCodeResponse:
    """Initiate device flow authorization.

    Creates a pending DeviceAuthorization with a device_code (for CLI polling)
    and a user_code (for user to enter in browser). No authentication required.
    """
    device_code = _generate_device_code()
    user_code = _generate_user_code()
    verification_uri = f"{settings.invitation_base_url.rstrip('/')}/cloud/device"
    # ct-1512 followup: RFC 8628 §3.2 — embed the user_code as a query
    # parameter so the macOS app's "Open in Browser" button can navigate
    # directly to a page that auto-fills the code (no copy-paste step).
    verification_uri_complete = (
        f"{verification_uri}?user_code={quote(user_code, safe='')}"
    )
    expires_at = datetime.now(UTC) + timedelta(seconds=settings.device_code_expiry_seconds)
    client_ip = request.client.host if request.client else None

    device_auth = DeviceAuthorization(
        device_code_hash=hash_device_code(device_code),
        user_code_hash=hash_user_code(user_code),
        verification_uri=verification_uri,
        status="pending",
        client_name=body.client_name,
        client_ip=client_ip,
        expires_at=expires_at,
        poll_interval=settings.device_poll_interval,
    )
    db.add(device_auth)
    await db.flush()

    logger.info(
        "Device code issued: user_code_prefix=%s client_name=%s client_ip=%s",
        _redact_user_code(user_code), body.client_name, client_ip,
    )

    return DeviceCodeResponse(
        device_code=device_code,
        user_code=user_code,
        verification_uri=verification_uri,
        verification_uri_complete=verification_uri_complete,
        expires_in=settings.device_code_expiry_seconds,
        interval=settings.device_poll_interval,
    )


@router.post("/token")
async def poll_device_token(
    request: Request,
    body: DeviceTokenRequest,
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """Poll for device authorization result.

    The CLI calls this endpoint repeatedly until the user authorizes (or denies)
    the request in the browser. Returns RFC 8628-compliant error responses
    for pending, slow_down, expired, and denied states.
    """
    # Validate grant_type
    if body.grant_type != "urn:ietf:params:oauth:grant-type:device_code":
        return device_error(
            "unsupported_grant_type",
            "grant_type must be 'urn:ietf:params:oauth:grant-type:device_code'.",
        )

    # Look up the device authorization (row lock prevents race conditions)
    result = await db.execute(
        select(DeviceAuthorization)
        .where(
            or_(
                DeviceAuthorization.device_code_hash == hash_device_code(body.device_code),
                DeviceAuthorization.device_code == body.device_code,
            )
        )
        .with_for_update()
    )
    device_auth = result.scalar_one_or_none()

    if not device_auth:
        return device_error("invalid_grant", "Unknown device code.")

    now = datetime.now(UTC)

    # Check expiry
    if now > device_auth.expires_at:
        if device_auth.status not in ("completed", "expired"):
            await db.execute(
                update(DeviceAuthorization)
                .where(DeviceAuthorization.id == device_auth.id)
                .values(status="expired")
            )
        return device_error("expired_token", "The device code has expired. Please restart setup.")

    # Rate limiting: check poll interval
    if device_auth.last_polled_at:
        elapsed = (now - device_auth.last_polled_at).total_seconds()
        if elapsed < device_auth.poll_interval:
            # Increase the interval by 5 seconds per RFC 8628
            new_interval = device_auth.poll_interval + 5
            await db.execute(
                update(DeviceAuthorization)
                .where(DeviceAuthorization.id == device_auth.id)
                .values(poll_interval=new_interval, last_polled_at=now)
            )
            return device_error(
                "slow_down",
                f"Polling too frequently. Wait {new_interval} seconds.",
            )

    # Update last_polled_at
    await db.execute(
        update(DeviceAuthorization)
        .where(DeviceAuthorization.id == device_auth.id)
        .values(last_polled_at=now)
    )

    # Handle status
    if device_auth.status == "pending":
        return device_error("authorization_pending", "The user has not yet authorized this device.")

    if device_auth.status == "denied":
        return device_error("access_denied", "The user denied the authorization request.")

    if device_auth.status == "completed":
        # The raw key cannot be re-delivered (only the hash is stored).
        # Returning a fake key would poison CLI config on retry.
        return device_error(
            "access_denied",
            "This device code has already been used. Please run setup again.",
        )

    if device_auth.status != "authorized":
        return device_error("authorization_pending", "The user has not yet authorized this device.")

    # Status is "authorized" - generate API key and complete the flow
    user_id = device_auth.user_id
    tenant_id = device_auth.tenant_id

    if not user_id or not tenant_id:
        logger.error(
            "Device authorization %s is authorized but missing user_id or tenant_id",
            device_auth.id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error: authorization data incomplete.",
        )

    # Block device authorization if tenant is scheduled for deletion
    await check_tenant_active(db, tenant_id)

    # Fetch user and tenant info
    user_result = await db.execute(
        select(User, Account)
        .join(Account, Account.id == User.account_id)
        .where(
            User.id == user_id,
            User.tenant_id == tenant_id,
            User.removed_at.is_(None),
            Account.status != "disabled",
            Account.email_verified_at.is_not(None),
        )
    )
    user_row = user_result.first()
    if user_row is not None:
        user, _account = user_row
    else:
        user = None

    if not user:
        logger.error(
            "Device auth %s: authorized user/tenant no longer valid "
            "(user_id=%s, tenant_id=%s)",
            device_auth.id, user_id, tenant_id,
        )
        await db.execute(
            update(DeviceAuthorization)
            .where(DeviceAuthorization.id == device_auth.id)
            .values(status="denied")
        )
        return device_error("access_denied", "Authorization is no longer valid.")

    tenant_result = await db.execute(
        select(Tenant).where(Tenant.id == tenant_id)
    )
    tenant = tenant_result.scalar_one_or_none()

    if not tenant:
        logger.error(
            "Device auth %s: authorized tenant no longer valid "
            "(user_id=%s, tenant_id=%s)",
            device_auth.id, user_id, tenant_id,
        )
        await db.execute(
            update(DeviceAuthorization)
            .where(DeviceAuthorization.id == device_auth.id)
            .values(status="denied")
        )
        return device_error("access_denied", "Authorization is no longer valid.")

    # Generate API key using existing mechanism
    raw_key, key_id, secret = generate_api_key()
    api_key = ApiKey(
        user_id=user_id,
        tenant_id=tenant_id,
        key_id=key_id,
        key_hash=hash_api_key(secret),
        key_prefix=f"ctx_{key_id}...",
        name="CLI (device flow)",
        scopes=["sync", "search"],
    )
    db.add(api_key)
    await db.flush()

    # Mark authorization as completed
    await db.execute(
        update(DeviceAuthorization)
        .where(DeviceAuthorization.id == device_auth.id)
        .values(
            status="completed",
            issued_api_key_id=api_key.id,
        )
    )

    # Audit log
    await log_event(
        db,
        tenant_id=tenant_id,
        user_id=user_id,
        action="device.authorize",
        resource_type="api_key",
        resource_id=str(api_key.id),
        detail={
            "key_id": key_id,
            "client_name": device_auth.client_name,
            "client_ip": device_auth.client_ip,
            "flow": "device_code",
        },
        ip_address=request.client.host if request.client else None,
    )

    logger.info(
        "Device flow completed: user=%s tenant=%s key_id=%s",
        user.email, tenant.slug, key_id,
    )

    token_data = DeviceTokenResponse(
        api_key=raw_key,
        api_key_prefix=f"ctx_{key_id}...",
        user_id=user.id,
        tenant_id=tenant.id,
        email=user.email,
        name=user.name,
        role=user.role,
        plan=tenant.plan,
        tenant_name=tenant.name,
    )
    return JSONResponse(
        content=token_data.model_dump(mode="json"),
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


# ── Magic-link / OTP device flow (cloud-magic-link spec §5.3) ────────────


def _account_status_label(account: Account | None) -> str:
    """Map account state to the §9 ``account_status`` log enum."""
    if account is None:
        return "new_signup"
    if getattr(account, "status", "active") == "disabled":
        return "disabled"
    return "existing_active"


def _client_ip(request: Request) -> str | None:
    """Best-effort client IP extraction respecting the trusted-proxy setup."""
    forwarded = request.headers.get("x-forwarded-for")
    peer_ip = request.client.host if request.client else None
    if peer_ip in {"127.0.0.1", "::1"} and forwarded:
        return forwarded.split(",", 1)[0].strip() or peer_ip
    return peer_ip


def _email_link_url(raw_token: str) -> str:
    """Build the magic-link URL embedded in the transactional email body."""
    return f"{settings.email_base_url.rstrip('/')}/cloud/device/email-link?token={raw_token}"


def _no_store_json(content: dict[str, object], status_code: int = 200) -> JSONResponse:
    return JSONResponse(
        content=content,
        status_code=status_code,
        headers={"Cache-Control": "no-store"},
    )


@router.post("/email-init", response_model=None)
async def email_init(
    request: Request,
    body: Annotated[DeviceEmailInitRequest, Body(...)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> JSONResponse:
    """Issue a magic-link / OTP email for the device flow.

    Returns the **same generic 200** for all branches (existing-active,
    new-signup, disabled, unknown) per spec §10 (email enumeration defense).
    Only true input validation failures (malformed device_code / setup_code)
    return 400.
    """
    if not await public_csrf_json_valid(request):
        # Route-level CSRF rejection happens BEFORE the service is invoked,
        # so route owns this funnel emission. (ct-1512 Shard C C3)
        logger.info(
            "event=device_flow_error error_code=csrf_invalid "
            "endpoint=email-init client_ip_hash=%s",
            hash_ip_for_logs(_client_ip(request)),
        )
        return _no_store_json(
            {"error": "csrf_invalid"}, status_code=403,
        )

    client_ip = _client_ip(request)
    user_agent = request.headers.get("user-agent")
    email_input = (body.email or "").strip()
    normalized = normalize_email(email_input)
    if not normalized or "@" not in normalized:
        # Route-level malformed-input rejection — service never runs.
        logger.info(
            "event=device_flow_error error_code=invalid_email "
            "endpoint=email-init client_ip_hash=%s",
            hash_ip_for_logs(client_ip),
        )
        return _no_store_json(
            {"error": "invalid_email"}, status_code=400,
        )

    device_authorization = await resolve_device_authorization(
        db,
        device_code=body.device_code,
        setup_code=body.setup_code,
    )
    if device_authorization is None:
        # Route-level invalid-user-code rejection — service never runs.
        logger.info(
            "event=device_flow_error error_code=invalid_user_code "
            "endpoint=email-init email_hash=%s client_ip_hash=%s",
            hash_email_for_logs(normalized),
            hash_ip_for_logs(client_ip),
        )
        return _no_store_json(
            {"error": "invalid_user_code"}, status_code=400,
        )

    # ct-1512 Shard B-1 / C-fix2: take a row-level lock on the
    # DeviceAuthorization row before the cap check so two concurrent
    # email-init requests for the same device cannot each observe count
    # < cap and each issue. The lock is released at commit (or rollback)
    # below; until then a parallel request blocks at this SELECT FOR
    # UPDATE call. This also doubles as a freshness re-check: if the
    # row was concurrently expired or fulfilled, we treat it as
    # invalid_user_code.
    locked_device_authorization = await lock_device_authorization_for_send(
        db, device_authorization_id=device_authorization.id,
    )
    if locked_device_authorization is None:
        logger.info(
            "event=device_flow_error error_code=invalid_user_code "
            "endpoint=email-init email_hash=%s client_ip_hash=%s "
            "reason=device_authorization_no_longer_pending",
            hash_email_for_logs(normalized),
            hash_ip_for_logs(client_ip),
        )
        return _no_store_json(
            {"error": "invalid_user_code"}, status_code=400,
        )
    device_authorization = locked_device_authorization

    if await device_email_send_cap_reached(
        db, device_authorization_id=device_authorization.id,
    ):
        # Route-level send-cap rejection — service never runs. Cap check
        # runs *inside* the row lock above so concurrent ``email-init``
        # requests for the same ``device_authorization_id`` are
        # serialized: the second request sees the count incremented by
        # the first (both real and sentinel rows count toward the cap,
        # closing ct-1512 Shard C C-3).
        logger.warning(
            "event=device_flow_error error_code=send_cap_reached "
            "endpoint=email-init device_authorization_id=%s email_hash=%s "
            "client_ip_hash=%s",
            device_authorization.id,
            hash_email_for_logs(normalized),
            hash_ip_for_logs(client_ip),
        )
        return _no_store_json(
            {"error": "rate_limited"}, status_code=429,
        )

    # Account lookup runs on EVERY branch (existing-active, new-signup,
    # disabled) — see ct-1512 Shard C C2 ``timing-strategy=equivalent-DB-work``
    # comment below.
    account_result = await db.execute(
        select(Account).where(Account.email_normalized == normalized)
    )
    account = account_result.scalar_one_or_none()
    account_status = _account_status_label(account)

    response_payload: dict[str, object] = {
        "status": "sent",
        "email_masked": mask_email(email_input),
        "expires_in": settings.auth_device_token_expiry_seconds,
        "otp_attempts_remaining": settings.auth_otp_attempts_per_token_max,
        "resend_available_in": settings.auth_email_resend_cooldown_seconds,
    }

    if account_status == "disabled":
        # Silent-skip: a *real* sentinel AuthToken row is issued (ct-1512
        # Shard C-fix2 C-1) so verify-otp behaves byte-identically to a
        # real-issuance branch — same response shape, same OTP attempt
        # counter, same lockout-at-5 semantics. Email-send is replaced
        # by a structurally-identical no-op task (sentinel branch of
        # ``_async_send_device_flow_email``) so request-time latency
        # matches the real branch (ct-1512 Shard C-fix2 C-2). Sentinel
        # rows count toward the per-device send cap (ct-1512 Shard C
        # C-3) because they carry the same ``device_authorization_id``
        # metadata stamp and ``device_email_send_cap_reached`` filters
        # purely on metadata.
        logger.info(
            "event=device_flow_email_init account_status=%s "
            "device_authorization_id=%s email_hash=%s client_ip_hash=%s "
            "endpoint=email-init",
            account_status,
            device_authorization.id,
            hash_email_for_logs(normalized),
            hash_ip_for_logs(client_ip),
        )
        logger.info(
            "event=device_flow_error error_code=silent_skip_disabled "
            "endpoint=email-init email_hash=%s",
            hash_email_for_logs(normalized),
        )
        sentinel = await issue_sentinel_email_token(
            db,
            purpose="device_login_existing_user",
            email_display=email_input,
            device_authorization=device_authorization,
        )
        await db.commit()

        async def _sentinel_sender(_to: str, _raw: str) -> bool:
            # Should never be invoked: the async-send task short-
            # circuits on ``is_sentinel`` before reaching the sender.
            # Defined for completeness so the type signature matches
            # the real-branch code path.
            return False

        await spawn_device_flow_email_send(
            token_id=sentinel.token.id,
            raw_token=sentinel.raw_token,
            sender=_sentinel_sender,
            workflow="device_login_existing_user",
        )
        response_payload["token_id"] = str(sentinel.token.id)
        return _build_email_init_response(request, response_payload)

    # Real-issuance path. The service layer (issue_device_email_token /
    # spawn_device_flow_email_send) emits ``device_flow_email_init`` and
    # ``device_flow_email_sent`` / ``device_flow_error(email_delivery_failed)``
    # — route MUST NOT re-emit. (ct-1512 Shard B B7 / Shard C C3)
    pending = await _issue_and_send_device_email(
        db,
        request_ip=client_ip,
        user_agent=user_agent,
        normalized=normalized,
        email_display=email_input,
        account=account,
        device_authorization=device_authorization,
        acquisition_attribution=attribution_from_request(request),
    )
    # ct-1512 Shard C-fix2 C-2: commit BEFORE spawning the async send so
    # the spawned task's fresh session can read the just-issued token. The
    # commit also persists the cross-purpose signup supersession even on the
    # suppressed (None) path below.
    await db.commit()
    if pending is None:
        # ct-2983 review-fix (FIX A): a concurrent signup won the shared
        # ``uq_auth_tokens_active_signup_email`` index. Suppress generically —
        # no token, no send — and return the SAME sent response with a
        # throwaway token_id so the device-signup path stays enumeration-safe.
        response_data: dict[str, object] = {
            **response_payload,
            "token_id": str(uuid.uuid4()),
        }
        return _build_email_init_response(request, response_data)
    # ct-1512 Shard C-fix2 C-2: commit already ran above; spawn the async send.
    await spawn_device_flow_email_send(
        token_id=pending.token.id,
        raw_token=pending.raw_token,
        sender=pending.sender,
        workflow=pending.workflow,
    )
    response_data = {
        **response_payload,
        "token_id": str(pending.token.id),
    }
    return _build_email_init_response(request, response_data)


def _build_email_init_response(
    request: Request, payload: dict[str, object],
) -> JSONResponse:
    response = _no_store_json(payload, status_code=200)
    set_public_csrf_cookie(response, request, public_csrf_token(request))
    return response


@dataclass(frozen=True)
class _PendingDeviceEmailSend:
    """Issued AuthToken + sender closure ready to be spawned post-commit.

    ct-1512 Shard C-fix2 C-2: ``_issue_and_send_device_email`` returns
    this struct so the route can commit the transaction BEFORE spawning
    the async send task. Ordering matters: the spawned task uses a fresh
    session that cannot see uncommitted writes, so ``await db.commit()``
    must precede ``await spawn_device_flow_email_send(...)``.
    """

    token: AuthToken
    raw_token: str
    sender: "Callable[[str, str], Awaitable[bool]]"
    workflow: str


async def _issue_and_send_device_email(
    db: AsyncSession,
    *,
    request_ip: str | None,
    user_agent: str | None,
    normalized: str,
    email_display: str,
    account: Account | None,
    device_authorization: DeviceAuthorization,
    acquisition_attribution: AcquisitionAttribution | None = None,
) -> _PendingDeviceEmailSend | None:
    """Issue the AuthToken row and prepare the email-send closure.

    Returns a ``_PendingDeviceEmailSend`` containing the issued token,
    raw token (for log URL re-derivation), sender closure (capturing
    OTP plaintext + email-specific kwargs), and workflow label. The
    caller MUST commit the issuance transaction BEFORE invoking
    ``spawn_device_flow_email_send`` with these fields so the spawned
    task's fresh session can read the just-committed row.

    Returns ``None`` when the device-signup issuance was suppressed because a
    concurrent signup won the shared ``uq_auth_tokens_active_signup_email``
    index (ct-2983 review-fix, FIX A): the caller renders the same generic
    sent state without spawning a send.

    The sender closure exists only for the spawned task's lifetime —
    the OTP plaintext is never persisted to the DB.
    """
    if account is not None:
        purpose = "device_login_existing_user"
        extra_metadata: dict[str, object] = {
            "user_code_hash": device_authorization.user_code_hash or "",
        }
    else:
        purpose = "device_signup_new_user"
        extra_metadata = {
            "signup_email": normalized,
            "user_code_hash": device_authorization.user_code_hash or "",
            "signup_metadata": {
                "client_ip": request_ip or "",
                "client_user_agent": user_agent or "",
            },
            **attribution_to_metadata(acquisition_attribution),
        }

    issued = await issue_device_email_token(
        db,
        account=account,
        email_display=email_display,
        purpose=purpose,
        device_authorization=device_authorization,
        extra_metadata=extra_metadata,
    )
    if issued is None:
        # ct-2983 review-fix (FIX A): device-signup insert was suppressed by a
        # concurrent signup winning the shared partial unique index. Propagate
        # the suppression so the route renders the generic sent state.
        return None
    device_name = display_device_name(device_authorization.client_name)
    expires_minutes = max(1, settings.auth_device_token_expiry_seconds // 60)
    magic_link = _email_link_url(issued.raw_token)

    async def _sender(_to: str, _raw: str) -> bool:
        if purpose == "device_login_existing_user":
            return await send_device_signin_existing_user(
                to_email=email_display,
                magic_link_url=magic_link,
                otp_code=issued.otp,
                device_name=device_name,
                expires_in_minutes=expires_minutes,
            )
        return await send_device_signup_new_user(
            to_email=email_display,
            signup_email=normalized,
            magic_link_url=magic_link,
            otp_code=issued.otp,
            device_name=device_name,
            expires_in_minutes=expires_minutes,
        )

    return _PendingDeviceEmailSend(
        token=issued.token,
        raw_token=issued.raw_token,
        sender=_sender,
        workflow=purpose,
    )


@router.post("/verify-otp", response_model=None)
async def verify_otp(
    request: Request,
    body: Annotated[DeviceVerifyOtpRequest, Body(...)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> JSONResponse | RedirectResponse:
    """Validate a typed OTP and finalize the device flow on success."""
    if not await public_csrf_json_valid(request):
        # ct-1512 Shard C C3: route-level CSRF rejection — service never
        # called, so route owns this funnel emission.
        logger.info(
            "event=device_flow_error error_code=csrf_invalid "
            "endpoint=verify-otp client_ip_hash=%s",
            hash_ip_for_logs(_client_ip(request)),
        )
        return _no_store_json({"error": "csrf_invalid"}, status_code=403)

    client_ip = _client_ip(request)
    user_agent = request.headers.get("user-agent")
    outcome = await verify_device_otp_attempt(
        db,
        token_id=body.token_id,
        otp=body.otp,
    )
    if not outcome.ok:
        # OTP-attempt failures are a route-level business event (the
        # service-level finalize never runs). Route emits.
        logger.info(
            "event=device_flow_error error_code=%s endpoint=verify-otp "
            "token_id=%s client_ip_hash=%s",
            outcome.error_code,
            body.token_id,
            hash_ip_for_logs(client_ip),
        )
        failure = DeviceVerifyOtpFailure(
            error_code=outcome.error_code or "otp_wrong",
            attempts_remaining=outcome.attempts_remaining,
        )
        return _no_store_json(
            failure.model_dump(),
            status_code=200,
        )

    assert outcome.token is not None  # noqa: S101 - narrowed by ok=True
    raw_token = reconstruct_raw_token(outcome.token)
    return await _finalize_and_set_session(
        request=request,
        db=db,
        raw_token=raw_token,
        client_ip=client_ip,
        user_agent=user_agent,
        method="otp",
    )


async def _finalize_and_set_session(
    *,
    request: Request,
    db: AsyncSession,
    raw_token: str,
    client_ip: str | None,
    user_agent: str | None,
    method: str,
) -> JSONResponse | RedirectResponse:
    """Shared finalize path for ``verify-otp`` and ``email-link/confirm``.

    Called after the OTP has matched (or after the magic-link interstitial
    POST has been validated). Calls ``_finalize_device_token``, sets the
    ``ctx_session`` cookie when a fresh session was created.

    ct-1512 Shard B/C contract: ``_finalize_device_token`` itself emits
    ``device_flow_finalized`` and ``device_flow_error`` (with the helper
    method label propagated through the ``method`` kwarg). Route MUST NOT
    re-emit those events.
    """
    try:
        result: FinalizeResult = await _finalize_device_token(
            db,
            raw_token=raw_token,
            db_session_user=None,
            request_ip=client_ip,
            user_agent=user_agent,
            method=method,
        )
    except BrowserAuthError:
        # ct-1512 Shard C C3: do NOT re-emit a route-level event here.
        # _finalize_device_token already emitted the appropriate
        # ``device_flow_error`` (token_unknown, account_resolve_rejected,
        # etc.) before raising.
        if method == "otp":
            failure = DeviceVerifyOtpFailure(
                error_code="token_unknown",
                attempts_remaining=0,
            )
            return _no_store_json(failure.model_dump(), status_code=200)
        # method == "link" : redirect to the device error page.
        return _redirect_to_device_error("link_invalid")

    redirect_url = "/cloud/device/success"
    if method == "otp":
        success = DeviceVerifyOtpSuccess(redirect=redirect_url)
        response: JSONResponse | RedirectResponse = _no_store_json(
            success.model_dump(),
            status_code=200,
        )
    else:
        response = RedirectResponse(redirect_url, status_code=303)

    # ct-1512 Shard B B3 / Shard C: prefer FinalizeResult.session_token to
    # avoid drifting session_version between commit and cookie set.
    if result.session is not None and result.session_token is not None:
        response.set_cookie(
            key=JWT_COOKIE_NAME,
            value=result.session_token,
            httponly=True,
            secure=is_secure_request(request),
            samesite="lax",
            max_age=settings.jwt_token_expire_hours * 3600,
            path="/cloud/",
        )
    return response


def _redirect_to_device_error(error_code: str) -> RedirectResponse:
    return RedirectResponse(
        f"/cloud/device?error_code={error_code}", status_code=303,
    )


# ── Browser-side magic-link interstitial (spec §5.3) ─────────────────────


@cloud_device_router.get("/email-link")
async def email_link_interstitial(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    token: str = "",
) -> Any:
    """Render the magic-link interstitial. Token is NOT consumed on GET.

    The interstitial defends against email-scanner pre-fetch (spec §10):
    pre-fetchers follow the GET URL but do not submit the form, so the
    actual ``consume_auth_token`` call only fires on
    ``POST /cloud/device/email-link/confirm``.

    On invalid / expired / consumed / superseded tokens the helper renders
    the same template with ``error_code`` set; impl 7 owns the device.html
    redesign that surfaces the §6 State E copy. The route reuses the
    existing minimal device.html until then.
    """
    error_code = await _classify_email_link_token(db, token)
    csrf_token = public_csrf_token(request)
    response = _templates.TemplateResponse(
        request,
        "cloud/device.html",
        {
            "request": request,
            "current_year": datetime.now(UTC).year,
            "registration_enabled": settings.enable_registration,
            "csp_nonce": getattr(request.state, "csp_nonce", ""),
            "auth": None,
            "error": _error_copy_for(error_code),
            "success": None,
            "confirm": None,
            "user_code": None,
            "csrf_token": csrf_token,
            # Magic-link interstitial context (impl 7 will read these to
            # render State A / B / E variants in cloud/device.html):
            "magic_link_state": "interstitial" if error_code is None else "error",
            "magic_link_token": token if error_code is None else None,
            "magic_link_error_code": error_code,
            "public_csrf_token": csrf_token,
            "confirm_action": "/cloud/device/email-link/confirm",
        },
        headers={
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer",
            "X-Robots-Tag": "noindex, nofollow",
        },
    )
    set_public_csrf_cookie(response, request, csrf_token)
    return response


def _error_copy_for(error_code: str | None) -> str | None:
    if error_code is None:
        return None
    if error_code == "token_expired":
        return "This sign-in link has expired. Request a new one from Contextify."
    if error_code == "token_consumed":
        return (
            "This link has already been used. If you didn't sign in, "
            "request a new one from Contextify."
        )
    if error_code == "superseded":
        return (
            "This email was replaced by a newer sign-in email. "
            "Use the latest email from Contextify."
        )
    return "This sign-in link is not valid. Request a new one from Contextify."


async def _classify_email_link_token(
    db: AsyncSession, raw_token: str,
) -> str | None:
    """Return ``None`` when the token is valid, else a §6 State E error code.

    The classification is read-only; the GET interstitial never mutates
    state (spec §10 email-scanner pre-fetch defense). Distinguishes
    consumed-by-success from consumed-by-resend (``superseded``) so impl 7
    can render the correct State E copy.
    """
    if not raw_token or len(raw_token) < 8:
        return "token_unknown"
    from contextify_cloud.services.browser_auth import _hash_token  # local import to avoid cycle
    now = datetime.now(UTC)
    result = await db.execute(
        select(AuthToken).where(AuthToken.token_hash == _hash_token(raw_token))
    )
    token = result.scalar_one_or_none()
    if token is None or token.purpose not in (
        "device_login_existing_user", "device_signup_new_user",
    ):
        return "token_unknown"
    if token.consumed_at is not None:
        # Distinguish superseded (resend invalidated) from a real consume.
        # A naive heuristic: tokens consumed before their expiry by another
        # call (status either authorized or active) are treated as
        # ``token_consumed``; anything else is ``superseded``. Without an
        # explicit flag the route conservatively reports ``superseded`` for
        # tokens whose delivery status was reset by replacement.
        metadata = token.metadata_json or {}
        prev_raw = metadata.get("otp_failed_attempts", 0)
        attempts = int(prev_raw) if isinstance(prev_raw, int | str) else 0
        if attempts >= settings.auth_otp_attempts_per_token_max:
            return "token_consumed"
        # If the device authorization tied to this token is already
        # ``authorized`` or ``completed``, classify as consumed (success).
        device_auth_id_str = metadata.get("device_authorization_id")
        if isinstance(device_auth_id_str, str):
            try:
                device_auth_id = uuid.UUID(device_auth_id_str)
            except ValueError:
                return "token_consumed"
            row = await db.execute(
                select(DeviceAuthorization.status).where(
                    DeviceAuthorization.id == device_auth_id,
                )
            )
            status_value = row.scalar_one_or_none()
            if status_value in {"authorized", "completed"}:
                return "token_consumed"
        return "superseded"
    if token.expires_at <= now:
        return "token_expired"
    return None


@cloud_device_router.post("/email-link/confirm", response_model=None)
async def email_link_confirm(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    token: Annotated[str, Form()],
) -> Any:
    """Consume a magic link via form POST and finalize the device flow."""
    if not await public_csrf_form_valid(request):
        # ct-1512 Shard C C3: route-level CSRF rejection — service never
        # called, so route owns this funnel emission.
        logger.info(
            "event=device_flow_error error_code=csrf_invalid "
            "endpoint=email-link-confirm client_ip_hash=%s",
            hash_ip_for_logs(_client_ip(request)),
        )
        return _redirect_to_device_error("csrf_invalid")
    client_ip = _client_ip(request)
    user_agent = request.headers.get("user-agent")
    return await _finalize_and_set_session(
        request=request,
        db=db,
        raw_token=token,
        client_ip=client_ip,
        user_agent=user_agent,
        method="link",
    )
