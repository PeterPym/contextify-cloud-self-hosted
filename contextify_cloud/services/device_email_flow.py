"""Device-flow magic-link / OTP service helpers (cloud-magic-link spec §5.3).

These helpers issue, look up, and update ``AuthToken`` rows for the new
``device_login_existing_user`` and ``device_signup_new_user`` purposes. They
sit between the route handlers in ``contextify_cloud.routers.device_auth``
and the lower-level token-issuance / finalization helpers in
``contextify_cloud.services.browser_auth``.

Responsibilities:
    * Generate a 6-digit OTP and stamp the salted SHA-256 hash on the new
      AuthToken metadata.
    * Constant-time OTP comparison via ``hmac.compare_digest`` per spec §10.
    * Per-token brute-force lockout at ``settings.auth_otp_attempts_per_token_max``
      failed attempts.
    * Per-device-code email send cap so a single CLI session cannot be used
      to email-bomb an arbitrary inbox.

Routing concerns (CSRF, rate limits, response shape, structured logging) all
live in the route handlers; this module just exposes a clean async API.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from contextify_cloud.config import settings
from contextify_cloud.models import Account, AuthToken, DeviceAuthorization
from contextify_cloud.services.browser_auth import (
    _emit_device_flow_email_init,
    _raw_token_for_auth_token,
    create_auth_token_record,
    lock_magic_link_issue_for_email,
)
from contextify_cloud.services.device_auth_codes import hash_user_code
from contextify_cloud.utils.email import normalize_email

logger = logging.getLogger(__name__)


_DEVICE_LOGIN_PURPOSE = "device_login_existing_user"
_DEVICE_SIGNUP_PURPOSE = "device_signup_new_user"
_LOGIN_MAGIC_LINK_PURPOSE = "login_magic_link"
_BROWSER_SIGNUP_PURPOSE = "browser_signup_new_user"
# ct-2983 review-fix: the two signup purposes that share the
# ``uq_auth_tokens_active_signup_email`` partial unique index. A new signup
# token for an email must supersede any active token in EITHER purpose so the
# device-flow and browser-flow signups cannot collide on the shared index.
_ACTIVE_SIGNUP_PURPOSES = (_DEVICE_SIGNUP_PURPOSE, _BROWSER_SIGNUP_PURPOSE)
# ct-2983 review-fix: the partial unique index whose collision the signup
# SAVEPOINT is allowed to suppress. Any other IntegrityError (CHECK, NOT-NULL,
# an unrelated unique index) must propagate rather than be masked as a generic
# "sent" state with no email actually sent.
_ACTIVE_SIGNUP_UNIQUE_CONSTRAINT = "uq_auth_tokens_active_signup_email"
_UNIQUE_VIOLATION_SQLSTATE = "23505"
_OTP_LENGTH = 6

# ── Sentinel-token enumeration defense (ct-1512 Shard C-fix2 C-1) ───────
#
# Silent-skip branches (disabled accounts in device + login flows; unknown
# emails in login flow) issue a *real* AuthToken row whose verify-otp
# behavior is byte-identical to a real token: same response shape, same
# attempts-remaining counter, same lockout-at-5 semantics. The only
# difference is two metadata flags:
#
#   * ``is_sentinel: True``   — recognized by ``_finalize_device_token``
#     and ``_finalize_login_token`` so a structurally-impossible OTP match
#     (random hash, never emailed) cannot accidentally complete the flow.
#   * ``delivery_status='exhausted'`` + ``delivery_last_error='sentinel_skipped'``
#     stamped at issue time — the auth-email outbox sweeper sees the
#     sentinel flag (or the terminal delivery_status) and never calls
#     Resend on the row.
#
# Sentinel rows hang off a single global "sentinel" Account row whose
# ``email_normalized`` is a reserved invalid-domain literal. Using a real
# account avoids the ``ck_auth_token_account_id_purpose_pairing`` check
# (login_magic_link / device_login_existing_user require account_id NOT
# NULL) without needing a schema migration.
_SENTINEL_ACCOUNT_EMAIL = "__ct1512_sentinel__@contextify.invalid"
_SENTINEL_PER_SUBJECT_EMAIL_TEMPLATE = "__ct1512_sentinel__+{key}@contextify.invalid"


def _sentinel_subject_key(*, purpose: str, email_normalized: str) -> str:
    """Derive a non-reversible per-subject key for sentinel scoping.

    Used by login-flow sentinels (where there is no ``device_authorization_id``
    to scope by) so the ``(account_id, purpose)`` partial unique index acts
    as a per-probe-email lock. Without this scoping, a single sentinel
    account would invalidate every active sentinel on each new probe,
    re-opening the C-1/D-2 enumeration oracle that round-2 review found.
    """
    payload = f"{purpose}|{email_normalized}".encode()
    return hmac.new(
        settings.api_secret_key.encode(),
        payload,
        hashlib.sha256,
    ).hexdigest()[:32]


@dataclass(frozen=True)
class IssuedDeviceToken:
    """Result of ``issue_device_email_token``.

    The route handler uses ``raw_token`` to build the magic-link URL,
    surfaces ``otp`` only via the email body (the API response only echoes
    ``token_id`` so the State A → B transition can post the OTP back).
    """

    token: AuthToken
    raw_token: str
    otp: str


def _hash_otp(otp: str) -> str:
    """Return the storage hash for an OTP value.

    ``sha256(otp || api_secret_key)`` per spec §5.2. The api_secret_key salt
    means a database leak does not reveal historical OTPs (the same OTP
    issued in two different deployments produces different hashes).
    """
    payload = f"{otp}|{settings.api_secret_key}".encode()
    return hashlib.sha256(payload).hexdigest()


def _generate_otp() -> str:
    """Return a 6-digit zero-padded numeric OTP per spec §5.3."""
    value = secrets.randbelow(10**_OTP_LENGTH)
    return f"{value:0{_OTP_LENGTH}d}"


def constant_time_compare(a: str, b: str) -> bool:
    """``hmac.compare_digest`` wrapper used for OTP comparison.

    Exposed so tests can monkey-patch the comparison and so route handlers
    do not import ``hmac`` directly.
    """
    return hmac.compare_digest(a, b)


async def resolve_device_authorization(
    db: AsyncSession,
    *,
    device_code: str | None,
    setup_code: str | None,
) -> DeviceAuthorization | None:
    """Look up a pending ``DeviceAuthorization`` by device_code or user_code.

    Returns ``None`` when neither identifier resolves or when the row is
    expired / not pending. The caller is responsible for the corresponding
    ``invalid_user_code`` HTTP error response. The lookup uses the keyed
    HMAC indices for both ``device_code_hash`` and ``user_code_hash``.

    Setup-code resolution accepts the spaced or de-spaced form; we strip /
    upper-case before hashing in line with ``hash_user_code``.
    """
    now = datetime.now(UTC)
    if device_code:
        from contextify_cloud.services.device_auth_codes import hash_device_code
        result = await db.execute(
            select(DeviceAuthorization).where(
                DeviceAuthorization.device_code_hash == hash_device_code(device_code),
                DeviceAuthorization.status == "pending",
                DeviceAuthorization.expires_at > now,
            )
        )
        row = result.scalar_one_or_none()
        if row is not None:
            return row
    if setup_code:
        normalized_user_code = setup_code.strip().upper()
        if not normalized_user_code:
            return None
        result = await db.execute(
            select(DeviceAuthorization).where(
                DeviceAuthorization.user_code_hash == hash_user_code(normalized_user_code),
                DeviceAuthorization.status == "pending",
                DeviceAuthorization.expires_at > now,
            )
        )
        row = result.scalar_one_or_none()
        if row is not None:
            return row
    return None


async def device_email_send_cap_reached(
    db: AsyncSession,
    *,
    device_authorization_id: uuid.UUID,
) -> bool:
    """Return ``True`` when the per-device-code email send cap is exhausted.

    Counts every AuthToken (active or not) whose
    ``metadata_json.device_authorization_id`` references the given device
    authorization. Spec §10. This includes tokens already invalidated by
    resend semantics, so a malicious caller cannot bypass the cap by
    forcing repeated resends.
    """
    cap = settings.auth_email_send_cap_per_device_code
    if cap <= 0:
        return False
    result = await db.execute(
        select(func.count())
        .select_from(AuthToken)
        .where(
            AuthToken.metadata_json["device_authorization_id"].astext
            == str(device_authorization_id),
        )
    )
    count = int(result.scalar_one() or 0)
    return count >= cap


async def lock_device_authorization_for_send(
    db: AsyncSession,
    *,
    device_authorization_id: uuid.UUID,
) -> DeviceAuthorization | None:
    """Take a row-level lock on a DeviceAuthorization for atomic cap+issue.

    ct-1512 Shard B-1 fix: ``device_email_send_cap_reached`` is a read-only
    SELECT; without serialization, two concurrent ``email-init`` requests for
    the same ``device_authorization_id`` can each observe count < cap and
    each issue a token, bypassing the per-device anti-email-bombing cap.
    Callers must hold this lock for the duration of the cap check + token
    insertion + commit so a parallel request blocks until the first request
    has either issued (incrementing the counted set) or rejected.

    Returns the locked row, or ``None`` when the row no longer exists /
    is no longer pending. Callers treat ``None`` as
    ``invalid_user_code``-equivalent.

    The lock is a Postgres ``SELECT ... FOR UPDATE`` on a single row scoped
    to the device authorization, which is cheaper than a table-level lock
    and matches the existing pattern used by ``poll_device_token``.
    """
    now = datetime.now(UTC)
    result = await db.execute(
        select(DeviceAuthorization)
        .where(
            DeviceAuthorization.id == device_authorization_id,
            DeviceAuthorization.status == "pending",
            DeviceAuthorization.expires_at > now,
        )
        .with_for_update()
    )
    return result.scalar_one_or_none()


async def get_or_create_sentinel_account(
    db: AsyncSession, *, subject_key: str | None = None,
) -> Account:
    """Return a sentinel Account, creating it on first use.

    Used as the ``account_id`` anchor for sentinel AuthToken rows issued by
    silent-skip branches of ``email-init``. Sentinel accounts are marked
    ``status='disabled'`` and use an invalid-domain email so they can never
    be discovered, logged into, or merged with a real human account.

    When ``subject_key`` is None (device flow — scoping is provided by
    ``device_authorization_id`` metadata), returns the singleton sentinel.

    When ``subject_key`` is provided (login flow — no device_authorization
    to scope by), returns a per-subject sentinel with a deterministic
    HMAC-derived plus-alias email. The ``(account_id, purpose)`` partial
    unique index then naturally provides per-probe-email scoping for
    sentinel invalidation, so probing a new email cannot consume a prior
    probe's sentinel token (the cross-token oracle that round-2 review
    caught).

    Concurrent first-time creation is handled via SELECT-then-INSERT with
    an INSERT race-loser path: the unique constraint on
    ``email_normalized`` rejects a duplicate INSERT, after which a
    re-SELECT returns the row created by the racing transaction.
    """
    if subject_key is None:
        target_email = _SENTINEL_ACCOUNT_EMAIL
    else:
        target_email = _SENTINEL_PER_SUBJECT_EMAIL_TEMPLATE.format(key=subject_key)

    result = await db.execute(
        select(Account).where(Account.email_normalized == target_email)
    )
    account = result.scalar_one_or_none()
    if account is not None:
        return account

    sentinel = Account(
        email_normalized=target_email,
        email_display=target_email,
        password_hash=None,
        status="disabled",
        email_verified_at=None,
    )
    db.add(sentinel)
    try:
        await db.flush()
    except IntegrityError:
        # Racing transaction inserted first. Roll the failed INSERT back
        # and re-SELECT — the row is now visible.
        await db.rollback()
        result = await db.execute(
            select(Account).where(
                Account.email_normalized == target_email,
            )
        )
        account = result.scalar_one_or_none()
        if account is None:
            # Should be impossible: IntegrityError implies a row exists.
            raise
        return account
    return sentinel


async def issue_sentinel_email_token(
    db: AsyncSession,
    *,
    purpose: str,
    email_display: str,
    email_normalized: str | None = None,
    device_authorization: DeviceAuthorization | None = None,
    extra_metadata: dict[str, object] | None = None,
) -> IssuedDeviceToken:
    """Issue a sentinel AuthToken for a silent-skip branch.

    The returned row is structurally identical to a real device-flow /
    login-flow token from the verify-otp surface's perspective:

      * Same ``purpose`` (``device_login_existing_user`` /
        ``login_magic_link``).
      * Same ``expires_at`` window.
      * Real (random) ``otp_hash`` stamped on metadata so
        ``verify_device_otp_attempt`` runs the constant-time hash compare
        against a real value.
      * ``otp_failed_attempts=0`` initially; the standard attempt counter
        + 5-attempt lockout machinery applies on every wrong OTP.
      * ``account_id`` set to the singleton sentinel account so the
        ``ck_auth_token_account_id_purpose_pairing`` check constraint is
        satisfied for ``login_magic_link`` / ``device_login_existing_user``
        without a schema migration.

    Differences from a real token (invisible to the verify-otp surface):

      * ``metadata_json["is_sentinel"] = True`` so finalize helpers refuse
        to consume the row even on the vanishingly improbable event of an
        OTP guess matching the sentinel's random hash.
      * ``delivery_status='exhausted'`` + ``delivery_last_error='sentinel_skipped'``
        stamped at issue time so the auth-email outbox sweeper never calls
        Resend on the row. ``delivery_attempts`` is set to the configured
        max so the outbox cannot reset it.
      * The sentinel's OTP value itself is never returned to the caller
        (callers do not pass it to a sender) and is not stored anywhere
        except the salted hash, so a database leak does not enable
        post-hoc OTP reconstruction.

    The route handler stamps the same ``device_authorization_id`` on the
    sentinel's metadata when applicable so the per-device send-cap counter
    (``device_email_send_cap_reached``) includes sentinel rows — closing
    ct-1512 Shard C C-3 (cap differential between real and silent-skip
    branches).
    """
    if purpose not in (_DEVICE_LOGIN_PURPOSE, _LOGIN_MAGIC_LINK_PURPOSE):
        # Sentinels for ``device_signup_new_user`` would conflict with the
        # ``uq_auth_tokens_active_signup_email`` partial unique index, so we
        # only support sentinels for purposes that require a non-null
        # account_id. The device flow's "unknown email" case escalates to a
        # real signup branch, so it never needs a sentinel.
        raise ValueError(
            f"sentinel tokens not supported for purpose={purpose!r}"
        )

    # Login-flow sentinels (no device_authorization) need per-subject
    # account scoping so the (account_id, purpose) unique index acts as
    # a per-probe-email lock. Without this, a fresh probe would consume
    # the prior probe's sentinel via the singleton-account scope, and
    # that cross-token consumption is itself an enumeration oracle
    # (round-2 review finding).
    subject_key: str | None = None
    if device_authorization is None:
        if email_normalized is None:
            raise ValueError(
                "login-flow sentinel issuance requires email_normalized "
                "for per-subject account scoping",
            )
        subject_key = _sentinel_subject_key(
            purpose=purpose, email_normalized=email_normalized,
        )

    sentinel_account = await get_or_create_sentinel_account(
        db, subject_key=subject_key,
    )
    otp = _generate_otp()
    metadata: dict[str, object] = {
        "otp_hash": _hash_otp(otp),
        "otp_failed_attempts": 0,
        "is_sentinel": True,
    }
    if device_authorization is not None:
        metadata["device_authorization_id"] = str(device_authorization.id)
        metadata["user_code_hash"] = device_authorization.user_code_hash or ""
    if subject_key is not None:
        metadata["sentinel_subject_key"] = subject_key
    if extra_metadata:
        metadata.update(extra_metadata)
        # ``is_sentinel`` is non-overridable.
        metadata["is_sentinel"] = True
        if subject_key is not None:
            metadata["sentinel_subject_key"] = subject_key

    # Per-device or per-account invalidation of any prior sentinel row so
    # the ``uq_auth_tokens_active_account_purpose`` partial unique index
    # (account_id, purpose) WHERE consumed_at IS NULL is not violated when
    # the same probe email is hit twice. For login-flow sentinels, the
    # per-subject account makes this scope per-probe-email by construction.
    now = datetime.now(UTC)
    if device_authorization is not None:
        await db.execute(
            update(AuthToken)
            .where(
                AuthToken.purpose == purpose,
                AuthToken.consumed_at.is_(None),
                AuthToken.metadata_json["device_authorization_id"].astext
                == str(device_authorization.id),
            )
            .values(consumed_at=now)
        )
    else:
        await db.execute(
            update(AuthToken)
            .where(
                AuthToken.purpose == purpose,
                AuthToken.account_id == sentinel_account.id,
                AuthToken.consumed_at.is_(None),
            )
            .values(consumed_at=now)
        )

    token, raw_token = await create_auth_token_record(
        db,
        account=sentinel_account,
        email=email_display,
        purpose=purpose,
        expires_in=timedelta(seconds=settings.auth_device_token_expiry_seconds),
        metadata=metadata,
        skip_prior_invalidation=True,
    )
    # Stamp the sentinel's delivery-state to a terminal value at issue
    # time so the outbox sweeper short-circuits on the first sweep without
    # ever calling the email sender. ``exhausted`` is in the existing
    # ``ck_auth_token_delivery_status`` allow-list, so no migration.
    token.delivery_status = "exhausted"
    token.delivery_attempts = settings.auth_email_delivery_max_attempts
    token.delivery_next_attempt_at = None
    token.delivery_last_error = "sentinel_skipped"
    await db.flush()

    return IssuedDeviceToken(token=token, raw_token=raw_token, otp=otp)


def is_sentinel_token(token: AuthToken) -> bool:
    """Return ``True`` when ``token`` is a sentinel issued for silent-skip.

    Used by ``_finalize_device_token`` / ``_finalize_login_token`` to refuse
    consumption even on a structurally-impossible OTP match. Cheap pure
    function: checks ``metadata_json['is_sentinel']`` for a truthy value.
    """
    metadata = token.metadata_json or {}
    return bool(metadata.get("is_sentinel", False))


async def issue_device_email_token(
    db: AsyncSession,
    *,
    account: Account | None,
    email_display: str,
    purpose: str,
    device_authorization: DeviceAuthorization,
    extra_metadata: dict[str, object] | None = None,
) -> IssuedDeviceToken | None:
    """Create a new device-flow magic-link / OTP AuthToken row.

    Stamps the OTP hash and ``device_authorization_id`` on
    ``metadata_json``. For ``device_signup_new_user`` the helper itself
    re-normalizes ``metadata['signup_email']`` defensively (ct-1512
    finding B6): the partial unique index
    ``uq_auth_tokens_active_signup_email`` indexes the canonical form, so
    callers that forget to normalize must not be able to bypass the
    index by passing a mixed-case address.

    Resend semantics for LOGIN (ct-1512 finding B4): prior-token invalidation
    is scoped to ``(purpose, device_authorization_id)`` rather than
    ``(purpose, email_normalized)`` / ``(purpose, account_id)`` so a re-send
    for one device flow cannot clobber an active flow for the same
    email/account on a *different* device. The wider scope is skipped via
    ``skip_prior_invalidation=True`` and the targeted UPDATE runs in this
    helper.

    ct-2983 review-fix (FIX A, symmetric cross-flow supersession): the SIGNUP
    branch (``device_signup_new_user``) instead routes through the shared
    ``_issue_signup_token_serialized`` contract so it honors the
    ``uq_auth_tokens_active_signup_email`` partial unique index that also
    covers ``browser_signup_new_user``. A lingering browser-signup token for
    the same email is superseded before the device insert (and vice-versa),
    so the two flows cannot collide on the shared index in either ordering.
    Because the shared index already forces at most one active signup token
    per email, the per-device-scoped invalidation is unnecessary for signup —
    the email-scoped supersession is a strict superset. Returns ``None`` when a
    concurrent signup won the shared index (the caller renders the same generic
    sent state, no 500, no enumeration signal). The device flow keeps its
    exemption from the browser SEND cooldown — only the shared-index
    supersession + serialization lock is shared.
    """
    if purpose not in (_DEVICE_LOGIN_PURPOSE, _DEVICE_SIGNUP_PURPOSE):
        raise ValueError(f"unsupported device-flow purpose: {purpose!r}")

    otp = _generate_otp()
    metadata: dict[str, object] = {
        "device_authorization_id": str(device_authorization.id),
        "otp_hash": _hash_otp(otp),
        "otp_failed_attempts": 0,
    }
    if extra_metadata:
        metadata.update(extra_metadata)

    if purpose == _DEVICE_SIGNUP_PURPOSE:
        # Defense-in-depth: re-normalize signup_email so the partial unique
        # index covers the canonical form even when the caller forgets.
        raw_signup = metadata.get("signup_email")
        if isinstance(raw_signup, str) and raw_signup:
            metadata["signup_email"] = normalize_email(raw_signup)
        signup_email_key = str(metadata.get("signup_email") or "")

        # Shared serialized issuance contract (advisory lock + cross-purpose
        # supersession + SAVEPOINT insert with narrowed integrity handling).
        issued = await _issue_signup_token_serialized(
            db,
            email_normalized=signup_email_key,
            email_display=email_display,
            purpose=_DEVICE_SIGNUP_PURPOSE,
            metadata=metadata,
        )
        if issued is None:
            return None
        token, raw_token = issued
    else:
        # LOGIN branch: per-device invalidation — replace any prior unconsumed
        # token for *this same device_authorization_id* (ct-1512 finding B4).
        now = datetime.now(UTC)
        await db.execute(
            update(AuthToken)
            .where(
                AuthToken.purpose == purpose,
                AuthToken.consumed_at.is_(None),
                AuthToken.metadata_json["device_authorization_id"].astext
                == str(device_authorization.id),
            )
            .values(consumed_at=now)
        )

        token, raw_token = await create_auth_token_record(
            db,
            account=account,
            email=email_display,
            purpose=purpose,
            expires_in=timedelta(seconds=settings.auth_device_token_expiry_seconds),
            metadata=metadata,
            skip_prior_invalidation=True,
        )

    # Funnel-stage emission (ct-1512 finding B7): the service layer owns
    # the ``device_flow_email_init`` event so route handlers do not
    # double-emit the same funnel stage.
    _emit_device_flow_email_init(
        purpose=purpose,
        account_status="existing" if account is not None else "new",
        device_authorization_id=device_authorization.id,
        email_normalized=token.email_normalized or email_display,
        client_ip=None,
        token_id=token.id,
        endpoint="email-init",
    )

    return IssuedDeviceToken(token=token, raw_token=raw_token, otp=otp)


@dataclass(frozen=True)
class OtpVerificationOutcome:
    """Result of ``verify_device_otp_attempt``.

    ``ok`` is True only when the OTP matched and the token is still valid.
    The route handler then reconstructs the raw token via
    ``_raw_token_for_auth_token`` and calls ``_finalize_device_token``.

    Failure modes carry a stable ``error_code`` matching spec §6 State E:
        * ``token_unknown``  - no AuthToken with this id
        * ``token_consumed`` - already consumed (success or lockout)
        * ``token_expired``  - expires_at < now()
        * ``otp_wrong``      - OTP mismatch (attempt counter incremented)
        * ``otp_locked``     - attempts exhausted; token invalidated
    """

    ok: bool
    token: AuthToken | None
    error_code: str | None
    attempts_remaining: int | None


async def verify_device_otp_attempt(
    db: AsyncSession,
    *,
    token_id: uuid.UUID,
    otp: str,
    purpose_allowlist: tuple[str, ...] = (_DEVICE_LOGIN_PURPOSE, _DEVICE_SIGNUP_PURPOSE),
) -> OtpVerificationOutcome:
    """Validate a typed OTP against the stored hash.

    On mismatch the helper atomically bumps ``metadata_json.otp_failed_attempts``
    and, when the cap is reached, marks the token consumed with the locked
    sentinel so it cannot be replayed. On match the helper does NOT consume
    the token; the caller calls ``_finalize_device_token(db, raw_token=...)``
    or ``_finalize_login_token(db, raw_token=...)`` which performs the atomic
    consume + finalize.

    ``purpose_allowlist`` defaults to the device-flow purposes; the
    ``/cloud/login`` magic-link flow (ct-1563) passes ``("login_magic_link",)``
    so the same OTP attempt / lockout machinery applies without a parallel
    helper. All comparisons use ``hmac.compare_digest`` per spec §10.
    """
    now = datetime.now(UTC)
    result = await db.execute(
        select(AuthToken).where(AuthToken.id == token_id).with_for_update()
    )
    token = result.scalar_one_or_none()
    if token is None:
        return OtpVerificationOutcome(
            ok=False, token=None, error_code="token_unknown", attempts_remaining=None
        )
    if token.consumed_at is not None:
        # Distinguish lockout from a successful consume so the route can
        # render the right §6 State E copy; both invalidate the OTP path.
        prev_attempts_raw = (token.metadata_json or {}).get("otp_failed_attempts", 0)
        attempts = int(prev_attempts_raw) if isinstance(prev_attempts_raw, int | str) else 0
        cap = settings.auth_otp_attempts_per_token_max
        error_code = "otp_locked" if attempts >= cap else "token_consumed"
        return OtpVerificationOutcome(
            ok=False, token=token, error_code=error_code, attempts_remaining=0
        )
    if token.expires_at <= now:
        return OtpVerificationOutcome(
            ok=False, token=token, error_code="token_expired", attempts_remaining=None
        )

    # Constant-time path (ct-1512 finding B5): always compute and compare
    # the OTP hash *before* checking purpose-allowlist membership, so the
    # response timing does not leak which purpose a tokenId belongs to.
    # The submitted_hash compare is the dominant time cost; doing it
    # first equalizes the response time across mismatched-purpose vs
    # mismatched-OTP cases.
    metadata = dict(token.metadata_json or {})
    stored_hash = metadata.get("otp_hash")
    if not isinstance(stored_hash, str) or not stored_hash:
        # Compute a dummy compare against a zero hash so the timing is
        # equivalent to the real path even when the token is malformed.
        constant_time_compare(_hash_otp(otp), "0" * 64)
        return OtpVerificationOutcome(
            ok=False, token=token, error_code="token_unknown", attempts_remaining=None
        )

    submitted_hash = _hash_otp(otp)
    hash_matches = constant_time_compare(submitted_hash, stored_hash)
    purpose_allowed = token.purpose in purpose_allowlist
    sentinel = is_sentinel_token(token)

    if hash_matches and purpose_allowed and not sentinel:
        return OtpVerificationOutcome(
            ok=True, token=token, error_code=None, attempts_remaining=None
        )

    if hash_matches and (not purpose_allowed or sentinel):
        # Hash matched but the token is unusable (wrong purpose, or a
        # sentinel issued by a silent-skip branch). Fall through to the
        # mismatch path so the response shape — including the
        # ``otp_failed_attempts`` increment + lockout-at-5 — is identical
        # to a real wrong-OTP attempt. ct-1512 Shard C-fix2 C-1: a
        # vanishingly improbable hash collision against a sentinel must
        # not finalize, but it must also not signal "this id is special"
        # via a unique error code.
        hash_matches = False

    # Hash mismatch: bump attempts / lock the token. Identical behavior
    # for in-purpose vs out-of-purpose tokens.
    prev_raw = metadata.get("otp_failed_attempts", 0)
    attempts = (int(prev_raw) if isinstance(prev_raw, int | str) else 0) + 1
    metadata["otp_failed_attempts"] = attempts
    cap = settings.auth_otp_attempts_per_token_max
    locked = attempts >= cap
    values: dict[str, object] = {"metadata_json": metadata}
    if locked:
        # Set consumed_at with the same sentinel semantics existing
        # consume_auth_token uses. The token row stays in place so
        # the OtpVerificationOutcome can read attempts after the fact.
        values["consumed_at"] = now
    await db.execute(
        update(AuthToken).where(AuthToken.id == token.id).values(**values)
    )
    await db.commit()
    return OtpVerificationOutcome(
        ok=False,
        token=token,
        error_code="otp_locked" if locked else "otp_wrong",
        attempts_remaining=max(0, cap - attempts),
    )


def reconstruct_raw_token(token: AuthToken) -> str:
    """Re-derive the raw magic-link token from an AuthToken row.

    Used after ``verify_device_otp_attempt`` reports success: the OTP path
    only knows ``token_id``, but ``_finalize_device_token`` consumes by
    raw_token. The reconstruction is deterministic per
    ``_raw_token_for_auth_token`` and never stores plaintext.
    """
    return _raw_token_for_auth_token(token.id, token.purpose)


# ── /cloud/login magic-link flow (cloud-magic-link spec §13b) ────────────


async def issue_login_email_token(
    db: AsyncSession,
    *,
    account: Account,
    email_display: str,
) -> IssuedDeviceToken:
    """Create a new ``login_magic_link`` AuthToken row for ``/cloud/login``.

    Sister of ``issue_device_email_token`` for the no-device login flow
    described in spec §13b. There is no ``device_authorization_id`` to
    stamp; the metadata only carries the OTP hash + attempt counter. The
    underlying ``create_auth_token_record`` helper invalidates any prior
    unconsumed AuthToken with the same ``(purpose, account_id)`` pair, so a
    second ``/api/v1/auth/login/email-link`` for the same account naturally
    invalidates the prior token before issuing a fresh one (matches the
    device-flow resend semantics in spec §13 done-when 10).

    The caller is responsible for the email-enumeration defense: only call
    this for existing, non-disabled accounts (spec §13b). Disabled or
    unknown emails must silent-skip without invoking this helper.
    """
    otp = _generate_otp()
    metadata: dict[str, object] = {
        "otp_hash": _hash_otp(otp),
        "otp_failed_attempts": 0,
    }

    token, raw_token = await create_auth_token_record(
        db,
        account=account,
        email=email_display,
        purpose=_LOGIN_MAGIC_LINK_PURPOSE,
        expires_in=timedelta(seconds=settings.auth_device_token_expiry_seconds),
        metadata=metadata,
    )

    # Funnel-stage emission (ct-1512 finding B7): service layer owns
    # ``device_flow_email_init`` so route handlers do not double-emit.
    _emit_device_flow_email_init(
        purpose=_LOGIN_MAGIC_LINK_PURPOSE,
        account_status="existing",
        device_authorization_id=None,
        email_normalized=token.email_normalized or email_display,
        client_ip=None,
        token_id=token.id,
        endpoint="login-email-init",
    )

    return IssuedDeviceToken(token=token, raw_token=raw_token, otp=otp)


async def _supersede_active_signup_tokens(
    db: AsyncSession, *, email_normalized: str
) -> None:
    """Consume any unconsumed signup token for this email across BOTH purposes.

    ct-2983 review-fix (cross-flow collision): ``create_auth_token_record``
    only supersedes the same ``(purpose, email)`` pair, but the
    ``uq_auth_tokens_active_signup_email`` partial unique index covers
    ``device_signup_new_user`` AND ``browser_signup_new_user`` on the shared
    ``lower(btrim(metadata_json->>'signup_email'))`` key. A lingering
    unconsumed ``device_signup_new_user`` token would otherwise collide with a
    fresh ``browser_signup_new_user`` insert (IntegrityError -> 500 and an
    enumeration oracle). The predicate matches the index's key expression
    exactly so every colliding row is superseded.
    """
    signup_email_key = func.lower(func.btrim(AuthToken.metadata_json["signup_email"].astext))
    await db.execute(
        update(AuthToken)
        .where(
            AuthToken.purpose.in_(_ACTIVE_SIGNUP_PURPOSES),
            AuthToken.consumed_at.is_(None),
            signup_email_key == email_normalized,
        )
        .values(consumed_at=datetime.now(UTC))
    )


def _integrity_constraint_name(orig: object | None) -> str | None:
    """Best-effort extraction of the violated constraint name.

    asyncpg surfaces ``constraint_name`` directly on the wrapped driver error;
    psycopg exposes it via ``diag.constraint_name``. Returns ``None`` when the
    driver does not attach the name so the caller can fall back to matching the
    constraint literal in the error text.
    """
    if orig is None:
        return None
    name = getattr(orig, "constraint_name", None)
    if name:
        return str(name)
    diag = getattr(orig, "diag", None)
    if diag is not None:
        name = getattr(diag, "constraint_name", None)
        if name:
            return str(name)
    return None


def _is_active_signup_unique_violation(exc: IntegrityError) -> bool:
    """Return ``True`` only for a unique violation on the shared signup index.

    ct-2983 review-fix (FIX B, overbroad IntegrityError suppression): the
    signup SAVEPOINT must swallow ONLY the expected
    ``uq_auth_tokens_active_signup_email`` collision (SQLSTATE ``23505`` on that
    constraint). A CHECK, NOT-NULL, or unrelated-unique violation would
    otherwise be silently converted into a generic "check your email" sent
    state with no email sent, hiding a real defect. Those must propagate.

    SQLSTATE is read defensively from both driver shapes (asyncpg
    ``sqlstate`` / psycopg ``pgcode``). The constraint name is read from the
    driver diagnostic when available, with a substring match on the error text
    as the fallback for drivers that do not attach it.
    """
    orig = getattr(exc, "orig", None)
    sqlstate = getattr(orig, "sqlstate", None) or getattr(orig, "pgcode", None)
    if sqlstate != _UNIQUE_VIOLATION_SQLSTATE:
        return False
    constraint = _integrity_constraint_name(orig)
    if constraint is not None:
        return constraint == _ACTIVE_SIGNUP_UNIQUE_CONSTRAINT
    # Fallback: the driver did not surface a constraint name; match the literal.
    return _ACTIVE_SIGNUP_UNIQUE_CONSTRAINT in str(orig if orig is not None else exc)


async def _issue_signup_token_serialized(
    db: AsyncSession,
    *,
    email_normalized: str,
    email_display: str,
    purpose: str,
    metadata: dict[str, object],
) -> tuple[AuthToken, str] | None:
    """Serialized, shared-index-safe issuance for a signup-purpose AuthToken.

    ct-2983 review-fix (FIX A, symmetric cross-flow supersession): the single
    issuance contract honored by BOTH signup paths — ``/cloud/register``
    (``browser_signup_new_user``) and the device-flow signup branch
    (``device_signup_new_user``). Both purposes share the
    ``uq_auth_tokens_active_signup_email`` partial unique index, so a token
    issued in either purpose must supersede any active token in EITHER purpose
    for the same email, or the second insert collides on the shared index
    (IntegrityError -> 500 and a distinguishable-latency enumeration oracle).

    The contract, in order:

      1. Acquire the per-email issuance advisory lock so two concurrent
         signups (device + browser, or two browsers) for the same email
         serialize rather than racing the supersession/insert window.
      2. Supersede every active signup token for the email across BOTH signup
         purposes (``_supersede_active_signup_tokens``).
      3. Insert inside a SAVEPOINT; a residual collision on the shared index
         (a concurrent signup that committed between the supersession and the
         insert) is caught via the NARROWED ``_is_active_signup_unique_violation``
         check and treated as generic suppression -> returns ``None``. Every
         other IntegrityError re-raises (FIX B).

    Returns ``(token, raw_token)`` on success, or ``None`` when the shared index
    rejected the insert (the caller renders the same generic sent state, no 500,
    no enumeration signal). The device flow keeps its exemption from the browser
    SEND cooldown; only this shared-index supersession + serialization lock is
    shared, not the cooldown check.
    """
    if purpose not in _ACTIVE_SIGNUP_PURPOSES:
        raise ValueError(f"not a signup purpose: {purpose!r}")

    # (1) serialize the per-email check-and-issue.
    await lock_magic_link_issue_for_email(db, email_normalized=email_normalized)
    # (2) cross-purpose supersession across both signup purposes.
    await _supersede_active_signup_tokens(db, email_normalized=email_normalized)
    # (3) SAVEPOINT-wrapped insert with narrowed integrity handling (FIX B).
    try:
        async with db.begin_nested():
            token, raw_token = await create_auth_token_record(
                db,
                account=None,
                email=email_display,
                purpose=purpose,
                expires_in=timedelta(seconds=settings.auth_device_token_expiry_seconds),
                metadata=metadata,
            )
    except IntegrityError as exc:
        if not _is_active_signup_unique_violation(exc):
            raise
        logger.info(
            "event=signup_token_issue_suppressed_by_race purpose=%s",
            purpose,
        )
        return None
    return token, raw_token


async def issue_register_signup_email_token(
    db: AsyncSession,
    *,
    email_display: str,
    email_normalized: str,
    extra_metadata: dict[str, object] | None = None,
) -> IssuedDeviceToken | None:
    """Create a new ``browser_signup_new_user`` AuthToken for ``/cloud/register``.

    ct-2983 (Option B+ / Decision-2a): the browser analogue of
    ``issue_device_email_token`` for the no-device, email-first sign-up flow.
    There is no ``account_id`` (the account is created passwordless only when
    the emailed link / OTP is consumed) and no ``device_authorization_id``; the
    metadata carries the OTP hash + attempt counter plus the ``signup_email``,
    ``signup_metadata`` and acquisition attribution stamped by the caller.

    Like ``issue_device_email_token`` the helper defensively re-normalizes
    ``signup_email`` so the ``uq_auth_tokens_active_signup_email`` partial
    unique index covers the canonical form even when the caller forgets.

    ct-2983 review-fix: before inserting, it supersedes any active token in
    EITHER signup purpose for this email (``_supersede_active_signup_tokens``)
    so a lingering ``device_signup_new_user`` token cannot collide with the new
    ``browser_signup_new_user`` insert on the shared partial unique index. The
    insert is wrapped in a SAVEPOINT; a residual ``IntegrityError`` (a
    concurrent signup won the index between the supersession and the insert) is
    caught and treated as generic suppression -> returns ``None`` so the caller
    renders the same "check your email" sent state (no 500, no second send, no
    enumeration signal).

    The email-enumeration defense lives in the caller: only call this for
    unknown emails when registration is enabled. Existing accounts get a
    login magic link; disabled accounts silent-skip via a sentinel.
    """
    otp = _generate_otp()
    metadata: dict[str, object] = {
        "otp_hash": _hash_otp(otp),
        "otp_failed_attempts": 0,
        "signup_email": email_normalized,
    }
    if extra_metadata:
        metadata.update(extra_metadata)

    # Defense-in-depth: re-normalize signup_email so the partial unique index
    # covers the canonical form even when the caller passes a mixed-case value.
    raw_signup = metadata.get("signup_email")
    if isinstance(raw_signup, str) and raw_signup:
        metadata["signup_email"] = normalize_email(raw_signup)
    signup_email_key = str(metadata["signup_email"])

    # ct-2983 review-fix: shared serialized issuance contract (advisory lock +
    # cross-purpose supersession + SAVEPOINT-guarded insert with narrowed
    # integrity handling). Identical to the device-flow signup branch so the
    # two paths cannot collide on the shared partial unique index in either
    # ordering.
    issued = await _issue_signup_token_serialized(
        db,
        email_normalized=signup_email_key,
        email_display=email_display,
        purpose=_BROWSER_SIGNUP_PURPOSE,
        metadata=metadata,
    )
    if issued is None:
        return None
    token, raw_token = issued

    # Funnel-stage emission (ct-1512 finding B7): service layer owns
    # ``device_flow_email_init`` so route handlers do not double-emit.
    _emit_device_flow_email_init(
        purpose=_BROWSER_SIGNUP_PURPOSE,
        account_status="new",
        device_authorization_id=None,
        email_normalized=token.email_normalized or email_display,
        client_ip=None,
        token_id=token.id,
        endpoint="register-email-init",
    )

    return IssuedDeviceToken(token=token, raw_token=raw_token, otp=otp)
