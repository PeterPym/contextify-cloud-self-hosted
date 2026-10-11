"""Caps on sign-up and sign-in emails, plus a spike alert.

The per-email cooldown (``magic_link_send_within_cooldown``) stops one address
from being mailed every minute. It does nothing against a scripted client
that rotates proxies and submits a different real address each time, which
is how the 2026-10-04 signup bot drained most of the daily Resend quota.

Every request to an email-sending endpoint (``/cloud/register``, the
``/cloud/login`` email link, device ``email-init``) is counted the same way
whatever the address, before the account branch, so no count or outcome
depends on whether the address has an account:

* Per client IP, hourly. Over the cap the request gets a 429 with a plain
  message.
* Globally, hourly and daily. Over the global cap, emails to addresses that
  have no account (new sign-ups) are paused: the request takes the same
  sentinel path as a disabled account, so its response and any later OTP
  attempt look exactly like a real issuance, and nothing is sent. Sign-in
  emails to existing accounts still go out, so a flood cannot lock users
  out. The operator is alerted.

There is deliberately no per-address cap: anyone can request mail for any
address, so such a cap would let three requests block one person's sign-in.
Mail to one existing address stays bounded by the per-IP cap and, in the
browser flows, the per-email cooldown.

Counting is synchronous with the check (the event loop does not switch
between them), so concurrent requests cannot overrun a cap. Counts are kept
per minute (a window always includes the minute its start falls in, so a cap
is never exceeded within any rolling hour), the per-IP table holds at most
``MAX_TRACKED_IPS`` keys (past that, new IPs share one capped overflow
counter), and idle keys are dropped on a fixed one-minute cadence.

State is in process memory. The API runs a single uvicorn worker
(``entrypoint.sh``), so the counts are exact for that process; a restart
(a deploy) clears them. A value of 0 disables the matching cap or alert.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import Counter
from dataclasses import dataclass

from contextify_cloud.config import settings
from contextify_cloud.utils.email import hash_email_for_logs, hash_ip_for_logs

logger = logging.getLogger(__name__)

HOUR_SECONDS = 3600.0
DAY_SECONDS = 86400.0
# One alert per kind per hour at most; the operator email itself goes through
# the same transactional sender these caps protect.
ALERT_INTERVAL_SECONDS = 3600.0
# Idle per-IP keys are swept this often.
_SWEEP_INTERVAL_SECONDS = 60.0
# Hard bound on the per-IP table. Past it, new IPs share one overflow counter
# with the same cap (fail closed for them) until the sweep frees room.
MAX_TRACKED_IPS = 20_000
_OVERFLOW_KEY = "overflow"

IP_LIMITED_MESSAGE = (
    "Too many sign-in emails were requested from your network. "
    "Please try again in an hour."
)


class _MinuteCounter:
    """Event counts in one-minute buckets: O(window minutes) memory."""

    __slots__ = ("_buckets",)

    def __init__(self) -> None:
        self._buckets: Counter[int] = Counter()

    def add(self, now: float) -> None:
        self._buckets[int(now // 60)] += 1

    def count_since(self, now: float, window: float) -> int:
        # Include the whole minute the window starts in: counts may run a little
        # high near the edge, never low.
        first = int((now - window) // 60)
        return sum(n for minute, n in self._buckets.items() if minute >= first)

    def prune(self, now: float, window: float) -> None:
        first = int((now - window) // 60)
        for minute in [m for m in self._buckets if m < first]:
            del self._buckets[minute]

    def empty(self) -> bool:
        return not self._buckets

    def clear(self) -> None:
        self._buckets.clear()


_requests = _MinuteCounter()  # every counted request, all endpoints
_rejected = _MinuteCounter()  # form-shield rejections (no email sent)
_by_ip: dict[str, _MinuteCounter] = {}
_overflow = _MinuteCounter()  # shared by new IPs while _by_ip is full
_last_sweep = 0.0
_last_alert_at: dict[str, float] = {}
# Strong references to in-flight alert tasks so they are not collected early.
_alert_tasks: set[asyncio.Task[None]] = set()


@dataclass(frozen=True)
class AuthEmailLimit:
    """Why a request was refused (``ip``)."""

    scope: str
    message: str


@dataclass(frozen=True)
class AuthEmailDecision:
    """``limit`` refuses the request (429). Otherwise it proceeds, and when
    ``new_address_paused`` an address with no account must get the generic
    response without an email."""

    limit: AuthEmailLimit | None = None
    new_address_paused: bool = False


def reset_auth_email_limit_state() -> None:
    """Clear all counters and alert debounce state (tests)."""
    global _last_sweep
    _requests.clear()
    _rejected.clear()
    _by_ip.clear()
    _overflow.clear()
    _last_alert_at.clear()
    _last_sweep = 0.0


def _sweep(now: float) -> None:
    global _last_sweep
    if now - _last_sweep < _SWEEP_INTERVAL_SECONDS:
        return
    _last_sweep = now
    _requests.prune(now, DAY_SECONDS)
    _rejected.prune(now, HOUR_SECONDS)
    _overflow.prune(now, HOUR_SECONDS)
    for key in list(_by_ip):
        counter = _by_ip[key]
        counter.prune(now, HOUR_SECONDS)
        if counter.empty():
            del _by_ip[key]


def check_auth_email_request(
    client_ip: str | None, email_normalized: str, *, endpoint: str
) -> AuthEmailDecision:
    """Check and count one request, before the account branch.

    A refused request is not counted. An allowed one is counted at once, so a
    concurrent request sees it.
    """
    now = time.monotonic()
    _sweep(now)
    ip_key = client_ip or "unknown"
    ip_cap = settings.auth_email_send_cap_per_ip_per_hour
    ip_counter = _by_ip.get(ip_key)
    if ip_counter is None and ip_cap > 0 and len(_by_ip) >= MAX_TRACKED_IPS:
        ip_key = _OVERFLOW_KEY
        ip_counter = _overflow

    limit: AuthEmailLimit | None = None
    if ip_cap > 0 and ip_counter and ip_counter.count_since(now, HOUR_SECONDS) >= ip_cap:
        limit = AuthEmailLimit(scope="ip", message=IP_LIMITED_MESSAGE)
    if limit is not None:
        logger.warning(
            "event=auth_email_send_limited scope=%s endpoint=%s client_ip_hash=%s email_hash=%s",
            limit.scope,
            endpoint,
            hash_ip_for_logs(client_ip),
            hash_email_for_logs(email_normalized),
        )
        return AuthEmailDecision(limit=limit)

    day_cap = settings.auth_email_send_cap_global_per_day
    hour_cap = settings.auth_email_send_cap_global_per_hour
    paused = (day_cap > 0 and _requests.count_since(now, DAY_SECONDS) >= day_cap) or (
        hour_cap > 0 and _requests.count_since(now, HOUR_SECONDS) >= hour_cap
    )
    _requests.add(now)
    if ip_counter is not None:
        ip_counter.add(now)
    elif ip_cap > 0:
        _by_ip[ip_key] = counter = _MinuteCounter()
        counter.add(now)
    if paused:
        logger.warning(
            "event=auth_email_new_address_paused endpoint=%s client_ip_hash=%s",
            endpoint,
            hash_ip_for_logs(client_ip),
        )
        _maybe_alert(
            kind="global_cap",
            now=now,
            summary=(
                "Contextify Cloud paused sign-up emails to new addresses: the global "
                "cap was reached."
            ),
        )
    _check_spike(now)
    return AuthEmailDecision(new_address_paused=paused)


def record_rejected_submission() -> None:
    """Count one form-shield rejection toward the spike alert (no email sent)."""
    now = time.monotonic()
    _sweep(now)
    _rejected.add(now)
    _check_spike(now)


def _check_spike(now: float) -> None:
    threshold = settings.auth_email_spike_alert_per_hour
    if threshold <= 0:
        return
    attempts = _requests.count_since(now, HOUR_SECONDS) + _rejected.count_since(
        now, HOUR_SECONDS
    )
    if attempts >= threshold:
        _maybe_alert(
            kind="spike",
            now=now,
            summary="Contextify Cloud sign-up/sign-in email requests are spiking.",
        )


def _maybe_alert(*, kind: str, now: float, summary: str) -> None:
    last = _last_alert_at.get(kind)
    if last is not None and now - last < ALERT_INTERVAL_SECONDS:
        return
    _last_alert_at[kind] = now
    requests_hour = _requests.count_since(now, HOUR_SECONDS)
    requests_day = _requests.count_since(now, DAY_SECONDS)
    rejected_hour = _rejected.count_since(now, HOUR_SECONDS)
    distinct_ips = sum(1 for c in _by_ip.values() if c.count_since(now, HOUR_SECONDS))
    logger.warning(
        "event=auth_email_alert kind=%s requests_last_hour=%d requests_last_day=%d "
        "rejected_last_hour=%d distinct_ips_last_hour=%d",
        kind,
        requests_hour,
        requests_day,
        rejected_hour,
        distinct_ips,
    )
    from contextify_cloud.monitoring import capture_auth_email_alert

    capture_auth_email_alert(
        kind=kind,
        sends_last_hour=requests_hour,
        sends_last_day=requests_day,
        distinct_ips_last_hour=distinct_ips,
    )
    text = (
        f"{summary}\n\n"
        f"Email requests counted in the last hour: {requests_hour}\n"
        f"Email requests counted in the last 24 hours (since the last restart): "
        f"{requests_day}\n"
        f"Scripted submissions rejected in the last hour (no email sent): {rejected_hour}\n"
        f"Distinct client IPs in the last hour: {distinct_ips}\n\n"
        "Caps (0 = off): "
        f"per IP {settings.auth_email_send_cap_per_ip_per_hour}/hour, "
        f"global {settings.auth_email_send_cap_global_per_hour}/hour and "
        f"{settings.auth_email_send_cap_global_per_day}/day (over the global cap, "
        "emails to new addresses pause; sign-in to existing accounts continues).\n"
        "Investigate with: grep 'auth_email_|form_shield_' in the API logs, and the "
        "nginx access log for POST /cloud/register and /api/v1/auth/login/email-link.\n"
    )
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    task = loop.create_task(_send_alert_email(subject=f"[alert] {summary}", text=text))
    _alert_tasks.add(task)
    task.add_done_callback(_alert_tasks.discard)


async def _send_alert_email(*, subject: str, text: str) -> None:
    from contextify_cloud.services.operator_notifications import _send_operator_email

    await _send_operator_email(subject=subject, text=text, important=True)
