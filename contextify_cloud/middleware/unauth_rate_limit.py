"""IP-based rate limiting for unauthenticated endpoints.

Uses a sliding window counter per (IP, endpoint) pair. This protects
public-facing endpoints (login, register, device code, invitation accept)
from brute-force and abuse without requiring authentication context.

Each endpoint can have its own rate limit (requests per minute).
Suitable for single-instance deployments. For multi-instance production,
replace with Redis-backed rate limiting.
"""

import ipaddress
import logging
import math
import time
from collections import defaultdict
from collections.abc import Callable
from typing import Any

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from contextify_cloud.config import settings
from contextify_cloud.http_security import _is_trusted_proxy_peer

logger = logging.getLogger(__name__)


# Hosted-only endpoints register their limits here at app-construction time
# (the hosted billing router registers its anonymous-checkout endpoints, wired
# from app_factory._include_hosted_routers). Keeping the registry here lets the
# shared middleware rate-limit endpoints whose path literals live ONLY in files
# excluded from the self-hosted commercial export (ct-2340): this module IS
# included in that export, so it must carry no excluded path literal of its own.
# Keyed by (METHOD, path) so re-registration overwrites and is safe across the
# multiple app constructions tests perform.
_registered_endpoint_limits: dict[tuple[str, str], Callable[[], int]] = {}


def register_unauth_rate_limit(
    method: str, path: str, limit_getter: Callable[[], int]
) -> None:
    """Register a per-IP rate limit for an unauthenticated endpoint.

    ``limit_getter`` is called per-request inside ``_get_endpoint_limits`` so a
    runtime setting override (e.g. a test patching settings) takes effect
    immediately. Idempotent: re-registering the same (method, path) overwrites.
    """
    _registered_endpoint_limits[(method.upper(), path)] = limit_getter


def _get_endpoint_limits() -> dict[tuple[str, str], int]:
    """Build per-endpoint rate limits from settings.

    Called on each request so that runtime overrides (e.g. tests patching
    settings) take effect immediately. Static auth limits are merged with any
    limits registered by hosted-only routers (see ``register_unauth_rate_limit``).
    """
    limits: dict[tuple[str, str], int] = {
        ("POST", "/cloud/login"): settings.rate_limit_unauth_login_per_minute,
        ("POST", "/cloud/register"): settings.rate_limit_unauth_register_per_minute,
        ("POST", "/api/v1/auth/device/code"): settings.rate_limit_unauth_device_code_per_minute,
        ("POST", "/api/v1/auth/device/token"): settings.rate_limit_unauth_device_token_per_minute,
        ("POST", "/api/v1/auth/device/email-init"): (
            settings.rate_limit_unauth_email_init_per_minute
        ),
        ("POST", "/api/v1/auth/device/verify-otp"): (
            settings.rate_limit_unauth_verify_otp_per_minute
        ),
        # ct-1563 — /cloud/login magic-link flow (spec §13b).
        ("POST", "/api/v1/auth/login/email-link"): (
            settings.rate_limit_unauth_login_email_link_per_minute
        ),
        ("POST", "/api/v1/auth/login/verify-otp"): (
            settings.rate_limit_unauth_login_verify_otp_per_minute
        ),
        # Parameterized: /api/v1/invitations/{token}/accept
        ("POST", "/api/v1/invitations/*/accept"): (
            settings.rate_limit_unauth_invitation_accept_per_minute
        ),
    }
    # Merge in hosted-only registered limits (e.g. ct-2340 anonymous checkout
    # endpoints, registered by the billing router only in HOSTED mode).
    for key, limit_getter in _registered_endpoint_limits.items():
        limits[key] = limit_getter()
    return limits

# In-memory store: {(ip, method, path_pattern): [timestamp1, timestamp2, ...]}
_unauth_request_log: dict[str, list[float]] = defaultdict(list)

# Periodic pruning to prevent unbounded memory growth
_PRUNE_INTERVAL = 300  # 5 minutes
_last_prune_time: float = 0.0

WINDOW_SECONDS = 60.0  # 1-minute sliding window


def _valid_ip(value: str | None) -> str | None:
    """Return the candidate if it is a valid IP address, else None."""
    if not value:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return candidate


def _rightmost_forwarded_for(value: str | None) -> str | None:
    """Return the genuine rightmost X-Forwarded-For hop, if it is a valid IP.

    The rightmost entry is the hop the trusted proxy appended (the real
    client). The leftmost is client-supplied and spoofable, so it is never
    used here. Crucially, we take ONLY the last non-empty token and validate
    IT: we do not scan further left for the first valid token. If an attacker
    seeds a valid-looking IP to the left and the genuine rightmost hop is
    garbage, this returns None so the caller falls back to the peer IP rather
    than trusting the attacker's value.
    """
    if not value:
        return None
    # Drop trailing empty/whitespace-only tokens, then take the last remaining.
    tokens = [token.strip() for token in value.split(",")]
    non_empty = [token for token in tokens if token]
    if not non_empty:
        return None
    return _valid_ip(non_empty[-1])


def _get_client_ip(request: Request) -> str:
    """Resolve the client IP used for per-IP rate-limit bucketing.

    Trust is determined by the shared config-driven check
    (loopback always trusted plus any CIDR in settings.trusted_proxy_cidrs).
    For untrusted (direct) peers, forwarding headers are ignored so an
    attacker cannot mint fresh buckets. For trusted proxy peers, the real
    client is resolved from X-Real-IP, then the rightmost X-Forwarded-For hop,
    falling back to the peer IP. Never raises and never returns "".
    """
    peer_ip = request.client.host if request.client else "unknown"

    if not _is_trusted_proxy_peer(peer_ip):
        # Direct attacker: ignore forwarding headers entirely (spoof-safety).
        return peer_ip

    # Trusted proxy: prefer X-Real-IP, else rightmost X-Forwarded-For hop.
    real_ip = _valid_ip(request.headers.get("x-real-ip"))
    if real_ip is not None:
        return real_ip
    forwarded = _rightmost_forwarded_for(request.headers.get("x-forwarded-for"))
    if forwarded is not None:
        return forwarded
    return peer_ip


def _match_endpoint(method: str, path: str) -> tuple[str, int] | None:
    """Match a request to a rate-limited endpoint.

    Returns (pattern_key, limit) if matched, None otherwise.
    Handles parameterized paths like /api/v1/invitations/{token}/accept.
    """
    endpoint_limits = _get_endpoint_limits()

    # Try exact match first
    key = (method, path)
    if key in endpoint_limits:
        return f"{method}:{path}", endpoint_limits[key]

    # Try wildcard match for parameterized routes
    for (ep_method, ep_pattern), limit in endpoint_limits.items():
        if ep_method != method:
            continue
        if "*" not in ep_pattern:
            continue
        # Split pattern and path into segments
        pattern_parts = ep_pattern.split("/")
        path_parts = path.split("/")
        if len(pattern_parts) != len(path_parts):
            continue
        matched = True
        for pp, rp in zip(pattern_parts, path_parts):
            if pp == "*":
                continue
            if pp != rp:
                matched = False
                break
        if matched:
            return f"{ep_method}:{ep_pattern}", limit

    return None


def _prune_expired() -> None:
    """Remove expired timestamps from the rate limit log.

    Called periodically to prevent unbounded memory growth.
    """
    global _last_prune_time
    now = time.monotonic()
    if now - _last_prune_time < _PRUNE_INTERVAL:
        return
    _last_prune_time = now
    cutoff = now - WINDOW_SECONDS
    expired_keys = []
    for key, timestamps in _unauth_request_log.items():
        _unauth_request_log[key] = [t for t in timestamps if t > cutoff]
        if not _unauth_request_log[key]:
            expired_keys.append(key)
    for key in expired_keys:
        del _unauth_request_log[key]


class UnauthRateLimitMiddleware(BaseHTTPMiddleware):
    """Rate-limit unauthenticated endpoints by client IP.

    Applies per-endpoint, per-IP sliding window rate limits to protect
    public-facing endpoints from brute-force and abuse attacks.
    Non-matching endpoints pass through without rate limiting.
    """

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        match = _match_endpoint(request.method, request.url.path)
        if match is None:
            response: Response = await call_next(request)
            return response

        pattern_key, limit = match

        # Zero limit disables rate limiting for this endpoint (used in CI/E2E)
        if limit <= 0:
            response = await call_next(request)
            return response

        client_ip = _get_client_ip(request)
        store_key = f"{client_ip}:{pattern_key}"
        now = time.monotonic()

        _prune_expired()

        # Count requests in current window
        timestamps = _unauth_request_log[store_key]
        timestamps = [t for t in timestamps if t > now - WINDOW_SECONDS]
        _unauth_request_log[store_key] = timestamps

        if len(timestamps) >= limit:
            logger.warning(
                "Unauth rate limit exceeded: ip=%s endpoint=%s count=%d limit=%d",
                client_ip,
                pattern_key,
                len(timestamps),
                limit,
            )
            return Response(
                content='{"detail":"Rate limit exceeded. Try again later."}',
                status_code=429,
                media_type="application/json",
                headers={
                    "Retry-After": str(
                        max(1, math.ceil(WINDOW_SECONDS - (now - timestamps[0])))
                    )
                },
            )

        # Record this request
        timestamps.append(now)
        _unauth_request_log[store_key] = timestamps

        response = await call_next(request)
        return response


def reset_unauth_rate_limit_state() -> None:
    """Reset in-memory rate limit state. Used in tests."""
    global _last_prune_time
    _unauth_request_log.clear()
    _last_prune_time = 0.0
