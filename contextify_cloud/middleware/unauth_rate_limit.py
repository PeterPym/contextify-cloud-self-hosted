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
from typing import Any

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from contextify_cloud.config import settings

logger = logging.getLogger(__name__)


def _get_endpoint_limits() -> dict[tuple[str, str], int]:
    """Build per-endpoint rate limits from settings.

    Called on each request so that runtime overrides (e.g. tests patching
    settings) take effect immediately.
    """
    return {
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

# In-memory store: {(ip, method, path_pattern): [timestamp1, timestamp2, ...]}
_unauth_request_log: dict[str, list[float]] = defaultdict(list)

# Periodic pruning to prevent unbounded memory growth
_PRUNE_INTERVAL = 300  # 5 minutes
_last_prune_time: float = 0.0

WINDOW_SECONDS = 60.0  # 1-minute sliding window

# Trust forwarded client IPs only when the immediate peer is a local proxy.
# This matches the common single-host nginx -> uvicorn deployment and avoids
# trusting spoofable X-Forwarded-For headers from arbitrary direct clients.
_TRUSTED_PROXY_IPS = frozenset({"127.0.0.1", "::1"})


def _parse_forwarded_for(value: str | None) -> str | None:
    """Return the first valid IP from X-Forwarded-For, if any."""
    if not value:
        return None
    candidate = value.split(",", 1)[0].strip()
    if not candidate:
        return None
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return candidate


def _get_client_ip(request: Request) -> str:
    peer_ip = request.client.host if request.client else "unknown"
    if peer_ip in _TRUSTED_PROXY_IPS:
        return _parse_forwarded_for(request.headers.get("x-forwarded-for")) or peer_ip
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
