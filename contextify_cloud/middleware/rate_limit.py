"""In-memory rate limiting for auth endpoints.

Uses a simple sliding window counter per IP address. This is suitable for
single-instance deployments. For multi-instance production, replace with
Redis-backed rate limiting.

Rate limits are configured via settings.rate_limit_auth_per_minute.
Only applied to auth endpoints (/api/v1/auth/*) to protect against
brute-force and credential-stuffing attacks.
"""

import logging
import time
from collections import defaultdict
from typing import Any

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from contextify_cloud.config import settings

logger = logging.getLogger(__name__)

# In-memory store: {ip_address: [timestamp1, timestamp2, ...]}
_auth_request_log: dict[str, list[float]] = defaultdict(list)

# How often to prune expired entries (seconds)
_PRUNE_INTERVAL = 300  # 5 minutes
_last_prune_time: float = 0.0


def _prune_expired() -> None:
    """Remove expired timestamps from the rate limit log.

    Called periodically to prevent unbounded memory growth.
    """
    global _last_prune_time
    now = time.monotonic()
    if now - _last_prune_time < _PRUNE_INTERVAL:
        return
    _last_prune_time = now
    cutoff = now - 60.0  # 1 minute window
    expired_keys = []
    for key, timestamps in _auth_request_log.items():
        _auth_request_log[key] = [t for t in timestamps if t > cutoff]
        if not _auth_request_log[key]:
            expired_keys.append(key)
    for key in expired_keys:
        del _auth_request_log[key]


class AuthRateLimitMiddleware(BaseHTTPMiddleware):
    """Rate-limit authentication endpoints to prevent brute-force attacks.

    Applies a per-IP sliding window rate limit to /api/v1/auth/* endpoints.
    Non-auth endpoints pass through without rate limiting.
    """

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        # Only rate-limit auth endpoints
        if not request.url.path.startswith("/api/v1/auth"):
            response: Response = await call_next(request)
            return response

        # Device auth endpoints have their own per-endpoint IP rate limits
        # in UnauthRateLimitMiddleware; skip them here to avoid double-counting
        if request.url.path.startswith("/api/v1/auth/device"):
            response = await call_next(request)
            return response

        # GET requests (list keys) are less sensitive; only limit POST/DELETE
        if request.method == "GET":
            response = await call_next(request)
            return response

        client_ip = request.client.host if request.client else "unknown"
        now = time.monotonic()
        window = 60.0  # 1-minute sliding window

        _prune_expired()

        # Count requests in window
        timestamps = _auth_request_log[client_ip]
        timestamps = [t for t in timestamps if t > now - window]
        _auth_request_log[client_ip] = timestamps

        limit = settings.rate_limit_auth_per_minute
        if limit > 0 and len(timestamps) >= limit:
            logger.warning(
                "Auth rate limit exceeded: ip=%s count=%d limit=%d",
                client_ip,
                len(timestamps),
                limit,
            )
            return Response(
                content='{"detail":"Rate limit exceeded. Try again later."}',
                status_code=429,
                media_type="application/json",
                headers={"Retry-After": "60"},
            )

        # Record this request
        timestamps.append(now)
        _auth_request_log[client_ip] = timestamps

        response = await call_next(request)
        return response


def reset_rate_limit_state() -> None:
    """Reset in-memory rate limit state. Used in tests."""
    _auth_request_log.clear()
