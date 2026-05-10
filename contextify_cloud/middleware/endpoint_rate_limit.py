"""Per-tenant and per-user rate limiting for sync and search endpoints.

Uses sliding window counters keyed by tenant_id (sync) or user key_id (search).
Implemented as FastAPI dependencies (not middleware) because they need the
resolved AuthContext which is only available after API key validation.

Rate limits are configured via:
  - settings.rate_limit_sync_per_minute (per tenant)
  - settings.rate_limit_search_per_minute (per user/key)

Returns 429 with Retry-After and standard rate limit headers when exceeded:
  - X-RateLimit-Limit: max requests per window
  - X-RateLimit-Remaining: requests remaining
  - X-RateLimit-Reset: seconds until window resets
"""

import logging
import math
import time
from collections import defaultdict
from typing import Annotated

from fastapi import Depends, HTTPException, Request

from contextify_cloud.config import settings
from contextify_cloud.middleware.auth import AuthContext, require_scope

logger = logging.getLogger(__name__)

# In-memory stores: {key: [timestamp1, timestamp2, ...]}
_sync_request_log: dict[str, list[float]] = defaultdict(list)
_search_request_log: dict[str, list[float]] = defaultdict(list)

# Periodic pruning
_PRUNE_INTERVAL = 300  # 5 minutes
_last_prune_time: float = 0.0

WINDOW_SECONDS = 60.0  # 1-minute sliding window


def _prune_expired() -> None:
    """Remove expired timestamps from rate limit logs.

    Called periodically to prevent unbounded memory growth.
    """
    global _last_prune_time
    now = time.monotonic()
    if now - _last_prune_time < _PRUNE_INTERVAL:
        return
    _last_prune_time = now
    cutoff = now - WINDOW_SECONDS

    for store in (_sync_request_log, _search_request_log):
        expired_keys = []
        for key, timestamps in store.items():
            store[key] = [t for t in timestamps if t > cutoff]
            if not store[key]:
                expired_keys.append(key)
        for key in expired_keys:
            del store[key]


def _check_rate_limit(
    store: dict[str, list[float]],
    key: str,
    limit: int,
    endpoint_name: str,
) -> tuple[int, int, int]:
    """Check and record a request against the rate limit.

    Returns (remaining, limit, reset_seconds).
    Raises HTTPException(429) if limit exceeded.
    A limit of 0 disables rate limiting (used in CI/E2E).
    """
    if limit <= 0:
        return (0, 0, 0)

    now = time.monotonic()
    _prune_expired()

    # Filter to current window
    timestamps = store[key]
    timestamps = [t for t in timestamps if t > now - WINDOW_SECONDS]
    store[key] = timestamps

    remaining = max(0, limit - len(timestamps))
    # Reset time: seconds until the oldest request in window expires
    if timestamps:
        oldest_in_window = min(timestamps)
        reset_seconds = max(1, math.ceil((oldest_in_window + WINDOW_SECONDS) - now))
    else:
        reset_seconds = int(WINDOW_SECONDS)

    if len(timestamps) >= limit:
        logger.warning(
            "%s rate limit exceeded: key=%s count=%d limit=%d",
            endpoint_name,
            key,
            len(timestamps),
            limit,
        )
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded for {endpoint_name}. Try again later.",
            headers={
                "Retry-After": str(reset_seconds),
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(reset_seconds),
            },
        )

    # Record this request
    timestamps.append(now)
    store[key] = timestamps

    # Recalculate remaining after recording
    remaining = max(0, limit - len(timestamps))

    return remaining, limit, reset_seconds


async def require_sync_rate_limit(
    request: Request,
    auth: Annotated[AuthContext, Depends(require_scope("sync"))],
) -> AuthContext:
    """FastAPI dependency that enforces per-tenant rate limiting on sync endpoints.

    Key: tenant_id (all users in a tenant share the sync rate limit).
    """
    key = str(auth.tenant_id)
    remaining, limit, reset_seconds = _check_rate_limit(
        _sync_request_log,
        key,
        settings.rate_limit_sync_per_minute,
        "sync",
    )

    # Store rate limit info on request state for response headers
    request.state.rate_limit_remaining = remaining
    request.state.rate_limit_limit = limit
    request.state.rate_limit_reset = reset_seconds

    return auth


async def require_search_rate_limit(
    request: Request,
    auth: Annotated[AuthContext, Depends(require_scope("search"))],
) -> AuthContext:
    """FastAPI dependency that enforces per-user rate limiting on search endpoints.

    Key: key_id (per API key, so each user/key has an independent limit).
    """
    key = auth.key_id
    remaining, limit, reset_seconds = _check_rate_limit(
        _search_request_log,
        key,
        settings.rate_limit_search_per_minute,
        "search",
    )

    # Store rate limit info on request state for response headers
    request.state.rate_limit_remaining = remaining
    request.state.rate_limit_limit = limit
    request.state.rate_limit_reset = reset_seconds

    return auth


def reset_endpoint_rate_limit_state() -> None:
    """Reset in-memory rate limit state. Used in tests."""
    global _last_prune_time
    _sync_request_log.clear()
    _search_request_log.clear()
    _last_prune_time = 0.0
