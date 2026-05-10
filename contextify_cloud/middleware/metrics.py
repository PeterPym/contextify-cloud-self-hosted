"""Request metrics middleware for observability.

Tracks per-endpoint latency and per-tenant request counts using simple
in-memory dict-based counters. No external dependencies required.

Features:
  - Per-endpoint request count and latency histogram (min/max/avg/p95)
  - Per-tenant request counts
  - Slow request logging: warns for requests exceeding 1 second

Metrics are accessible via get_metrics() for inspection or future
/admin/metrics endpoint integration.
"""

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field

from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger(__name__)

# Threshold for slow request warnings (seconds)
SLOW_REQUEST_THRESHOLD = 1.0


@dataclass
class EndpointStats:
    """Aggregated stats for a single endpoint."""

    count: int = 0
    total_ms: float = 0.0
    min_ms: float = float("inf")
    max_ms: float = 0.0
    # Keep recent latencies for percentile calculation (bounded buffer)
    recent_latencies: list[float] = field(default_factory=list)
    _max_recent: int = 1000

    def record(self, latency_ms: float) -> None:
        self.count += 1
        self.total_ms += latency_ms
        self.min_ms = min(self.min_ms, latency_ms)
        self.max_ms = max(self.max_ms, latency_ms)
        self.recent_latencies.append(latency_ms)
        if len(self.recent_latencies) > self._max_recent:
            self.recent_latencies = self.recent_latencies[-self._max_recent:]

    @property
    def avg_ms(self) -> float:
        return self.total_ms / self.count if self.count > 0 else 0.0

    @property
    def p95_ms(self) -> float:
        if not self.recent_latencies:
            return 0.0
        sorted_latencies = sorted(self.recent_latencies)
        idx = int(len(sorted_latencies) * 0.95)
        return sorted_latencies[min(idx, len(sorted_latencies) - 1)]

    def to_dict(self) -> dict[str, object]:
        return {
            "count": self.count,
            "avg_ms": round(self.avg_ms, 2),
            "min_ms": round(self.min_ms, 2) if self.min_ms != float("inf") else 0.0,
            "max_ms": round(self.max_ms, 2),
            "p95_ms": round(self.p95_ms, 2),
        }


class MetricsCollector:
    """In-memory metrics collector for request stats."""

    def __init__(self) -> None:
        self.endpoint_stats: dict[str, EndpointStats] = defaultdict(EndpointStats)
        self.tenant_request_counts: dict[str, int] = defaultdict(int)
        self.status_code_counts: dict[int, int] = defaultdict(int)
        self.total_requests: int = 0

    def record_request(
        self,
        method: str,
        path: str,
        status_code: int,
        latency_ms: float,
        tenant_id: str | None = None,
    ) -> None:
        """Record metrics for a completed request."""
        self.total_requests += 1

        endpoint_key = f"{method} {path}"
        self.endpoint_stats[endpoint_key].record(latency_ms)

        self.status_code_counts[status_code] += 1

        if tenant_id:
            self.tenant_request_counts[tenant_id] += 1

    def get_metrics(self) -> dict[str, object]:
        """Return current metrics snapshot."""
        return {
            "total_requests": self.total_requests,
            "endpoints": {
                k: v.to_dict() for k, v in self.endpoint_stats.items()
            },
            "status_codes": dict(self.status_code_counts),
            "tenant_request_counts": dict(self.tenant_request_counts),
        }

    def reset(self) -> None:
        """Reset all metrics. Used in tests."""
        self.endpoint_stats.clear()
        self.tenant_request_counts.clear()
        self.status_code_counts.clear()
        self.total_requests = 0


# Global metrics collector instance
metrics_collector = MetricsCollector()


def _normalize_path(path: str) -> str:
    """Normalize URL paths to group dynamic segments.

    Replaces UUID-like segments with {id} to avoid unbounded cardinality.
    Examples:
      /api/v1/sync/push -> /api/v1/sync/push
      /api/v1/projects/550e8400-... -> /api/v1/projects/{id}
    """
    import re

    # Replace UUID segments
    path = re.sub(
        r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "/{id}",
        path,
    )
    return path


class MetricsMiddleware:
    """Collect per-request metrics and log slow requests.

    Pure ASGI middleware (no BaseHTTPMiddleware) to avoid event-loop teardown
    issues that cause "Event loop is closed" / "Task pending" Sentry errors.

    Records endpoint latency, status codes, and per-tenant request counts.
    Logs a warning for any request exceeding SLOW_REQUEST_THRESHOLD seconds.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        start = time.monotonic()
        status_code = 200

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]

                # Propagate endpoint rate-limit state to successful responses.
                # (429 responses already include these headers via HTTPException.headers.)
                rate_limit_limit = getattr(request.state, "rate_limit_limit", None)
                if rate_limit_limit is not None:
                    headers = list(message.get("headers", []))
                    headers.append(
                        (b"x-ratelimit-limit", str(rate_limit_limit).encode())
                    )
                    headers.append(
                        (
                            b"x-ratelimit-remaining",
                            str(
                                getattr(request.state, "rate_limit_remaining", 0)
                            ).encode(),
                        )
                    )
                    headers.append(
                        (
                            b"x-ratelimit-reset",
                            str(
                                getattr(request.state, "rate_limit_reset", 60)
                            ).encode(),
                        )
                    )
                    message = {**message, "headers": headers}

            await send(message)

        await self.app(scope, receive, send_wrapper)

        elapsed_s = time.monotonic() - start
        elapsed_ms = elapsed_s * 1000

        # Normalize path to avoid high-cardinality metrics
        normalized_path = _normalize_path(request.url.path)
        # Read tenant_id from request.state (set by auth dependencies).
        tenant_id = getattr(request.state, "tenant_id", None)

        metrics_collector.record_request(
            method=request.method,
            path=normalized_path,
            status_code=status_code,
            latency_ms=elapsed_ms,
            tenant_id=tenant_id,
        )

        # Slow request warning
        if elapsed_s > SLOW_REQUEST_THRESHOLD:
            logger.warning(
                "Slow request: %s %s took %.1fms (threshold: %.0fms) tenant=%s",
                request.method,
                request.url.path,
                elapsed_ms,
                SLOW_REQUEST_THRESHOLD * 1000,
                tenant_id or "anonymous",
            )


def get_metrics() -> dict[str, object]:
    """Return current metrics snapshot (for admin endpoints or health checks)."""
    return metrics_collector.get_metrics()


def reset_metrics() -> None:
    """Reset metrics state. Used in tests."""
    metrics_collector.reset()
