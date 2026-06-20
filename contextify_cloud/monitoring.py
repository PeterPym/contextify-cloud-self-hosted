"""Sentry-compatible production error monitoring helpers.

Includes a before_send hook that strips API key secrets from all Sentry
events (messages, extra data, breadcrumbs, exception values) to prevent
credential leakage. See docs/engineering/redaction-policy.md.
"""

from __future__ import annotations

import contextlib
import copy
import logging
import re
import time
from collections import defaultdict, deque
from collections.abc import Iterator
from typing import Any, Literal

from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from contextify_cloud import __version__
from contextify_cloud.config import settings
from contextify_cloud.middleware.logging import redact_api_key_secrets

logger = logging.getLogger(__name__)

try:
    import sentry_sdk

    _SENTRY_SDK_AVAILABLE = True
except ModuleNotFoundError:
    _SENTRY_SDK_AVAILABLE = False

    class _NoopScope:
        fingerprint: list[str] | None = None

        def set_context(self, _: str, __: Any) -> None:
            return None

        def set_tag(self, _: str, __: str) -> None:
            return None

    class _NoopSentrySDK:
        def init(self, **_: Any) -> None:
            return None

        def capture_exception(self, _: Exception) -> None:
            return None

        def capture_message(self, _: str, level: str = "error") -> None:
            return None

        @contextlib.contextmanager
        def push_scope(self) -> Iterator[_NoopScope]:
            yield _NoopScope()

        @contextlib.contextmanager
        def new_scope(self) -> Iterator[_NoopScope]:
            yield _NoopScope()

    sentry_sdk = _NoopSentrySDK()  # type: ignore[assignment]

_REDACTED = "[Filtered]"
_WINDOW_SECONDS = 60.0
_SENSITIVE_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "csrf",
    "password",
    "secret",
    "session",
    "set-cookie",
    "token",
    "x-api-key",
}
_SAFE_REQUEST_HEADERS = {
    "accept",
    "content-length",
    "content-type",
    "hx-request",
    "origin",
    "user-agent",
    "x-requested-with",
}
_monitoring_initialized = False
_TOKEN_PATH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(/cloud/password-reset/)[^/?#]+"),
    re.compile(r"(/cloud/verify-email/)[^/?#]+"),
    re.compile(r"(/cloud/settings/email/confirm/)[^/?#]+"),
    re.compile(r"(/api/v1/invitations/)[^/?#]+(/accept)"),
)


class EventRateLimiter:
    """Simple in-memory limiter to avoid bursty duplicate events."""

    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, fingerprint: str, max_events: int, now: float | None = None) -> bool:
        if max_events <= 0:
            return True

        current = time.monotonic() if now is None else now
        window = self._events[fingerprint]
        cutoff = current - _WINDOW_SECONDS

        while window and window[0] < cutoff:
            window.popleft()

        if len(window) >= max_events:
            return False

        window.append(current)
        return True

    def reset(self) -> None:
        self._events.clear()


_rate_limiter = EventRateLimiter()


def is_error_monitoring_active() -> bool:
    """Return whether error monitoring is fully configured and initialized."""
    return (
        _monitoring_initialized
        and settings.error_monitoring_enabled
        and bool(settings.sentry_dsn)
    )


def reset_error_monitoring_state() -> None:
    """Reset test-only monitoring state."""
    global _monitoring_initialized
    _monitoring_initialized = False
    _rate_limiter.reset()


def init_error_monitoring() -> bool:
    """Initialize Sentry/GlitchTip-compatible monitoring if configured."""
    global _monitoring_initialized

    if not settings.error_monitoring_enabled:
        logger.info("Error monitoring disabled via ERROR_MONITORING_ENABLED=false")
        return False

    if not settings.sentry_dsn:
        logger.warning(
            "Error monitoring enabled but SENTRY_DSN is missing; monitoring is disabled"
        )
        return False

    if not _SENTRY_SDK_AVAILABLE:
        logger.warning(
            "Error monitoring enabled but sentry-sdk is not installed; monitoring is disabled"
        )
        return False

    options: dict[str, Any] = {
        "dsn": settings.sentry_dsn,
        "before_send": scrub_event,
        "debug": settings.sentry_debug,
        "environment": settings.sentry_environment,
        # Conversation-content boundary (ct-1660):
        #   - max_request_body_size="never" prevents request bodies from
        #     reaching Sentry.
        #   - include_local_variables=False prevents Python stack-frame
        #     locals (e.g. transcript_text, entry_content in scope at the
        #     time of an exception) from being serialised to Sentry.
        # Both options harden the Privacy §7 claim that conversation
        # content is not sent to Sentry. Cloud code must NOT interpolate
        # transcript / prompt / response content into logger calls or
        # exception strings; see build/docs/operations/error-monitoring.md.
        "max_request_body_size": "never",
        "include_local_variables": False,
        "release": settings.sentry_release or f"contextify-cloud@{__version__}",
        "sample_rate": settings.sentry_error_sample_rate,
        "send_default_pii": settings.error_monitoring_send_default_pii,
    }

    if settings.sentry_traces_sample_rate is not None:
        options["traces_sample_rate"] = settings.sentry_traces_sample_rate

    if settings.sentry_profiles_sample_rate is not None:
        options["profiles_sample_rate"] = settings.sentry_profiles_sample_rate

    sentry_sdk.init(**options)
    _monitoring_initialized = True
    logger.info(
        "Error monitoring initialized for environment=%s release=%s",
        settings.sentry_environment,
        options["release"],
    )
    return True


def build_monitoring_context(
    request: Request,
    status_code: int,
    event_kind: str,
) -> dict[str, Any]:
    """Build tags and request context for an error monitoring event."""
    route = request.scope.get("route")
    route_path = redact_token_path_segments(getattr(route, "path", request.url.path))
    request_path = redact_token_path_segments(request.url.path)
    request_id = getattr(request.state, "request_id", None)
    tenant_id = getattr(request.state, "tenant_id", None)
    user_id = getattr(request.state, "user_id", None)
    key_id = getattr(request.state, "key_id", None)

    tags: dict[str, str] = {
        "event_kind": event_kind,
        "http.method": request.method,
        "http.route": route_path,
        "http.status_code": str(status_code),
    }
    if request_id:
        tags["request_id"] = request_id
    if tenant_id:
        tags["tenant_id"] = str(tenant_id)
    if user_id:
        tags["user_id"] = str(user_id)
    if key_id:
        tags["key_id"] = str(key_id)

    request_context: dict[str, Any] = {
        "headers": _scrub_mapping(
            {
                key: value
                for key, value in dict(request.headers).items()
                if key.lower() in _SAFE_REQUEST_HEADERS
            }
        ),
        "method": request.method,
        "path": request_path,
        "query_params": _scrub_mapping(dict(request.query_params)),
        "request_id": request_id,
        "route": route_path,
        "status_code": status_code,
    }

    return {
        "fingerprint": [event_kind, request.method, route_path, str(status_code)],
        "request": request_context,
        "tags": tags,
    }


def capture_exception_event(
    exc: Exception,
    request: Request,
    status_code: int = 500,
) -> None:
    """Capture an unhandled exception with request metadata."""
    if not is_error_monitoring_active():
        return

    context = build_monitoring_context(
        request=request,
        status_code=status_code,
        event_kind="unhandled_exception",
    )
    _capture_with_scope(
        context=context,
        capture=lambda: sentry_sdk.capture_exception(exc),
    )


def capture_server_error_response(
    request: Request,
    status_code: int,
) -> None:
    """Capture a handled 5xx response so alert rules can count production failures."""
    if not is_error_monitoring_active():
        return

    context = build_monitoring_context(
        request=request,
        status_code=status_code,
        event_kind="handled_5xx_response",
    )
    message = (
        f"Handled 5xx response for {request.method} "
        f"{context['request']['route']} ({status_code})"
    )
    _capture_with_scope(
        context=context,
        capture=lambda: sentry_sdk.capture_message(message, level="error"),
    )


def capture_client_rejection_response(
    request: Request,
    status_code: int,
) -> None:
    """Capture a handled 4xx middleware rejection (413, 429) as a warning.

    These are returned by ASGI middleware (RequestSizeLimit, rate_limit,
    unauth_rate_limit) before any handler runs, so they never raise an
    exception for the Sentry integration's default hooks to capture.
    This function makes them visible to Sentry as warning-level events
    so operators can detect spikes of rejected traffic.

    For 413s specifically, Content-Length is attached as the
    `http.content_length` tag so operators can filter / aggregate by
    request size (input to ct-1284 client-side payload-cap design).

    The existing fingerprint-based rate limiter in `scrub_event` caps
    the rate of events per (method, route, status) so bursts do not
    overwhelm Sentry.
    """
    if not is_error_monitoring_active():
        return

    context = build_monitoring_context(
        request=request,
        status_code=status_code,
        event_kind="handled_4xx_middleware_rejection",
    )

    # Enrich with Content-Length for diagnostics (especially 413s where
    # the body was rejected pre-parse and is otherwise invisible).
    content_length = request.headers.get("content-length")
    if content_length:
        context["tags"]["http.content_length"] = content_length

    message = (
        f"Handled {status_code} response for {request.method} "
        f"{context['request']['route']}"
    )
    _capture_with_scope(
        context=context,
        capture=lambda: sentry_sdk.capture_message(message, level="warning"),
    )


def redact_api_key_patterns(event: dict[str, Any]) -> dict[str, Any]:
    """Strip API key secrets from all string values in a Sentry event.

    Recursively walks the entire event structure and replaces full API keys
    (ctx_{key_id}_{secret}) with ctx_{key_id}_[REDACTED]. Preserves the
    key_id for correlation.

    This is applied inside scrub_event() before the event is sent.
    """
    redacted = _redact_string_values(event)
    return redacted if isinstance(redacted, dict) else event


def _redact_string_values(value: Any) -> Any:
    """Recursively redact API key patterns in any nested string value."""
    if isinstance(value, str):
        return redact_token_path_segments(redact_api_key_secrets(value))
    if isinstance(value, dict):
        return {key: _redact_string_values(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_string_values(item) for item in value]
    return value


def redact_token_path_segments(value: str) -> str:
    """Redact raw auth-token path segments from request paths and event text."""
    redacted = value
    for pattern in _TOKEN_PATH_PATTERNS[:3]:
        redacted = pattern.sub(r"\1[Filtered]", redacted)
    redacted = _TOKEN_PATH_PATTERNS[3].sub(r"\1[Filtered]\2", redacted)
    return redacted


def scrub_event(event: dict[str, Any], _: dict[str, Any]) -> dict[str, Any] | None:
    """Redact secrets and drop excessive duplicate bursts before sending."""
    sanitized = copy.deepcopy(event)

    # Key-based scrubbing (authorization headers, sensitive field names)
    request_data = sanitized.get("request")
    if isinstance(request_data, dict):
        sanitized["request"] = _scrub_mapping(request_data)

    extra = sanitized.get("extra")
    if isinstance(extra, dict):
        sanitized["extra"] = _scrub_mapping(extra)

    contexts = sanitized.get("contexts")
    if isinstance(contexts, dict):
        sanitized["contexts"] = _scrub_mapping(contexts)

    user = sanitized.get("user")
    if isinstance(user, dict):
        sanitized["user"] = _scrub_mapping(user)

    # Pattern-based scrubbing: strip API key secrets from string values
    sanitized = redact_api_key_patterns(sanitized)

    fingerprint = _event_fingerprint(sanitized)
    if not _rate_limiter.allow(
        fingerprint=fingerprint,
        max_events=settings.error_monitoring_max_events_per_minute,
    ):
        logger.warning("Dropping rate-limited error monitoring event: %s", fingerprint)
        return None

    return sanitized


def capture_request_validation(
    request: Request,
    first_loc: str,
    first_type: str,
    error_count: int,
) -> None:
    """Capture a FastAPI Pydantic request-validation failure (HTTP 422).

    ct-1841: 422s used to be invisible to us in production because FastAPI's
    default RequestValidationError handler returns the response directly
    without raising, and 422 is not in `_CAPTURED_CLIENT_REJECTION_CODES`.
    A dedicated capture handler routes these into Sentry as warning-level
    events tagged with the first failing field loc and Pydantic error type.

    Privacy: the caller MUST sanitize the Pydantic error list with
    `_sanitize_pydantic_errors` before invoking this so raw user content
    from `input` is never shipped to Sentry.
    """
    if not is_error_monitoring_active():
        return

    context = build_monitoring_context(
        request=request,
        status_code=422,
        event_kind="request_validation",
    )
    context["tags"]["error_kind"] = "request_validation"
    if first_loc:
        context["tags"]["first_field_loc"] = first_loc
    if first_type:
        context["tags"]["first_field_type"] = first_type
    context["tags"]["error_count"] = str(error_count)
    message = (
        f"RequestValidationError on {request.method} "
        f"{context['request']['route']} ({error_count} field(s))"
    )
    _capture_with_scope(
        context=context,
        capture=lambda: sentry_sdk.capture_message(message, level="warning"),
    )


def capture_sync_item_validation(
    request: Request,
    item_kind: str,
    item_id: str | None,
    loc: str,
    pydantic_type: str,
    error_code: str,
) -> None:
    """Capture a per-entry validation failure surfaced through SyncItemError.

    ct-1841: per-entry failures never propagate as exceptions because the
    handler collects them into item_errors[] and returns 200. Sentry would
    miss them entirely without this explicit capture. ENTRY_UNKNOWN_VALIDATION
    is the most operationally interesting code; we ship `pydantic_type` as a
    tag so we can promote new mappings into the classifier.
    """
    if not is_error_monitoring_active():
        return

    context = build_monitoring_context(
        request=request,
        status_code=200,
        event_kind="sync_item_validation",
    )
    context["tags"]["error_kind"] = "sync_item_validation"
    context["tags"]["error_code"] = error_code
    context["tags"]["item_kind"] = item_kind
    if pydantic_type:
        context["tags"]["pydantic_type"] = pydantic_type
    if loc:
        context["tags"]["first_field_loc"] = loc
    if item_id:
        context["tags"]["item_id"] = item_id
    message = (
        f"sync_item_validation: {error_code} ({pydantic_type}) at {loc}"
    )
    # Only ENTRY_UNKNOWN_VALIDATION reaches warning level; expected codes
    # (ENTRY_TOO_LARGE, ENTRY_MISSING_FIELD, ENTRY_INVALID_FIELD, etc.) emit
    # info-level events so triage alerts focus on the truly novel failures.
    if error_code == "ENTRY_UNKNOWN_VALIDATION":
        _capture_with_scope(
            context=context,
            capture=lambda: sentry_sdk.capture_message(message, level="warning"),
        )
    else:
        _capture_with_scope(
            context=context,
            capture=lambda: sentry_sdk.capture_message(message, level="info"),
        )


def capture_response_validation(
    request: Request,
    first_loc: str,
    first_type: str,
    error_count: int,
) -> None:
    """Capture a FastAPI Pydantic response-validation failure.

    A response-shape mismatch is a server bug, not a client one, so we send
    it as a Sentry **error** (vs warning for request-side validation).
    """
    if not is_error_monitoring_active():
        return

    context = build_monitoring_context(
        request=request,
        status_code=500,
        event_kind="response_validation",
    )
    context["tags"]["error_kind"] = "response_validation"
    if first_loc:
        context["tags"]["first_field_loc"] = first_loc
    if first_type:
        context["tags"]["first_field_type"] = first_type
    context["tags"]["error_count"] = str(error_count)
    message = (
        f"ResponseValidationError on {request.method} "
        f"{context['request']['route']} ({error_count} field(s))"
    )
    _capture_with_scope(
        context=context,
        capture=lambda: sentry_sdk.capture_message(message, level="error"),
    )


SentryMessageLevel = Literal["fatal", "critical", "error", "warning", "info", "debug"]


def capture_handled_operational_response(
    request: Request,
    status_code: int,
    error_kind: str,
    extra_tags: dict[str, str] | None = None,
    *,
    level: SentryMessageLevel = "warning",
) -> None:
    """Capture a known-operational handled response that the global 4xx
    whitelist would normally miss.

    Use this for specific, named situations we want visible in Sentry but
    that don't belong in `_CAPTURED_CLIENT_REJECTION_CODES` (which would
    drown Sentry in expected client noise). Examples: invalid
    Content-Length headers (operational/probe traffic at 400), sync
    invariant guards (handler-side 422 like entries_sent mismatch),
    server-state idempotency conflicts (409 for storms / replay attacks),
    operational 410 indicating unexpected stored-state loss.

    Do NOT use this for ordinary user mistakes, expired-link 410s, auth
    denials, or routine 404s. The rule of thumb: Sentry should get server
    bugs, operational invariants, replay storms, and abuse/probe anomalies.

    ct-1841 follow-up (unit-7 audit).
    """
    if not is_error_monitoring_active():
        return

    context = build_monitoring_context(
        request=request,
        status_code=status_code,
        event_kind="handled_operational_response",
    )
    context["tags"]["error_kind"] = error_kind
    for key, value in (extra_tags or {}).items():
        context["tags"][key] = value
    message = (
        f"Handled operational {status_code} for {request.method} "
        f"{context['request']['route']}: {error_kind}"
    )
    # ct-1841 unit-7 iter-02 W2: level is configurable so future adopters
    # (info-level 410s, error-level operational invariants) can route to
    # the right severity without forking the helper.
    if level == "fatal":
        _capture_with_scope(
            context=context,
            capture=lambda: sentry_sdk.capture_message(message, level="fatal"),
        )
    elif level == "critical":
        _capture_with_scope(
            context=context,
            capture=lambda: sentry_sdk.capture_message(message, level="critical"),
        )
    elif level == "error":
        _capture_with_scope(
            context=context,
            capture=lambda: sentry_sdk.capture_message(message, level="error"),
        )
    elif level == "info":
        _capture_with_scope(
            context=context,
            capture=lambda: sentry_sdk.capture_message(message, level="info"),
        )
    elif level == "debug":
        _capture_with_scope(
            context=context,
            capture=lambda: sentry_sdk.capture_message(message, level="debug"),
        )
    else:
        _capture_with_scope(
            context=context,
            capture=lambda: sentry_sdk.capture_message(message, level="warning"),
        )


def capture_background_exception(
    exc: Exception,
    *,
    job: str,
    phase: str,
) -> None:
    """Capture an unhandled exception from a background scheduler task.

    Scheduler loops in main.py (`_purge_scheduler_loop`,
    `_auth_email_outbox_scheduler_loop`) catch broad `Exception` and only
    `logger.error(..., exc_info=True)`. Those failures never traverse the
    request middleware so the existing Sentry hook never sees them. This
    helper is the missing capture path: a Sentry error tagged with the
    job + phase identifiers so operators can correlate scheduler outages
    across deploys.

    ct-1841 follow-up (unit-7 audit).
    """
    if not is_error_monitoring_active():
        return

    fingerprint = ["background_task_exception", job, phase]
    request_context: dict[str, Any] = {
        "job": job,
        "phase": phase,
    }
    tags: dict[str, str] = {
        "event_kind": "background_task_exception",
        "job": job,
        "phase": phase,
    }
    context = {
        "fingerprint": fingerprint,
        "request": request_context,
        "tags": tags,
    }
    _capture_with_scope(
        context=context,
        capture=lambda: sentry_sdk.capture_exception(exc),
    )


def sanitize_pydantic_errors(errors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Strip the `input` field from Pydantic error dicts before exposing them.

    Pydantic embeds the offending raw value in `input`, which for sync entries
    can be transcript content. Returning it in 422 bodies or shipping it to
    Sentry would leak user content. Keep `type`, `loc`, `msg`, `ctx`; drop
    `input`. Mirror of `routers.sync._sanitize_pydantic_errors` for callers
    that don't already import the sync module.
    """
    return [{k: v for k, v in err.items() if k != "input"} for err in errors]


# Middleware-generated 4xx codes we want visible in Sentry as warnings.
# These are rejected before any handler runs, so they never raise an exception
# for Sentry's default hooks. See capture_client_rejection_response.
# - 413: RequestSizeLimitMiddleware (oversized body)
# - 429: rate_limit / unauth_rate_limit / endpoint_rate_limit
_CAPTURED_CLIENT_REJECTION_CODES: frozenset[int] = frozenset({413, 429})


class ErrorMonitoringMiddleware:
    """Capture unhandled exceptions, 5xx responses, and middleware-level 4xx rejections.

    Pure ASGI middleware (no BaseHTTPMiddleware) to avoid event-loop teardown
    issues that cause "Event loop is closed" / "Task pending" Sentry errors.

    Captured status codes:
    - 500+: via capture_server_error_response (error level)
    - 413, 429: via capture_client_rejection_response (warning level)
    - Uncaught exceptions: via capture_exception_event (error level)
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        status_code = 200

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        request = Request(scope)
        try:
            await self.app(scope, receive, send_wrapper)
        except Exception as exc:
            capture_exception_event(exc, request=request, status_code=500)
            raise

        if status_code >= 500:
            capture_server_error_response(request=request, status_code=status_code)
        elif status_code in _CAPTURED_CLIENT_REJECTION_CODES:
            capture_client_rejection_response(request=request, status_code=status_code)


def _capture_with_scope(
    context: dict[str, Any],
    capture: Any,
) -> None:
    with sentry_sdk.new_scope() as scope:
        for key, value in context["tags"].items():
            scope.set_tag(key, value)

        scope.set_context("request", context["request"])
        scope.fingerprint = context["fingerprint"]
        capture()


def _scrub_mapping(payload: dict[str, Any]) -> dict[str, Any]:
    scrubbed: dict[str, Any] = {}
    for key, value in payload.items():
        scrubbed[key] = _scrub_value(key, value)
    return scrubbed


def _scrub_value(key: str | None, value: Any) -> Any:
    normalized_key = (key or "").lower()
    if _is_sensitive_key(normalized_key):
        return _REDACTED

    if isinstance(value, dict):
        return _scrub_mapping(value)

    if isinstance(value, list):
        return [_scrub_value(None, item) for item in value]

    return value


def _is_sensitive_key(key: str) -> bool:
    return any(token in key for token in _SENSITIVE_KEYS)


def _event_fingerprint(event: dict[str, Any]) -> str:
    fingerprint = event.get("fingerprint")
    if isinstance(fingerprint, list) and fingerprint:
        return "|".join(str(part) for part in fingerprint)

    exception = event.get("exception")
    if isinstance(exception, dict):
        values = exception.get("values")
        if isinstance(values, list) and values:
            first = values[0]
            if isinstance(first, dict):
                exc_type = first.get("type", "Exception")
                return f"exception|{exc_type}"

    message = event.get("message")
    if isinstance(message, str) and message:
        return f"message|{message}"

    return "event|unknown"
