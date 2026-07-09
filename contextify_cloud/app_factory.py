"""FastAPI application factory and profile-aware route registration."""

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from contextify_cloud import __version__
from contextify_cloud.config import (
    DEFAULT_API_SECRET_KEY,
    DEFAULT_EMAIL_FROM,
    MIN_SUPPORT_ADMIN_TOKEN_LENGTH,
    is_dev_email_url,
    settings,
)
from contextify_cloud.http_security import is_transport_https
from contextify_cloud.middleware.logging import configure_logging
from contextify_cloud.middleware.metrics import MetricsMiddleware
from contextify_cloud.middleware.rate_limit import AuthRateLimitMiddleware
from contextify_cloud.middleware.request_id import RequestIDMiddleware
from contextify_cloud.middleware.security_headers import SecurityHeadersMiddleware
from contextify_cloud.middleware.unauth_rate_limit import UnauthRateLimitMiddleware
from contextify_cloud.monitoring import ErrorMonitoringMiddleware, init_error_monitoring
from contextify_cloud.profiles import CloudProfile, profile_from_settings

configure_logging(settings.log_level, settings.log_format)
init_error_monitoring()

logger = logging.getLogger(__name__)

HOSTED_CONTEXTIFY_HOST = "cloud.contextify.sh"


def _is_hosted_contextify_url(value: str) -> bool:
    """Return True when a configured URL points at Contextify-operated cloud."""
    lowered = value.strip().lower()
    try:
        host = urlsplit(lowered).hostname
    except ValueError:
        host = None
    if host:
        host = host.rstrip(".")
        return host == HOSTED_CONTEXTIFY_HOST or host.endswith(f".{HOSTED_CONTEXTIFY_HOST}")
    return HOSTED_CONTEXTIFY_HOST in lowered


def _is_absolute_http_url(value: str) -> bool:
    """Return True when ``value`` is an absolute http(s) URL with a host."""
    try:
        parsed = urlsplit(value.strip())
    except ValueError:
        return False
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def validate_runtime_settings(profile: CloudProfile | None = None) -> None:
    """Reject boots that would emit unsafe defaults or hosted-domain leakage."""
    resolved_profile = profile or profile_from_settings(settings)
    is_self_hosted = resolved_profile is not CloudProfile.HOSTED
    if settings.api_secret_key == DEFAULT_API_SECRET_KEY:
        raise RuntimeError(
            "API_SECRET_KEY must be set to a non-default value. "
            "Generate a unique key (e.g. `openssl rand -hex 32`) and set it "
            "via the API_SECRET_KEY environment variable. The default "
            f"{DEFAULT_API_SECRET_KEY!r} is for development only and lets "
            "anyone with the source forge session and CSRF tokens."
        )
    if not settings.email_base_url:
        raise RuntimeError(
            "EMAIL_BASE_URL must be configured. Auth emails (verification, "
            "password reset, magic-link, email change) embed this URL; an "
            "empty value would emit broken links."
        )
    if not _is_absolute_http_url(settings.email_base_url):
        raise RuntimeError(
            "EMAIL_BASE_URL must be an absolute http(s) URL with a host "
            f"(got {settings.email_base_url!r}). Values without a scheme "
            "or host produce broken links in transactional email."
        )
    if not settings.invitation_base_url:
        raise RuntimeError(
            "INVITATION_BASE_URL must be configured. Team invitations and "
            "dashboard redirects embed this URL; an empty value would emit "
            "broken links."
        )
    if not _is_absolute_http_url(settings.invitation_base_url):
        raise RuntimeError(
            "INVITATION_BASE_URL must be an absolute http(s) URL with a "
            f"host (got {settings.invitation_base_url!r}). Values without "
            "a scheme or host produce broken links in invitations and "
            "dashboard redirects."
        )
    if is_self_hosted and _is_hosted_contextify_url(settings.email_base_url):
        raise RuntimeError(
            "EMAIL_BASE_URL points at cloud.contextify.sh while "
            "SELF_HOSTED=true. Self-hosted deployments must set "
            "EMAIL_BASE_URL to their own server URL so verification, "
            "password-reset, and magic-link emails do not direct operator "
            "users onto the Contextify-operated service."
        )
    if is_self_hosted and _is_hosted_contextify_url(settings.invitation_base_url):
        raise RuntimeError(
            "INVITATION_BASE_URL points at cloud.contextify.sh while "
            "SELF_HOSTED=true. Self-hosted deployments must set "
            "INVITATION_BASE_URL to their own server URL so invitation and "
            "dashboard links resolve to the operator's server."
        )
    if not is_self_hosted and not settings.force_secure_cookies:
        raise RuntimeError(
            "FORCE_SECURE_COOKIES is False with SELF_HOSTED=false. "
            "Set FORCE_SECURE_COOKIES=true in production so session and CSRF "
            "cookies are emitted with Secure=True regardless of proxy topology."
        )
    if (
        not is_self_hosted
        and settings.dev_allow_fake_transactional_email
        and not (
            is_dev_email_url(settings.email_base_url)
            and is_dev_email_url(settings.invitation_base_url)
        )
    ):
        raise RuntimeError(
            "DEV_ALLOW_FAKE_TRANSACTIONAL_EMAIL is only allowed with localhost, "
            "loopback, or .test EMAIL_BASE_URL and INVITATION_BASE_URL values."
        )
    if (
        not is_self_hosted
        and not settings.resend_api_key
        and not settings.dev_allow_fake_transactional_email
    ):
        raise RuntimeError(
            "RESEND_API_KEY must be configured when SELF_HOSTED=false. "
            "Hosted production must use real transactional email delivery for "
            "verification, password reset, and email change workflows."
        )
    if not is_self_hosted and settings.email_from == DEFAULT_EMAIL_FROM:
        raise RuntimeError(
            f"EMAIL_FROM must be set to a verified Resend sending address when "
            f"SELF_HOSTED=false. The default value {DEFAULT_EMAIL_FROM!r} is for "
            "self-hosted/dev examples only; hosted production must override it "
            "to match the configured sending domain (e.g. noreply@auth.example.com)."
        )
    if (
        settings.support_admin_token
        and len(settings.support_admin_token) < MIN_SUPPORT_ADMIN_TOKEN_LENGTH
    ):
        raise RuntimeError("SUPPORT_ADMIN_TOKEN must be at least 32 characters when configured.")
    try:
        settings.cors_origins
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc


async def _purge_scheduler_loop() -> None:
    """Periodic purge sweep. Runs immediately on startup, then on interval."""
    from contextify_cloud import monitoring
    from contextify_cloud.services.purge import run_purge_once

    logger.info(
        "Purge scheduler started (interval=%ds, grace=%dd)",
        settings.purge_check_interval_seconds,
        settings.purge_grace_period_days,
    )

    try:
        result = await run_purge_once()
        logger.info("Startup purge sweep: purged=%d", result.purged)
    except Exception as exc:
        logger.error("Startup purge sweep failed", exc_info=True)
        # ct-1841 follow-up (unit-7 audit iter-02): live path captures here.
        # The main.py-side compat functions are kept in sync but never run
        # under the production app_factory.lifespan.
        monitoring.capture_background_exception(exc, job="purge_scheduler", phase="startup")

    while True:
        await asyncio.sleep(settings.purge_check_interval_seconds)
        try:
            result = await run_purge_once()
            if result.purged > 0 or result.errors:
                logger.info(
                    "Scheduled purge sweep: purged=%d errors=%d",
                    result.purged,
                    len(result.errors),
                )
        except Exception as exc:
            logger.error("Scheduled purge sweep failed", exc_info=True)
            monitoring.capture_background_exception(exc, job="purge_scheduler", phase="scheduled")


async def _auth_email_outbox_scheduler_loop() -> None:
    """Periodic auth-token email retry sweep."""
    from contextify_cloud import monitoring
    from contextify_cloud.services.browser_auth import run_auth_email_outbox_once

    logger.info(
        "Auth email outbox scheduler started (interval=%ds)",
        settings.auth_email_outbox_interval_seconds,
    )

    try:
        result = await run_auth_email_outbox_once()
        if result.attempted or result.errors:
            logger.info(
                "Startup auth email outbox sweep: "
                "attempted=%d sent=%d failed=%d exhausted=%d errors=%d",
                result.attempted,
                result.sent,
                result.failed,
                result.exhausted,
                len(result.errors or []),
            )
    except Exception as exc:
        logger.error("Startup auth email outbox sweep failed", exc_info=True)
        monitoring.capture_background_exception(exc, job="auth_email_outbox", phase="startup")

    while True:
        await asyncio.sleep(settings.auth_email_outbox_interval_seconds)
        try:
            result = await run_auth_email_outbox_once()
            if result.attempted or result.errors:
                logger.info(
                    "Scheduled auth email outbox sweep: "
                    "attempted=%d sent=%d failed=%d exhausted=%d errors=%d",
                    result.attempted,
                    result.sent,
                    result.failed,
                    result.exhausted,
                    len(result.errors or []),
                )
        except Exception as exc:
            logger.error("Scheduled auth email outbox sweep failed", exc_info=True)
            monitoring.capture_background_exception(exc, job="auth_email_outbox", phase="scheduled")


async def _license_delivery_outbox_scheduler_loop() -> None:
    """Periodic Local Commercial license-delivery retry sweep (ct-2015)."""
    from contextify_cloud import monitoring
    from contextify_cloud.services.license_delivery import run_license_delivery_outbox_once

    logger.info(
        "License delivery outbox scheduler started (interval=%ds)",
        settings.license_delivery_outbox_interval_seconds,
    )

    try:
        result = await run_license_delivery_outbox_once()
        if result.attempted or result.errors:
            logger.info(
                "Startup license delivery outbox sweep: "
                "attempted=%d sent=%d failed=%d exhausted=%d errors=%d",
                result.attempted,
                result.sent,
                result.failed,
                result.exhausted,
                len(result.errors or []),
            )
    except Exception as exc:
        logger.error("Startup license delivery outbox sweep failed", exc_info=True)
        monitoring.capture_background_exception(exc, job="license_delivery_outbox", phase="startup")

    while True:
        await asyncio.sleep(settings.license_delivery_outbox_interval_seconds)
        try:
            result = await run_license_delivery_outbox_once()
            if result.attempted or result.errors:
                logger.info(
                    "Scheduled license delivery outbox sweep: "
                    "attempted=%d sent=%d failed=%d exhausted=%d errors=%d",
                    result.attempted,
                    result.sent,
                    result.failed,
                    result.exhausted,
                    len(result.errors or []),
                )
        except Exception as exc:
            logger.error("Scheduled license delivery outbox sweep failed", exc_info=True)
            monitoring.capture_background_exception(
                exc, job="license_delivery_outbox", phase="scheduled"
            )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    profile = getattr(app.state, "cloud_profile", None)
    validate_runtime_settings(profile)

    purge_task = asyncio.create_task(_purge_scheduler_loop())
    auth_email_outbox_task = asyncio.create_task(_auth_email_outbox_scheduler_loop())
    license_delivery_task = asyncio.create_task(_license_delivery_outbox_scheduler_loop())
    background_tasks = (purge_task, auth_email_outbox_task, license_delivery_task)
    try:
        yield
    finally:
        for task in background_tasks:
            task.cancel()
        for task in background_tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests whose Content-Length exceeds the configured limit."""

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        client_ip = request.client.host if request.client else "unknown"
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                content_length_int = int(content_length)
            except (ValueError, OverflowError):
                logger.warning(
                    "Request rejected: invalid Content-Length header "
                    "path=%s method=%s ip=%s content_length=%r",
                    request.url.path,
                    request.method,
                    client_ip,
                    content_length,
                )
                # ct-1841 follow-up (unit-7 audit): malformed Content-Length
                # is operational/probe traffic that today never reaches
                # Sentry because 400 isn't in the global whitelist. Surface
                # it explicitly so operators can spot probe/abuse waves.
                from contextify_cloud import monitoring as _monitoring

                _monitoring.capture_handled_operational_response(
                    request=request,
                    status_code=400,
                    error_kind="invalid_content_length_header",
                )
                return Response(
                    content='{"detail":"Invalid Content-Length header."}',
                    status_code=400,
                    media_type="application/json",
                )
            if content_length_int > settings.max_request_body_bytes:
                logger.warning(
                    "Request rejected: body size %d exceeds limit %d path=%s method=%s ip=%s",
                    content_length_int,
                    settings.max_request_body_bytes,
                    request.url.path,
                    request.method,
                    client_ip,
                )
                return Response(
                    content=(
                        f'{{"detail":"Request body too large. '
                        f'Max {settings.max_request_body_bytes} bytes."}}'
                    ),
                    status_code=413,
                    media_type="application/json",
                )
        elif request.method in ("POST", "PUT", "PATCH"):
            body = bytearray()
            limit = settings.max_request_body_bytes
            async for chunk in request.stream():
                if len(body) + len(chunk) > limit:
                    logger.warning(
                        "Request rejected: streamed body exceeds limit %d "
                        "(no Content-Length) path=%s method=%s ip=%s bytes_seen=%d",
                        limit,
                        request.url.path,
                        request.method,
                        client_ip,
                        len(body) + len(chunk),
                    )
                    return Response(
                        content=(
                            f'{{"detail":"Request body too large. '
                            f'Max {settings.max_request_body_bytes} bytes."}}'
                        ),
                        status_code=413,
                        media_type="application/json",
                    )
                body.extend(chunk)
            request._body = bytes(body)
        response: Response = await call_next(request)
        return response


class HSTSMiddleware(BaseHTTPMiddleware):
    """Add Strict-Transport-Security header to HTTPS responses."""

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        response: Response = await call_next(request)
        if is_transport_https(request):
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000",
            )
        return response


def _install_exception_handlers(app: FastAPI) -> None:
    """Register handlers for Pydantic request/response validation failures.

    ct-1841 observability fix: FastAPI's default RequestValidationError
    handler short-circuits to a 422 response without raising, so 422s were
    invisible to Sentry (only 413/429/5xx were captured in
    ErrorMonitoringMiddleware). This explicit handler routes them into
    Sentry as warnings, after stripping raw user `input` from the response
    body and any Sentry payload.

    ResponseValidationError is a server bug; we capture it as a Sentry
    error (vs warning for request-side) and let FastAPI's default
    behavior (HTTP 500) stand.
    """
    from fastapi.exceptions import RequestValidationError, ResponseValidationError
    from fastapi.responses import JSONResponse

    from contextify_cloud import monitoring as _monitoring

    @app.exception_handler(RequestValidationError)
    async def _on_request_validation(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        raw_errors: list[dict[str, Any]] = [dict(e) for e in exc.errors()]
        sanitized = _monitoring.sanitize_pydantic_errors(raw_errors)
        first = sanitized[0] if sanitized else {}
        _monitoring.capture_request_validation(
            request=request,
            first_loc=".".join(str(p) for p in first.get("loc", [])),
            first_type=str(first.get("type", "")),
            error_count=len(sanitized),
        )
        return JSONResponse(status_code=422, content={"detail": sanitized})

    @app.exception_handler(ResponseValidationError)
    async def _on_response_validation(
        request: Request,
        exc: ResponseValidationError,
    ) -> JSONResponse:
        raw_errors: list[dict[str, Any]] = [dict(e) for e in exc.errors()]
        sanitized = _monitoring.sanitize_pydantic_errors(raw_errors)
        first = sanitized[0] if sanitized else {}
        _monitoring.capture_response_validation(
            request=request,
            first_loc=".".join(str(p) for p in first.get("loc", [])),
            first_type=str(first.get("type", "")),
            error_count=len(sanitized),
        )
        # Response-shape mismatches must not leak server internals to the
        # client. Return a generic 500 with a stable error code so operators
        # can correlate via Sentry's request_id tag.
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal response validation error"},
        )


def _install_middleware(app: FastAPI) -> None:
    app.add_middleware(RequestSizeLimitMiddleware)
    app.add_middleware(UnauthRateLimitMiddleware)
    app.add_middleware(AuthRateLimitMiddleware)
    app.add_middleware(MetricsMiddleware)
    app.add_middleware(ErrorMonitoringMiddleware)
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(HSTSMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)


def _install_static(app: FastAPI, profile: CloudProfile) -> None:
    if profile not in {
        CloudProfile.HOSTED,
        CloudProfile.SELF_HOSTED_PERSONAL,
        CloudProfile.SELF_HOSTED_COMMERCIAL,
    }:
        return
    static_dir = Path(__file__).resolve().parent / "static"
    app.mount("/cloud/static", StaticFiles(directory=str(static_dir)), name="static")


def _include_core_routers(app: FastAPI) -> None:
    from contextify_cloud.routers import (
        account,
        auth,
        device_auth,
        health,
        projects,
        search,
        sync,
    )

    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(device_auth.router)
    app.include_router(device_auth.cloud_device_router)
    app.include_router(account.router)
    app.include_router(sync.router)
    app.include_router(search.router)
    app.include_router(projects.router)


def _include_hosted_routers(app: FastAPI) -> None:
    from contextify_cloud.hosted import funnel_backend, ops_routes, telemetry_relay
    from contextify_cloud.routers import (
        admin,
        analytics,
        billing,
        dashboard,
        internal_growth,
        internal_support,
        invitations,
        team,
        tenant_admin,
    )

    app.include_router(ops_routes.router)
    app.include_router(billing.router)
    # ct-2340: register the anonymous-checkout per-IP rate limits via the billing
    # router itself (HOSTED only), keeping the billing path literals out of any
    # file shipped in the self-hosted commercial export.
    billing.register_billing_rate_limits()
    app.include_router(invitations.router)
    app.include_router(internal_growth.router)
    app.include_router(internal_support.router)
    app.include_router(admin.router)
    app.include_router(analytics.router)
    app.include_router(team.router)
    app.include_router(tenant_admin.router)
    app.include_router(dashboard.router)

    # ct-2080/ct-2550: register the hosted-only funnel-analytics backend.
    # HOSTED profile must fail closed if capture is not configured; otherwise
    # the activation funnel can silently look like zero activation.
    funnel_backend.install(require_configured=True)

    # ct-2614: register the hosted-only first-party telemetry relay (POST /capture/
    # served on telemetry.contextify.sh). Host-checked in-handler and per-IP rate
    # limited via register_telemetry_rate_limits(); the route path literal + key
    # live only in the hosted (mirror-excluded) module.
    app.include_router(telemetry_relay.router)
    telemetry_relay.register_telemetry_rate_limits()


def _include_commercial_self_hosted_routers(app: FastAPI) -> None:
    from contextify_cloud.routers import analytics, invitations, team, tenant_admin
    from contextify_cloud.services.commercial_license import (
        require_commercial_self_hosted_license,
    )

    license_dependency = [Depends(require_commercial_self_hosted_license)]
    app.include_router(invitations.router, dependencies=license_dependency)
    app.include_router(analytics.router, dependencies=license_dependency)
    app.include_router(team.router, dependencies=license_dependency)
    app.include_router(tenant_admin.router, dependencies=license_dependency)


def create_app(profile: CloudProfile | None = None) -> FastAPI:
    """Build the FastAPI app for the requested runtime profile.

    Passing ``profile`` is an explicit override for tests and alternate entry
    points. Settings-level contradictions are rejected only when the profile is
    derived from settings.
    """
    resolved_profile = profile or profile_from_settings(settings)
    app = FastAPI(
        title="Contextify Cloud",
        description="Cloud sync and team features for Contextify",
        version=__version__,
        docs_url="/api/docs" if settings.enable_docs else None,
        redoc_url="/api/redoc" if settings.enable_docs else None,
        openapi_url="/openapi.json" if settings.enable_docs else None,
        lifespan=lifespan,
    )
    app.state.cloud_profile = resolved_profile

    _install_middleware(app)
    _install_exception_handlers(app)
    _install_static(app, resolved_profile)
    _include_core_routers(app)

    if resolved_profile is CloudProfile.HOSTED:
        _include_hosted_routers(app)
    elif resolved_profile is CloudProfile.SELF_HOSTED_COMMERCIAL:
        _include_commercial_self_hosted_routers(app)

    @app.get("/")
    async def root() -> dict[str, str]:
        return {"name": "Contextify Cloud"}

    return app
