"""Contextify Cloud - FastAPI application entry point."""

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from contextify_cloud import app_factory
from contextify_cloud.app_factory import (
    HSTSMiddleware,
    RequestSizeLimitMiddleware,
    create_app,
)
from contextify_cloud.config import settings

logger = logging.getLogger(__name__)
validate_runtime_settings = app_factory.validate_runtime_settings


async def _purge_scheduler_loop() -> None:
    """Periodic purge sweep compatibility entry point."""
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
        # ct-1841 follow-up (unit-7 audit): scheduler exceptions never
        # traverse request middleware, so the existing Sentry hooks miss
        # them. Capture explicitly with job/phase tags so operators can
        # see scheduler outages.
        monitoring.capture_background_exception(
            exc, job="purge_scheduler", phase="startup"
        )

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
            monitoring.capture_background_exception(
                exc, job="purge_scheduler", phase="scheduled"
            )


async def _auth_email_outbox_scheduler_loop() -> None:
    """Periodic auth-token email retry sweep compatibility entry point."""
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
        # ct-1841 follow-up (unit-7 audit): see _purge_scheduler_loop.
        monitoring.capture_background_exception(
            exc, job="auth_email_outbox", phase="startup"
        )

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
            monitoring.capture_background_exception(
                exc, job="auth_email_outbox", phase="scheduled"
            )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Compatibility lifespan for tests that patch helpers through main."""
    validate_runtime_settings(getattr(app.state, "cloud_profile", None))

    purge_task = asyncio.create_task(_purge_scheduler_loop())
    auth_email_outbox_task = asyncio.create_task(_auth_email_outbox_scheduler_loop())
    try:
        yield
    finally:
        for task in (purge_task, auth_email_outbox_task):
            task.cancel()
        for task in (purge_task, auth_email_outbox_task):
            try:
                await task
            except asyncio.CancelledError:
                pass


app = create_app()

__all__ = [
    "HSTSMiddleware",
    "RequestSizeLimitMiddleware",
    "_auth_email_outbox_scheduler_loop",
    "_purge_scheduler_loop",
    "app",
    "create_app",
    "lifespan",
    "validate_runtime_settings",
]
