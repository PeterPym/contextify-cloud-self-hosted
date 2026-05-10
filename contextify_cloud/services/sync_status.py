"""Shared sync session lifecycle and presentation helpers."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from contextify_cloud.middleware.auth import AuthContext
from contextify_cloud.models import SyncSession

RECENT_ACTIVITY_WINDOW = timedelta(minutes=10)
STALL_WINDOW = timedelta(minutes=3)


def session_is_effectively_complete(
    *,
    total_batches: int | None,
    completed_batches: int,
) -> bool:
    """Return True when a session has finished all of its known batches."""
    return total_batches is not None and total_batches > 0 and completed_batches >= total_batches


def session_is_bulk_catch_up(
    *,
    total_batches: int | None,
    completed_batches: int,
) -> bool:
    """Return True when a session still represents bounded catch-up work."""
    return (
        total_batches is not None
        and total_batches > 1
        and not session_is_effectively_complete(
            total_batches=total_batches,
            completed_batches=completed_batches,
        )
    )


async def finalize_effectively_complete_sessions(
    auth: AuthContext,
    db: AsyncSession,
    *,
    now: datetime | None = None,
) -> None:
    """Mark lingering in-progress sessions complete once their batches are done.

    Callers currently use this as compatibility cleanup for older rows that
    already satisfied completion semantics but still linger as in-progress.
    """
    effective_now = now or datetime.now(UTC)
    await db.execute(
        update(SyncSession)
        .where(
            SyncSession.tenant_id == auth.tenant_id,
            SyncSession.user_id == auth.user_id,
            SyncSession.status == "in_progress",
            SyncSession.total_batches.is_not(None),
            SyncSession.total_batches > 0,
            SyncSession.completed_batches >= SyncSession.total_batches,
        )
        .values(
            status="completed",
            completed_at=effective_now,
        )
    )
