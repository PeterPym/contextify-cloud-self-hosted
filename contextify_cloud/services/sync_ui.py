"""Sync status data for the dashboard UI.

Gathers device info, entry counts, sync session state, and progress
metrics for display on the /cloud/sync page.
"""

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from contextify_cloud.config import settings
from contextify_cloud.middleware.auth import AuthContext
from contextify_cloud.models import Device, SyncSession
from contextify_cloud.services.sync_status import (
    RECENT_ACTIVITY_WINDOW,
    STALL_WINDOW,
    finalize_effectively_complete_sessions,
    session_is_bulk_catch_up,
)
from contextify_cloud.services.tenant_schema import resolve_schema
from contextify_cloud.services.user_scoping import build_user_scope_clause

logger = logging.getLogger(__name__)


@dataclass
class DeviceStatus:
    """A device with sync health info."""

    id: str  # UUID primary key (for unlink endpoint)
    user_id: str  # Owner user ID (for role-scoped visibility)
    machine_name: str
    machine_id: str
    os: str | None
    app_version: str | None
    last_sync_at: datetime | None
    created_at: datetime
    health: str  # "healthy", "recently_active", "syncing", "stalled", "inactive", "never_synced"
    last_sync_ago: str  # Human-readable "2 hours ago", "never"


@dataclass
class ActiveSessionInfo:
    """Active push session progress."""

    sync_session_id: str
    phase: str  # "initial_upload", "stalled"
    completed_batches: int
    total_batches: int | None
    progress_percent: float | None
    eta_seconds: int | None
    eta_display: str  # Human-readable ETA
    started_at: datetime
    last_batch_at: datetime | None
    is_stalled: bool


@dataclass
class SyncOverview:
    """All sync data needed for the dashboard page."""

    entries_synced: int
    server_sequence: int
    last_sync: datetime | None
    last_sync_ago: str
    devices: list[DeviceStatus]
    active_session: ActiveSessionInfo | None
    pending_sessions: int
    is_syncing: bool
    is_recently_active: bool


def _time_ago(dt: datetime | None, now: datetime) -> str:
    """Format a datetime as a human-readable 'X ago' string."""
    if dt is None:
        return "Never"
    delta = now - dt
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return "Just now"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h ago"
    days = hours // 24
    if days < 30:
        return f"{days}d ago"
    return dt.strftime("%b %d, %Y")


def _format_eta(seconds: int | None) -> str:
    """Format ETA seconds as human-readable string."""
    if seconds is None:
        return "Unknown"
    if seconds <= 0:
        return "Almost done"
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m"
    hours = minutes // 60
    remaining_min = minutes % 60
    if remaining_min > 0:
        return f"{hours}h {remaining_min}m"
    return f"{hours}h"


def _device_health(
    device: Device,
    now: datetime,
    active_session: ActiveSessionInfo | None,
    current_user_id: str,
) -> str:
    """Determine device health status."""
    if device.last_sync_at is None:
        return "never_synced"

    age = now - device.last_sync_at
    # Only apply session state to devices owned by the session's user
    session_applies = (
        active_session is not None and str(device.user_id) == current_user_id
    )
    if (
        session_applies
        and active_session is not None
        and active_session.is_stalled
        and age < timedelta(hours=1)
    ):
        return "stalled"
    if session_applies and age < timedelta(minutes=10):
        return "syncing"
    if age < RECENT_ACTIVITY_WINDOW:
        return "recently_active"
    # Healthy: synced within the last hour
    if age < timedelta(hours=1):
        return "healthy"
    # Inactive: not synced in over an hour
    return "inactive"


async def get_sync_overview(
    auth: AuthContext, db: AsyncSession,
) -> SyncOverview:
    """Gather all sync status data for the dashboard page."""
    now = datetime.now(UTC)

    # Resolve tenant schema
    schema = await resolve_schema(auth, db)

    # -- Devices (owners/admins see all tenant devices, members see own) --
    if auth.has_full_access:
        from contextify_cloud.models import User
        tenant_user_ids = select(User.id).where(User.tenant_id == auth.tenant_id)
        devices_result = await db.execute(
            select(Device).where(Device.user_id.in_(tenant_user_ids))
        )
    else:
        devices_result = await db.execute(
            select(Device).where(Device.user_id == auth.user_id)
        )
    devices = devices_result.scalars().all()

    # -- Entry count (user-scoped) --
    entries_synced = 0
    scope_clause, scope_params = build_user_scope_clause(auth)
    try:
        count_sql = (
            f"SELECT COUNT(*) FROM {schema}.transcript_entries "
            f"WHERE 1=1 {scope_clause}"
        )
        result = await db.execute(text(count_sql), scope_params)
        entries_synced = result.scalar() or 0
    except Exception:
        pass  # Schema may not exist yet

    # -- Server sequence (global) --
    server_sequence = 0
    try:
        max_result = await db.execute(
            text(
                f"SELECT COALESCE(MAX(server_sequence), 0) "
                f"FROM {schema}.transcript_entries"
            )
        )
        server_sequence = max_result.scalar() or 0
    except Exception:
        pass

    # -- Last sync time --
    last_sync = None
    if devices:
        sync_times: list[datetime] = [d.last_sync_at for d in devices if d.last_sync_at is not None]
        if sync_times:
            last_sync = max(sync_times)

    # -- Active push sessions --
    stale_cutoff = now - timedelta(hours=settings.session_ttl_hours)
    pending_sessions = 0
    active_session: ActiveSessionInfo | None = None

    try:
        # Compatibility cleanup for older lingering sessions. This read path
        # intentionally mutates state, and get_db() commits on request teardown.
        await finalize_effectively_complete_sessions(auth, db, now=now)
        pending_result = await db.execute(
            select(func.count(SyncSession.id)).where(
                SyncSession.tenant_id == auth.tenant_id,
                SyncSession.user_id == auth.user_id,
                SyncSession.status == "in_progress",
                SyncSession.last_batch_at >= stale_cutoff,
                SyncSession.total_batches.is_not(None),
                SyncSession.total_batches > 1,
                SyncSession.completed_batches < SyncSession.total_batches,
            )
        )
        pending_sessions = pending_result.scalar() or 0

        latest_result = await db.execute(
            select(SyncSession)
            .where(
                SyncSession.tenant_id == auth.tenant_id,
                SyncSession.user_id == auth.user_id,
                SyncSession.status == "in_progress",
                SyncSession.last_batch_at >= stale_cutoff,
                SyncSession.total_batches.is_not(None),
                SyncSession.total_batches > 1,
                SyncSession.completed_batches < SyncSession.total_batches,
            )
            .order_by(
                SyncSession.last_batch_at.desc(),
                SyncSession.started_at.desc(),
            )
            .limit(1)
        )
        latest = latest_result.scalar_one_or_none()

        if latest:
            if not session_is_bulk_catch_up(
                total_batches=latest.total_batches,
                completed_batches=latest.completed_batches,
            ):
                latest = None

        if latest:
            progress_percent = None
            eta_seconds = None

            if latest.total_batches and latest.total_batches > 0:
                progress_percent = min(
                    100.0,
                    (latest.completed_batches / latest.total_batches) * 100.0,
                )

            if (
                latest.total_batches
                and latest.total_batches > 0
                and latest.started_at
                and latest.completed_batches > 0
            ):
                elapsed = max(
                    1.0, (now - latest.started_at).total_seconds()
                )
                rate = latest.completed_batches / elapsed
                if rate > 0:
                    remaining = max(
                        0, latest.total_batches - latest.completed_batches
                    )
                    eta_seconds = int(remaining / rate)

            stalled_cutoff = now - STALL_WINDOW
            is_stalled = (
                latest.last_batch_at is not None
                and latest.last_batch_at < stalled_cutoff
            )

            active_session = ActiveSessionInfo(
                sync_session_id=str(latest.id),
                phase="stalled" if is_stalled else "initial_upload",
                completed_batches=latest.completed_batches,
                total_batches=latest.total_batches,
                progress_percent=progress_percent,
                eta_seconds=eta_seconds,
                eta_display=_format_eta(eta_seconds),
                started_at=latest.started_at,
                last_batch_at=latest.last_batch_at,
                is_stalled=is_stalled,
            )
    except Exception:
        pass  # Table may not exist yet

    device_statuses = [
        DeviceStatus(
            id=str(d.id),
            user_id=str(d.user_id),
            machine_name=d.machine_name,
            machine_id=d.machine_id,
            os=d.os,
            app_version=d.app_version,
            last_sync_at=d.last_sync_at,
            created_at=d.created_at,
            health=_device_health(d, now, active_session, str(auth.user_id)),
            last_sync_ago=_time_ago(d.last_sync_at, now),
        )
        for d in devices
    ]

    return SyncOverview(
        entries_synced=entries_synced,
        server_sequence=server_sequence,
        last_sync=last_sync,
        last_sync_ago=_time_ago(last_sync, now),
        devices=device_statuses,
        active_session=active_session,
        pending_sessions=pending_sessions,
        is_syncing=active_session is not None and not active_session.is_stalled,
        is_recently_active=(
            active_session is None
            and last_sync is not None
            and (now - last_sync) < RECENT_ACTIVITY_WINDOW
        ),
    )
