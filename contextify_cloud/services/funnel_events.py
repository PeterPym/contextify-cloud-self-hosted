"""Engagement-funnel event emit indirection (ct-2080).

This is the CORE, profile-agnostic seam that ships in EVERY build (including the
FSL source-available mirrors). It is a pure no-op unless a backend is registered
at startup, and ONLY the hosted profile registers one (see
``contextify_cloud/hosted/funnel_backend.py``, which is excluded from the
mirrors). The mirror therefore ships this no-op and none of the capture code,
endpoint, or key.

Deliberately provider-agnostic naming (no analytics-vendor or capture-module
identifiers) so this file passes the export leak-guard (ct-2086) when it ships in
the mirror. The funnel events instrument the ct-1460 activation funnel; call
sites live at the same chokepoints as the ct-2076 operator notifications.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from sqlalchemy import event as sa_event

logger = logging.getLogger(__name__)

# A backend takes (event_name, distinct_id, properties) and sends it onward.
FunnelBackend = Callable[[str, str, Mapping[str, Any]], Awaitable[None]]

_backend: FunnelBackend | None = None
# ct-2080 (CT2080-1): strong refs to in-flight detached send tasks so the event
# loop does not GC them mid-flight; discarded on completion.
_pending: set[asyncio.Task[None]] = set()


def register_funnel_backend(backend: FunnelBackend | None) -> None:
    """Install (or clear, with None) the funnel-event backend.

    Only the hosted profile calls this with a real backend. Idempotent; the last
    registration wins. Clearing with None restores the no-op behavior (used by
    tests)."""
    global _backend
    _backend = backend


def funnel_backend_registered() -> bool:
    """True when a backend is installed (hosted + key present)."""
    return _backend is not None


async def emit_funnel_event(
    event: str,
    *,
    distinct_id: str,
    properties: Mapping[str, Any] | None = None,
    is_internal: bool = False,
) -> None:
    """Emit one funnel event. No-op unless a backend is registered.

    TRULY fire-and-forget (CT2080-1): the backend send is scheduled as a detached
    task and this returns immediately, so analytics latency never couples into the
    signup / sync / billing request paths. Best-effort: a backend failure is
    swallowed so analytics can never break the caller. ``distinct_id`` must be an
    opaque id (tenant/user UUID), never PII; ``properties`` must be coarse
    metadata only (the backend additionally enforces a property allowlist).
    Internal tenants are QA/developer accounts and never emit funnel analytics."""
    if is_internal:
        return
    backend = _backend
    if backend is None:
        return
    props = dict(properties or {})

    async def _send() -> None:
        try:
            await backend(event, distinct_id, props)
        except Exception:  # noqa: BLE001 - analytics must never break the caller
            logger.exception("event=funnel_emit_failed funnel_event=%s", event)

    try:
        task = asyncio.create_task(_send())
    except RuntimeError:
        # No running loop (e.g. called outside async context) - skip rather than raise.
        return
    _pending.add(task)
    task.add_done_callback(_pending.discard)


def emit_funnel_event_after_commit(
    session: Any,
    event: str,
    *,
    distinct_id: str,
    properties: Mapping[str, Any] | None = None,
    is_internal: bool = False,
) -> None:
    """Queue a funnel emit that fires only if the CURRENT transaction commits.

    ct-3286. The route handlers here do not commit; ``get_db`` commits after the
    handler returns. So an emit written inline fires BEFORE the transaction is
    durable, and a later rollback leaves an event describing something that does
    not exist. For a credential-issued event that is a phantom activation, and it
    is the same defect the client half of ct-3273 removed from the telemetry send
    path: never record an outcome before it is known.

    Registered as a one-shot SQLAlchemy ``after_commit`` listener on the session,
    so the emit is scheduled at the moment the transaction actually commits and is
    simply never scheduled if it does not. A rollback therefore costs nothing and
    says nothing.

    The scheduled task is tracked in the same ``_pending`` set that
    ``emit_funnel_event`` uses. That is not bookkeeping tidiness: the test helper
    drains ``_pending`` to make fire-and-forget assertable, so a task outside it
    would make every funnel test racy.
    """
    if is_internal:
        return
    props = dict(properties or {})
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # No running loop (sync context): nothing can be scheduled later either.
        return

    sync_session = getattr(session, "sync_session", session)

    def _on_commit(_session: Any) -> None:
        task = loop.create_task(
            emit_funnel_event(
                event,
                distinct_id=distinct_id,
                properties=props,
                is_internal=is_internal,
            )
        )
        _pending.add(task)
        task.add_done_callback(_pending.discard)

    try:
        sa_event.listen(sync_session, "after_commit", _on_commit, once=True)
    except Exception:  # noqa: BLE001 - analytics must never break the caller
        # A session that is not a real SQLAlchemy Session (test doubles, and any
        # future caller passing something else) simply gets no event. Emitting
        # nothing is the correct failure: this helper exists to avoid recording an
        # outcome that did not happen, so failing closed is consistent.
        logger.exception("event=funnel_after_commit_registration_failed funnel_event=%s", event)


async def drain_pending(timeout: float) -> int:
    """Await in-flight funnel sends at shutdown. Returns how many did NOT finish.

    ct-3303. ``_pending`` exists so the loop cannot collect a detached send
    mid-flight, but nothing consulted it when the loop was torn down, so every
    in-flight event was dropped on shutdown. Cloud ``main`` auto-deploys on every
    merge, and the funnel volumes are tiny -- single-digit counts per year for
    some events -- so a handful lost per deploy is a meaningful fraction of the
    dataset, and the loss leaves no trace.

    BOUNDED on purpose. A drain that can block forever is worse than one that
    drops: it converts a silent analytics loss into a stalled deploy. On expiry
    this logs how many events it gave up on and returns, which is the real
    improvement even in the bad case -- the loss stops being invisible.

    Never raises. This runs on the shutdown path, where the module's standing
    contract that analytics must never break the caller matters most: failing to
    record an event must not also fail the deployment.
    """
    pending = {task for task in _pending if not task.done()}
    if not pending:
        return 0
    try:
        _done, still_pending = await asyncio.wait(pending, timeout=timeout)
    except Exception:  # noqa: BLE001 - a drain must never break shutdown
        logger.exception("event=funnel_drain_failed pending=%d", len(pending))
        return len(pending)
    if still_pending:
        # The count is the point: an operator can see that a deploy ate events.
        logger.warning(
            "event=funnel_drain_incomplete dropped=%d timeout=%s",
            len(still_pending),
            timeout,
        )
    return len(still_pending)
