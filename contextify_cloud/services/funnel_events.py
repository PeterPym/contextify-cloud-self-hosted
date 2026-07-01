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
