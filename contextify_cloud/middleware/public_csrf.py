"""Public-CSRF helpers for unauthenticated POST forms.

These helpers implement the cookie-based CSRF token pattern used by every
unauthenticated POST in the dashboard (login, register, forgot-password,
verify-email, magic-link / OTP). The token is generated server-side, stored
in a host-only ``ctx_public_csrf`` cookie scoped to ``/`` (root), and
validated against a matching ``csrf_token`` form field or
``X-CSRF-Token`` header on submission.

Originally inlined in ``contextify_cloud.routers.dashboard``; lifted here in
ct-1562 so the new device-flow magic-link / OTP routes in
``contextify_cloud.routers.device_auth`` can apply the same defense without
re-exporting helpers across router modules.

ct-1512 Shard C — C1 fix: cookie ``Path`` was previously ``/cloud/`` because
all CSRF-protected forms historically lived under that prefix. The new
fetch-based magic-link flow (ct-1562 / ct-1563) posts JSON to
``/api/v1/auth/...`` endpoints; browsers do NOT send a ``Path=/cloud/``
cookie on those requests, so the JSON POST failed CSRF every time. The
cookie is now scoped to ``/`` so it is sent on both the rendered
``/cloud/...`` GETs (where the token is embedded into the page) and the
``/api/v1/auth/...`` JSON POSTs (where the same token is echoed back via
the ``X-CSRF-Token`` header). No conflicting ``ctx_public_csrf`` cookie
exists on a sibling subpath: a project-wide grep confirms this name is used
only by these helpers (and in the post-deploy smoke test that issues a
fresh value of its own). The previous ``Path=/cloud/`` value also still
matched ``/cloud/...`` GETs, so widening the scope strictly increases the
set of paths the browser will send the cookie to — no scope conflict.
"""

from __future__ import annotations

import hmac
import secrets
from typing import Any

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from contextify_cloud.http_security import is_secure_request

PUBLIC_CSRF_COOKIE_NAME = "ctx_public_csrf"
# ct-1512 Shard C C1: scope to root so /api/v1/auth/... fetch POSTs receive
# the same cookie that the /cloud/... GETs set. See module docstring.
_PUBLIC_CSRF_COOKIE_PATH = "/"
_PUBLIC_CSRF_MAX_AGE_SECONDS = 3600


def public_csrf_token(request: Request) -> str:
    """Return the per-request CSRF token (existing cookie or fresh value)."""
    token = request.cookies.get(PUBLIC_CSRF_COOKIE_NAME)
    if token and len(token) >= 32:
        return token
    return secrets.token_urlsafe(32)


def set_public_csrf_cookie(
    response: HTMLResponse | RedirectResponse | JSONResponse,
    request: Request,
    token: str,
) -> None:
    """Persist the public CSRF token as a host-only ``/cloud/`` cookie."""
    response.set_cookie(
        key=PUBLIC_CSRF_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=is_secure_request(request),
        samesite="lax",
        max_age=_PUBLIC_CSRF_MAX_AGE_SECONDS,
        path=_PUBLIC_CSRF_COOKIE_PATH,
    )


def clear_public_csrf_cookie(
    response: HTMLResponse | RedirectResponse | JSONResponse,
) -> None:
    response.delete_cookie(key=PUBLIC_CSRF_COOKIE_NAME, path=_PUBLIC_CSRF_COOKIE_PATH)


async def public_csrf_form_valid(request: Request) -> bool:
    """Validate a POSTed form against the public-CSRF cookie.

    Accepts the token either as a ``csrf_token`` form field (HTML forms) or
    as an ``X-CSRF-Token`` header (JSON fetch clients). Comparison is
    constant-time via ``hmac.compare_digest``.
    """
    cookie_token = request.cookies.get(PUBLIC_CSRF_COOKIE_NAME)
    if not cookie_token:
        return False
    try:
        form: Any = await request.form()
    except Exception:
        form = {}
    submitted = form.get("csrf_token") or request.headers.get("x-csrf-token")
    if not submitted:
        return False
    return hmac.compare_digest(str(submitted), cookie_token)


async def public_csrf_json_valid(request: Request) -> bool:
    """Validate a public-CSRF token for a JSON request body.

    Used by ``email-init`` / ``verify-otp`` where the State A → B →
    success transitions are driven by ``fetch()`` POSTs with JSON bodies.
    The State A page sets the public-CSRF cookie alongside the rendered
    HTML; the fetch client echoes the same value back via the
    ``X-CSRF-Token`` header. Form-encoded submissions still go through
    ``public_csrf_form_valid``.
    """
    cookie_token = request.cookies.get(PUBLIC_CSRF_COOKIE_NAME)
    if not cookie_token:
        return False
    submitted = request.headers.get("x-csrf-token")
    if not submitted:
        return False
    return hmac.compare_digest(str(submitted), cookie_token)
