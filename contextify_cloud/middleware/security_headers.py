"""Security response headers middleware for dashboard responses.

Adds Content-Security-Policy, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy, and Permissions-Policy headers to all /cloud* responses.
API routes are intentionally excluded since they return JSON, not HTML.
"""

import logging
import secrets
from typing import Any

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

# Non-CSP security headers (static, same for every response)
_STATIC_SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


def _is_token_bearing_cloud_path(path: str) -> bool:
    return (
        path.startswith("/cloud/password-reset/")
        or path.startswith("/cloud/verify-email/")
        or path.startswith("/cloud/settings/email/confirm/")
        or path == "/cloud/login/handoff"
    )


def _build_csp(nonce: str) -> str:
    """Build a Content-Security-Policy with a per-request nonce.

    The nonce allows the theme bootstrap <script> in <head> to run
    without ``unsafe-inline``.  All other scripts are served as
    external files from 'self'.
    """
    return (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'"
    )


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Inject browser security headers on dashboard (/cloud*) responses.

    For every /cloud* request a fresh CSP nonce is generated, stored on
    ``request.state.csp_nonce`` so templates can embed it, and then
    included in the ``Content-Security-Policy`` response header.

    Only targets /cloud* paths so that API consumers are not affected by
    CSP or framing restrictions that are irrelevant for JSON endpoints.
    """

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        path = request.url.path
        is_cloud = (
            (path == "/cloud" or path.startswith("/cloud/"))
            and not path.startswith("/cloud/static/")
        )

        if is_cloud:
            # Generate a per-request nonce *before* the handler renders
            # templates so they can reference request.state.csp_nonce.
            nonce = secrets.token_urlsafe(16)
            request.state.csp_nonce = nonce

        response: Response = await call_next(request)

        if is_cloud:
            response.headers["Content-Security-Policy"] = _build_csp(
                request.state.csp_nonce
            )
            for name, value in _STATIC_SECURITY_HEADERS.items():
                response.headers[name] = value
            if _is_token_bearing_cloud_path(path):
                response.headers["Referrer-Policy"] = "no-referrer"
                response.headers["X-Robots-Tag"] = "noindex, nofollow"

        return response
