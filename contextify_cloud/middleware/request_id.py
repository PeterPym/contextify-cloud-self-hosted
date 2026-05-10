"""Request ID middleware for request tracing.

Generates a unique UUID per request and propagates it via:
  1. contextvars (so all log calls in the request include request_id)
  2. X-Request-ID response header (so clients can correlate requests)

If the incoming request already has an X-Request-ID header (e.g., from a
reverse proxy or client), that value is used instead of generating a new one.
"""

import uuid
from typing import Any

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from contextify_cloud.middleware.logging import request_id_var, tenant_id_var, user_id_var

_REQUEST_ID_HEADER = "X-Request-ID"
_MAX_REQUEST_ID_LENGTH = 128


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Assign a unique request ID to every request.

    - Respects incoming X-Request-ID header if present.
    - Stores request_id in contextvars for log enrichment.
    - Adds X-Request-ID to response headers.
    """

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        # Use incoming header or generate a new UUID.
        # Cap length to prevent log noise / header bloat from oversized values.
        incoming_id = request.headers.get(_REQUEST_ID_HEADER)
        if incoming_id and len(incoming_id) <= _MAX_REQUEST_ID_LENGTH:
            req_id = incoming_id
        else:
            req_id = str(uuid.uuid4())

        # Store in contextvars for structured logging.
        # Also clear tenant/user context at request start to prevent stale values
        # from a previous request leaking into logs/metrics for unauthenticated paths.
        request_token = request_id_var.set(req_id)
        tenant_token = tenant_id_var.set(None)
        user_token = user_id_var.set(None)
        request.state.request_id = req_id
        try:
            response: Response = await call_next(request)
            response.headers[_REQUEST_ID_HEADER] = req_id
            return response
        finally:
            user_id_var.reset(user_token)
            tenant_id_var.reset(tenant_token)
            request_id_var.reset(request_token)
