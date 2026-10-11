"""Cloudflare Turnstile human check for the public sign-up form.

Enabled only when ``TURNSTILE_ENABLED`` is true and both keys are set (the
settings validator refuses the flag without keys). Self-hosted installs leave
it off. The token from the widget is verified server-side against Cloudflare's
siteverify endpoint; a missing, invalid or unverifiable token is refused, so a
Cloudflare outage blocks new sign-ups rather than reopening the form to bots.
A verified token must also have been solved on the host in ``EMAIL_BASE_URL``.
"""

from __future__ import annotations

import logging
from urllib.parse import urlsplit

import httpx
from fastapi import Request

from contextify_cloud.config import settings

logger = logging.getLogger(__name__)

TURNSTILE_ORIGIN = "https://challenges.cloudflare.com"
SITEVERIFY_URL = f"{TURNSTILE_ORIGIN}/turnstile/v0/siteverify"
# The form field the widget adds to the enclosing form.
RESPONSE_FIELD = "cf-turnstile-response"
# Pages that render the widget; the CSP allows the Turnstile origin only here.
TURNSTILE_PATHS = frozenset({"/cloud/register"})
# Cloudflare documents tokens of at most 2048 characters.
_MAX_TOKEN_LENGTH = 2048


def turnstile_enabled() -> bool:
    return bool(
        settings.turnstile_enabled and settings.turnstile_site_key and settings.turnstile_secret_key
    )


def turnstile_active_for(request: Request) -> bool:
    """Whether this page renders the widget (and so needs the CSP allowance)."""
    return turnstile_enabled() and request.url.path in TURNSTILE_PATHS


async def verify_turnstile_token(token: str | None, *, remote_ip: str | None) -> bool:
    """Verify a widget token with Cloudflare. Never raises."""
    if not token or len(token) > _MAX_TOKEN_LENGTH:
        return False
    data = {"secret": settings.turnstile_secret_key, "response": token}
    if remote_ip and remote_ip != "unknown":
        data["remoteip"] = remote_ip
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(SITEVERIFY_URL, data=data)
        payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("event=turnstile_verify_unavailable error_type=%s", type(exc).__name__)
        return False
    if not isinstance(payload, dict) or payload.get("success") is not True:
        codes = payload.get("error-codes") if isinstance(payload, dict) else None
        logger.info("event=turnstile_verify_failed error_codes=%s", codes)
        return False
    # A token solved on another site that shares the widget is not ours.
    expected_host = _expected_hostname()
    if expected_host and payload.get("hostname") != expected_host:
        logger.info(
            "event=turnstile_verify_failed error_codes=hostname_mismatch hostname=%r",
            payload.get("hostname"),
        )
        return False
    return True


def _expected_hostname() -> str:
    """The public host the widget runs on, from EMAIL_BASE_URL (empty: unchecked)."""
    return urlsplit(settings.email_base_url).hostname or ""
