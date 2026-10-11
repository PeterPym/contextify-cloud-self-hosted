"""Reject scripted submissions of the public forms that send email.

The 2026-10-04 signup bot fetched /cloud/register and POSTed in the same
second, never ran our JavaScript, and never loaded CSS. Four cheap checks,
all verified server-side and none keyed on User-Agent:

1. A signed form-render token. The page embeds an HMAC of the form name, the
   render time and the page's public-CSRF token; a submission needs a valid,
   unexpired token for the same CSRF cookie, submitted no sooner than
   ``FORM_SHIELD_MIN_SECONDS`` after render.
2. A JavaScript proof: a field only our script (``static/js/form-shield.js``)
   fills in, derived from the token. No JavaScript, no email.
3. A honeypot field hidden from people, keyboards and assistive technology.
4. The verdict. A scripted submission (bad or missing token, no JS proof,
   honeypot filled) gets the same generic page as a real one and no email,
   so it learns nothing. Two outcomes a person can reach get the real form
   with a clear message instead: a too-fast submit that carries a valid JS
   proof (our script normally waits out the floor, so this is rare), and an
   expired token from a tab left open.

Every rejection is logged once (reason, IP hash, user agent) and counts
toward the auth email spike alert.

This raises the cost of a script, it does not prove a human: a client that
fetches the page, keeps the cookie, derives the proof and waits out the floor
passes. It stops the observed bot, and the email caps bound anything that
gets through. Turnstile (services/turnstile.py) is the durable human check
where a Cloudflare account is available.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from dataclasses import dataclass

from fastapi import Request

from contextify_cloud.config import settings
from contextify_cloud.http_security import resolve_client_ip
from contextify_cloud.utils.email import hash_ip_for_logs

logger = logging.getLogger(__name__)

TOKEN_FIELD = "form_token"
JS_FIELD = "form_js"
HONEYPOT_FIELD = "website"
_VERSION = "v1"
_JS_PREFIX = "js."
# A token older than this is from a tab left open, not a bot; the person is
# asked to try again.
MAX_AGE_SECONDS = 12 * 3600
_MAX_FIELD_LENGTH = 512

# Verdicts.
ACCEPT = "accept"
DROP = "drop"  # scripted: generic success page, no email
RETRY = "retry"  # a person can reach this: real form with a message

TOO_FAST_MESSAGE = "That was quick. Please press the button again to continue."
EXPIRED_MESSAGE = "This page expired. Please reload the page and try again."


@dataclass(frozen=True)
class ShieldResult:
    verdict: str
    reason: str = ""
    message: str = ""

    @property
    def accepted(self) -> bool:
        return self.verdict == ACCEPT


def form_shield_enabled() -> bool:
    return settings.form_shield_enabled


def _signature(form: str, issued_ms: int, csrf_token: str) -> str:
    key = f"form-shield|{settings.api_secret_key}".encode()
    message = f"{_VERSION}|{form}|{issued_ms}|{csrf_token}".encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()[:32]


def issue_form_token(form: str, csrf_token: str, *, now: float | None = None) -> str:
    """Token for one rendered form, bound to the page's public-CSRF token."""
    issued_ms = int((time.time() if now is None else now) * 1000)
    return f"{_VERSION}.{issued_ms}.{_signature(form, issued_ms, csrf_token)}"


def expected_js_proof(token: str) -> str:
    """What form-shield.js writes into the JS field for ``token``."""
    return _JS_PREFIX + token[::-1]


def form_shield_context(form: str, csrf_token: str) -> dict[str, object]:
    """Template context for a form that renders the shield fields."""
    if not form_shield_enabled():
        return {"form_shield": None}
    return {
        "form_shield": {
            "token": issue_form_token(form, csrf_token),
            "min_ms": int(settings.form_shield_min_seconds * 1000),
            "token_field": TOKEN_FIELD,
            "js_field": JS_FIELD,
            "honeypot_field": HONEYPOT_FIELD,
        }
    }


def check_submission(
    *,
    form: str,
    csrf_token: str,
    token: object,
    js_proof: object,
    honeypot: object,
    now: float | None = None,
) -> ShieldResult:
    """Classify one submission. The CSRF token must already be validated."""
    if not form_shield_enabled():
        return ShieldResult(ACCEPT)
    if honeypot not in (None, ""):
        return ShieldResult(DROP, "honeypot")
    if not isinstance(token, str) or not token or len(token) > _MAX_FIELD_LENGTH:
        return ShieldResult(DROP, "token_missing")
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != _VERSION or not parts[1].isdigit():
        return ShieldResult(DROP, "token_malformed")
    issued_ms = int(parts[1])
    if not hmac.compare_digest(parts[2], _signature(form, issued_ms, csrf_token)):
        return ShieldResult(DROP, "token_forged")
    if not isinstance(js_proof, str) or not hmac.compare_digest(
        js_proof.encode(), expected_js_proof(token).encode()
    ):
        return ShieldResult(DROP, "no_js")
    age = (time.time() if now is None else now) - issued_ms / 1000
    if age < -5:
        return ShieldResult(DROP, "token_from_future")
    if age < settings.form_shield_min_seconds:
        return ShieldResult(RETRY, "too_fast", TOO_FAST_MESSAGE)
    if age > MAX_AGE_SECONDS:
        return ShieldResult(RETRY, "expired", EXPIRED_MESSAGE)
    return ShieldResult(ACCEPT)


def log_rejection(request: Request, *, form: str, result: ShieldResult) -> None:
    """One structured line per rejected submission, and a spike-alert count."""
    user_agent = (request.headers.get("user-agent") or "")[:200]
    logger.warning(
        "event=form_shield_rejected form=%s reason=%s verdict=%s client_ip_hash=%s ua=%r",
        form,
        result.reason,
        result.verdict,
        hash_ip_for_logs(resolve_client_ip(request)),
        user_agent,
    )
    from contextify_cloud.services.auth_email_limits import record_rejected_submission

    record_rejected_submission()
