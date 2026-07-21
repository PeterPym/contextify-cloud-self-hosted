"""Transactional email delivery for auth and team workflows.

Resend is the production sender. When RESEND_API_KEY is not configured,
messages are logged instead so local development and CI can validate the
workflow without external credentials.
"""

import logging
from dataclasses import dataclass
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path

import httpx
from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from contextify_cloud.config import is_dev_email_url, settings

logger = logging.getLogger(__name__)

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
# StrictUndefined raises UndefinedError when a template references a variable
# that the caller did not pass. Without it, missing OTP codes / verify URLs /
# reset URLs render as empty strings and produce broken auth emails that pass
# tests. autoescape stays HTML-extension-scoped so .txt fallbacks remain
# unescaped while .html user-supplied values (team_name, inviter_name,
# display_name, device_name, signup_email) are always escaped.
_email_template_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=select_autoescape(enabled_extensions=("html",), default_for_string=False),
    keep_trailing_newline=True,
    undefined=StrictUndefined,
)


def _render_email_template(template_name: str, **context: object) -> str:
    """Render a Jinja2 email template under ``templates/email/``."""
    template = _email_template_env.get_template(template_name)
    return template.render(**context)


def _email_template_defaults() -> dict[str, str]:
    """Default Jinja context applied to every email template render."""
    return {
        "brand_name": "Contextify",
        "homepage_url": "https://contextify.sh",
        "help_url": "https://contextify.sh/help",
    }


@dataclass(frozen=True)
class TransactionalEmail:
    to_email: str
    subject: str
    text: str
    html: str | None = None
    headers: dict[str, str] | None = None


async def send_transactional_email(message: TransactionalEmail) -> bool:
    """Send one transactional email using Resend or the fake logger path."""
    if settings.dev_allow_fake_transactional_email:
        if not settings.self_hosted and not (
            is_dev_email_url(settings.email_base_url)
            and is_dev_email_url(settings.invitation_base_url)
        ):
            logger.error(
                "event=fake_email_delivery_refused "
                "DEV_ALLOW_FAKE_TRANSACTIONAL_EMAIL refused for non-dev "
                "hosted URLs. Email not sent. to=%s subject=%s",
                message.to_email,
                message.subject,
            )
            return False
        logger.warning(
            "event=fake_email_delivery "
            "DEV_ALLOW_FAKE_TRANSACTIONAL_EMAIL enabled. "
            "Email not sent. to=%s subject=%s",
            message.to_email,
            message.subject,
        )
        return True

    if not settings.resend_api_key:
        if not settings.self_hosted:
            logger.error(
                "event=auth_email_delivery_unconfigured "
                "RESEND_API_KEY missing in managed mode. Email not sent. "
                "to=%s subject=%s",
                message.to_email,
                message.subject,
            )
            return False
        logger.warning(
            "event=fake_email_delivery "
            "RESEND_API_KEY not configured. Email not sent. to=%s subject=%s",
            message.to_email,
            message.subject,
        )
        return True

    payload: dict[str, object] = {
        "from": settings.email_from,
        "to": [message.to_email],
        "subject": message.subject,
        "text": message.text,
    }
    if settings.email_reply_to:
        payload["reply_to"] = settings.email_reply_to
    if message.html:
        payload["html"] = message.html

    # Do not synthesize RFC 8058 one-click unsubscribe headers here. One-click
    # requires a working HTTPS POST endpoint with an opaque recipient identifier;
    # advertising "List-Unsubscribe-Post: List-Unsubscribe=One-Click" while
    # serving only a mailto: target is incorrect per RFC 8058 and Gmail
    # bulk-sender guidance. Callers may still pass explicit, provider-safe
    # headers via TransactionalEmail.headers. ct-1588 will reintroduce real
    # RFC 8058 unsubscribe handling once the preferences page ships with a
    # working HTTPS endpoint and an opaque per-recipient token.
    if message.headers:
        payload["headers"] = message.headers

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                "https://api.resend.com/emails",
                headers={
                    "Authorization": f"Bearer {settings.resend_api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
    except httpx.HTTPError:
        logger.exception(
            "Resend email send failed: transport error to=%s subject=%s",
            message.to_email,
            message.subject,
        )
        return False
    if response.status_code >= 400:
        logger.error(
            "Resend email send failed: status=%s to=%s",
            response.status_code,
            message.to_email,
        )
        return False
    return True


def _classify_signup_platform(user_agent: str | None) -> str:
    """Classify a browser User-Agent header as macos, linux, or unknown.

    Heuristic only: a Mac UA suggests the user is browsing from a Mac and
    will most likely run Contextify on a Mac, but they could also run
    Contextify on a Linux machine they own. Linux desktop is rare, so a
    Linux UA is a strong signal that the user is a Linux Contextify user.
    Anything else (mobile, Windows, blank) -> unknown, which the welcome
    template renders with neutral copy. Plurals always cover both
    supported platforms regardless of detection result.
    """
    if not user_agent:
        return "unknown"
    ua = user_agent.lower()
    # Mobile UAs frequently include "linux" (Android) — exclude them so they
    # fall through to neutral instead of being miscategorized as Linux desktop.
    if "android" in ua or "iphone" in ua or "ipad" in ua or "mobile" in ua:
        return "unknown"
    if "linux" in ua:
        return "linux"
    if "macintosh" in ua or "mac os x" in ua or "darwin" in ua:
        return "macos"
    return "unknown"


def _welcome_copy_for(platform: str) -> dict[str, str]:
    """Return platform-aware singular noun + CTA label for the welcome email.

    The plural ("Macs and Linux machines") is hardcoded in the templates
    because it always covers both supported platforms regardless of which
    one the user is signing up from.
    """
    if platform == "macos":
        return {"device": "Mac", "cta": "Connect this Mac"}
    if platform == "linux":
        return {"device": "Linux machine", "cta": "Connect this Linux machine"}
    return {"device": "device", "cta": "Connect this device"}


async def send_welcome_email(
    to_email: str,
    name: str | None = None,
    *,
    user_agent: str | None = None,
) -> bool:
    """Send the welcome email after a successful signup.

    ``user_agent`` is the browser ``User-Agent`` header captured at signup
    time. It is used as a heuristic to address the user with platform-aware
    singular copy ("this Mac" / "this Linux machine"); plurals always
    reference both supported platforms. Pass None on paths where the UA is
    not available — the template falls back to neutral "this device" copy.
    """
    # ct-1622: deep-link the welcome email CTA into the /welcome/ page's
    # first-machine path so it matches the post-register redirect target
    # (dashboard.py register_submit).
    platform = _classify_signup_platform(user_agent)
    copy = _welcome_copy_for(platform)
    context: dict[str, object] = {
        "display_name": name,
        "connect_url": f"{settings.email_base_url.rstrip('/')}/welcome/?path=first",
        "device": copy["device"],
        "cta": copy["cta"],
        **_email_template_defaults(),
    }
    text = _render_email_template("email/welcome.txt", **context)
    html = _render_email_template("email/welcome.html", **context)
    return await send_transactional_email(
        TransactionalEmail(
            to_email=to_email,
            subject="Welcome to Contextify Cloud",
            text=text,
            html=html,
        )
    )


async def send_local_commercial_license_email(
    to_email: str,
    license_token: str,
    expires_at: datetime,
) -> bool:
    """Deliver a freshly minted Local Commercial license token to the buyer (ct-1966).

    Sent once on purchase fulfillment. ``expires_at`` is the token's current
    expiry; it is rendered as a human date in the body. Renewals re-mint the
    token silently and are retrievable rather than re-emailed.
    """
    context: dict[str, object] = {
        "license_token": license_token,
        "expires_date": expires_at.strftime("%B %d, %Y"),
        **_email_template_defaults(),
    }
    text = _render_email_template("email/local_commercial_license.txt", **context)
    html = _render_email_template("email/local_commercial_license.html", **context)
    return await send_transactional_email(
        TransactionalEmail(
            to_email=to_email,
            subject="Your Contextify Local Commercial license",
            text=text,
            html=html,
        )
    )


async def send_self_hosted_pro_license_email(
    to_email: str,
    license_token: str,
    expires_at: datetime,
    company: str,
    seats: int,
) -> bool:
    """Deliver a freshly minted Self-Hosted Pro license key to the buyer (ct-2313).

    Sent once on purchase fulfillment to the billing/admin contact. The body is
    named-licensee (``company``, ``seats``) and explains server-side activation
    via the server's license-key environment variable, unlike the app-side Local
    Commercial activation. Renewals re-mint silently and are not re-emailed.
    """
    context: dict[str, object] = {
        "license_token": license_token,
        "expires_date": expires_at.strftime("%B %d, %Y"),
        "company": company,
        "seats": seats,
        **_email_template_defaults(),
    }
    text = _render_email_template("email/self_hosted_pro_license.txt", **context)
    html = _render_email_template("email/self_hosted_pro_license.html", **context)
    return await send_transactional_email(
        TransactionalEmail(
            to_email=to_email,
            subject="Your Contextify Self-Hosted Pro license",
            text=text,
            html=html,
        )
    )


async def send_license_retrieval_email(to_email: str, retrieve_url: str) -> bool:
    """Email a one-time link to retrieve an existing Local Commercial license (ct-2015).

    Sent only when a license exists for the requested email. The link reveals the
    license once and expires soon; this email never contains the token itself.
    """
    context: dict[str, object] = {
        "retrieve_url": retrieve_url,
        **_email_template_defaults(),
    }
    text = _render_email_template("email/license_retrieval.txt", **context)
    html = _render_email_template("email/license_retrieval.html", **context)
    return await send_transactional_email(
        TransactionalEmail(
            to_email=to_email,
            subject="Retrieve your Contextify Local Commercial license",
            text=text,
            html=html,
        )
    )


async def send_email_verification(to_email: str, token: str) -> bool:
    context: dict[str, object] = {
        "verify_url": f"{settings.email_base_url}/cloud/verify-email/{token}",
        **_email_template_defaults(),
    }
    text = _render_email_template("email/email_verification.txt", **context)
    html = _render_email_template("email/email_verification.html", **context)
    return await send_transactional_email(
        TransactionalEmail(
            to_email=to_email,
            subject="Verify your Contextify Cloud email",
            text=text,
            html=html,
        )
    )


async def send_password_reset(
    to_email: str, token: str, *, is_passwordless: bool = False,
) -> bool:
    """Send the password-reset / set-password email.

    Per cloud-magic-link spec §13a "Forgot-password copy adapts", accounts
    where ``password_hash IS NULL`` (created via the device-flow magic-link
    or login magic-link path and have never set a password) receive a
    "Set your..." subject and body in place of the legacy "Reset your..."
    copy. The link target is identical.
    """
    context: dict[str, object] = {
        "reset_url": f"{settings.email_base_url}/cloud/password-reset/{token}",
        "is_passwordless": is_passwordless,
        **_email_template_defaults(),
    }
    text = _render_email_template("email/password_reset.txt", **context)
    html = _render_email_template("email/password_reset.html", **context)
    subject = (
        "Set your Contextify Cloud password"
        if is_passwordless
        else "Reset your Contextify Cloud password"
    )
    return await send_transactional_email(
        TransactionalEmail(
            to_email=to_email,
            subject=subject,
            text=text,
            html=html,
        )
    )


async def send_email_change_confirmation(to_email: str, token: str) -> bool:
    context: dict[str, object] = {
        "confirm_url": f"{settings.email_base_url}/cloud/settings/email/confirm/{token}",
        **_email_template_defaults(),
    }
    text = _render_email_template("email/email_change_confirmation.txt", **context)
    html = _render_email_template("email/email_change_confirmation.html", **context)
    return await send_transactional_email(
        TransactionalEmail(
            to_email=to_email,
            subject="Confirm your Contextify Cloud email change",
            text=text,
            html=html,
        )
    )


async def send_device_signin_existing_user(
    to_email: str,
    magic_link_url: str,
    otp_code: str,
    device_name: str,
    expires_in_minutes: int,
) -> bool:
    """Send the device-flow magic link to an existing-account user.

    Per cloud-magic-link design spec §7. Subject is ``Finish connecting
    Contextify``; the HTML body's CTA button is labeled ``Connect Contextify``.
    """
    context = {
        "to_email": to_email,
        "magic_link_url": magic_link_url,
        "otp_code": otp_code,
        "device_name": device_name,
        "expires_in_minutes": expires_in_minutes,
    }
    text = _render_email_template("email/device_signin_existing_user.txt", **context)
    html = _render_email_template("email/device_signin_existing_user.html", **context)
    return await send_transactional_email(
        TransactionalEmail(
            to_email=to_email,
            subject="Finish connecting Contextify",
            text=text,
            html=html,
        )
    )


async def send_device_signup_new_user(
    to_email: str,
    signup_email: str,
    magic_link_url: str,
    otp_code: str,
    device_name: str,
    expires_in_minutes: int,
) -> bool:
    """Send the device-flow magic link to a brand-new (no-account) user.

    Per cloud-magic-link design spec §7. Subject is ``Connect Contextify on
    your Mac``; the HTML body's CTA button is labeled ``Connect Contextify``.
    No Account row exists yet at the time of send; one is created when the
    user completes the magic link or OTP step (see ``_finalize_device_token``).
    """
    context = {
        "to_email": to_email,
        "signup_email": signup_email,
        "magic_link_url": magic_link_url,
        "otp_code": otp_code,
        "device_name": device_name,
        "expires_in_minutes": expires_in_minutes,
    }
    text = _render_email_template("email/device_signup_new_user.txt", **context)
    html = _render_email_template("email/device_signup_new_user.html", **context)
    return await send_transactional_email(
        TransactionalEmail(
            to_email=to_email,
            subject="Connect Contextify on your Mac",
            text=text,
            html=html,
        )
    )


async def send_login_magic_link(
    to_email: str,
    magic_link_url: str,
    otp_code: str,
    expires_in_minutes: int,
) -> bool:
    """Send a passwordless sign-in magic link for the ``/cloud/login`` flow.

    Per cloud-magic-link design spec §13b. Subject is ``Sign in to
    Contextify``; the HTML body's CTA button is labeled ``Sign in to
    Contextify Cloud``. The dispatcher gates this so it is only sent for
    existing, non-disabled accounts; the email enumeration defense lives in
    the caller.
    """
    context = {
        "to_email": to_email,
        "magic_link_url": magic_link_url,
        "otp_code": otp_code,
        "expires_in_minutes": expires_in_minutes,
    }
    text = _render_email_template("email/login_magic_link.txt", **context)
    html = _render_email_template("email/login_magic_link.html", **context)
    return await send_transactional_email(
        TransactionalEmail(
            to_email=to_email,
            subject="Sign in to Contextify",
            text=text,
            html=html,
        )
    )


async def send_register_signup_email(
    to_email: str,
    signup_email: str,
    magic_link_url: str,
    otp_code: str,
    expires_in_minutes: int,
) -> bool:
    """Send the email-first passwordless sign-up link for ``/cloud/register``.

    ct-2983 (Option B+ / Decision-2a): the browser analogue of
    ``send_device_signup_new_user``. No Account row exists yet at the time of
    send; a passwordless one is created when the user completes the magic link
    or OTP step (see ``_finalize_browser_signup_token``). The dispatcher gates
    this so it is only sent for unknown emails when registration is enabled;
    the email enumeration defense lives in the caller.
    """
    context = {
        "to_email": to_email,
        "signup_email": signup_email,
        "magic_link_url": magic_link_url,
        "otp_code": otp_code,
        "expires_in_minutes": expires_in_minutes,
    }
    text = _render_email_template("email/register_signup_new_user.txt", **context)
    html = _render_email_template("email/register_signup_new_user.html", **context)
    return await send_transactional_email(
        TransactionalEmail(
            to_email=to_email,
            subject="Finish creating your Contextify account",
            text=text,
            html=html,
        )
    )


def _smtp_configured() -> bool:
    """Check whether SMTP credentials are configured."""
    return bool(settings.smtp_host and settings.smtp_host.strip())


async def send_invitation_email(
    to_email: str,
    invite_token: str,
    tenant_name: str,
    inviter_name: str,
    base_url: str | None = None,
) -> bool:
    """Send an invitation email to a new team member.

    Args:
        to_email: Recipient email address.
        invite_token: UUID token for the invitation accept link.
        tenant_name: Display name of the team/tenant.
        inviter_name: Display name of the person who sent the invite.
        base_url: Base URL for the accept link. Defaults to config value.

    Returns:
        True if email was sent (or logged), False on send failure.
    """
    base = base_url or settings.invitation_base_url
    accept_url = f"{base}/api/v1/invitations/{invite_token}/accept"

    context: dict[str, object] = {
        "team_name": tenant_name,
        "inviter_name": inviter_name,
        "accept_url": accept_url,
        "invitation_expiry_days": settings.invitation_expiry_days,
        **_email_template_defaults(),
    }
    subject = f"You're invited to join {tenant_name} on Contextify Cloud"
    text = _render_email_template("email/team_invitation.txt", **context)

    if settings.resend_api_key:
        html = _render_email_template("email/team_invitation.html", **context)
        return await send_transactional_email(
            TransactionalEmail(
                to_email=to_email,
                subject=subject,
                text=text,
                html=html,
            )
        )

    if not _smtp_configured():
        logger.warning(
            "Email delivery not configured. Invitation email not sent. to=%s",
            to_email,
        )
        return True  # Not a failure, just not configured

    try:
        import aiosmtplib

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = settings.smtp_from
        msg["To"] = to_email
        msg.set_content(text)

        await aiosmtplib.send(
            msg,
            hostname=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_user or None,
            password=settings.smtp_password or None,
            start_tls=True,
        )

        logger.info("Invitation email sent to %s for team %s", to_email, tenant_name)
        return True

    except ImportError:
        logger.warning(
            "aiosmtplib not installed. Invitation email not sent. "
            "Install with: pip install aiosmtplib. to=%s",
            to_email,
        )
        return True  # Graceful fallback

    except Exception:
        logger.exception("Failed to send invitation email to %s", to_email)
        return False
