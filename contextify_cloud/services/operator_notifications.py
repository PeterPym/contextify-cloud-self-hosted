"""Operator notification emails (ct-2076).

Fire-and-forget notifications to the operator (``settings.operator_notification_email``)
for the activation funnel that error monitoring alone cannot see:

1. New signup            -> a genuinely new account/tenant was provisioned.
2. First successful sync  -> a tenant landed its first data (activation). This is
                            the signal that was missing when a user looped on a
                            413 for weeks and another churned before ever syncing.
3. Became paid           -> a tenant transitioned to an active paid subscription
                            (marked high-priority/important).

Design: these are non-critical, best-effort, sent inline post-commit. They MUST
NOT block or break the caller's flow, so every entry point swallows its own
errors and returns a bool. They are skipped entirely in self-hosted mode (no
central operator) and when no recipient is configured.
"""

from __future__ import annotations

import logging

from contextify_cloud.config import settings
from contextify_cloud.services.email import (
    TransactionalEmail,
    _classify_signup_platform,
    send_transactional_email,
)

logger = logging.getLogger(__name__)

# Resend/SMTP importance headers for the high-priority "became paid" mail.
_IMPORTANT_HEADERS: dict[str, str] = {
    "X-Priority": "1",
    "Importance": "high",
    "X-MSMail-Priority": "High",
}

# Product-aware lead nouns for cancellation notices, keyed off the canonical
# product value; unknown products fall back to the generic Cloud lead.
_CANCELLED_LEADS: dict[str, str] = {
    "self_hosted_pro": "A Self-Hosted Pro license was just cancelled.",
    "local_commercial": "A Local Commercial license was just cancelled.",
    "cloud": "A Contextify Cloud subscription was just cancelled.",
}

# Product-aware subject templates for cancellation notices, keyed off the
# canonical product value; unknown products fall back to the generic Cloud
# cancellation subject (safe default). Each template contains ``{who}``.
_CANCELLED_SUBJECTS: dict[str, str] = {
    "self_hosted_pro": "Self-Hosted Pro license cancelled: {who}",
    "local_commercial": "Local Commercial license cancelled: {who}",
    "cloud": "Contextify Cloud cancellation: {who}",
}


def _operator_notifications_enabled() -> bool:
    """Operator notifications run only in managed mode with a recipient set."""
    return bool(not settings.self_hosted and settings.operator_notification_email)


async def _send_operator_email(
    *, subject: str, text: str, important: bool = False
) -> bool:
    """Send one operator notification, swallowing all errors.

    Returns True if the email was handed to the sender successfully, False if
    notifications are disabled or the send failed. Never raises.
    """
    if not _operator_notifications_enabled():
        return False
    try:
        return await send_transactional_email(
            TransactionalEmail(
                to_email=settings.operator_notification_email,
                subject=subject,
                text=text,
                headers=_IMPORTANT_HEADERS if important else None,
            )
        )
    except Exception:  # noqa: BLE001 - notifications must never break the caller
        logger.exception(
            "event=operator_notification_failed subject=%s", subject
        )
        return False


async def notify_new_signup(
    *,
    email: str,
    tenant_id: str,
    plan: str,
    user_agent: str | None = None,
    is_internal: bool = False,
) -> bool:
    """Notify the operator that a new account/tenant signed up."""
    if is_internal:
        return False
    platform = _classify_signup_platform(user_agent) if user_agent else None
    platform_line = f"\nPlatform (guessed): {platform}" if platform else ""
    text = (
        "A new Contextify Cloud account just signed up.\n\n"
        f"Email:  {email}\n"
        f"Tenant: {tenant_id}\n"
        f"Plan:   {plan}{platform_line}\n"
    )
    return await _send_operator_email(
        subject=f"New Contextify Cloud signup: {email}", text=text
    )


async def notify_first_activation(
    *,
    email: str | None,
    tenant_id: str,
    is_internal: bool = False,
) -> bool:
    """Notify the operator that a tenant landed its first successful sync.

    This is the activation signal: the tenant went from zero synced data to
    having data. Fired once, on the first push that accepts data for a tenant
    that previously had none.
    """
    if is_internal:
        return False
    who = email or "(unknown user)"
    text = (
        "A Contextify Cloud tenant just completed its FIRST successful sync "
        "(activation).\n\n"
        f"Email:  {who}\n"
        f"Tenant: {tenant_id}\n\n"
        "This tenant previously had no synced data.\n"
    )
    return await _send_operator_email(
        subject=f"Contextify Cloud activation (first sync): {who}", text=text
    )


async def notify_became_paid(
    *,
    email: str | None,
    tenant_id: str,
    plan: str,
    is_internal: bool = False,
) -> bool:
    """Notify the operator (high-priority) that a tenant became paid."""
    if is_internal:
        return False
    who = email or "(unknown user)"
    text = (
        "A Contextify Cloud tenant just became PAID.\n\n"
        f"Email:  {who}\n"
        f"Tenant: {tenant_id}\n"
        f"Plan:   {plan}\n"
    )
    return await _send_operator_email(
        subject=f"[IMPORTANT] Contextify Cloud paid conversion: {who}",
        text=text,
        important=True,
    )


def _should_notify_for_event(
    *,
    livemode: bool,
    is_internal: bool = False,
    test_metadata: bool = False,
) -> bool:
    """Decide whether a consequential billing event warrants an operator notice.

    Pure, synchronous suppression predicate the billing webhook calls BEFORE
    routing to a notify_* function. Stripe ``livemode`` is the primary universal
    backstop: test-mode events never notify, regardless of the other flags. An
    internal/QA tenant (``is_internal``) or an explicit test marker
    (``test_metadata``) also suppress. Otherwise the event is live and external,
    so notify.
    """
    if not livemode:
        return False
    if is_internal:
        return False
    if test_metadata:
        return False
    return True


async def notify_self_hosted_pro_purchase(
    *,
    company: str,
    admin_contact: str,
    seats: int,
    amount: str,
) -> bool:
    """Notify the operator (high-priority) of a Self-Hosted Pro purchase."""
    text = (
        "A Self-Hosted Pro license was just purchased.\n\n"
        f"Company:       {company}\n"
        f"Admin contact: {admin_contact}\n"
        f"Seats:         {seats}\n"
        f"Amount:        {amount}\n"
    )
    return await _send_operator_email(
        subject=f"[IMPORTANT] Self-Hosted Pro purchase: {company}",
        text=text,
        important=True,
    )


async def notify_local_commercial_purchase(
    *,
    customer_email: str,
    seats: int,
    amount: str,
) -> bool:
    """Notify the operator (high-priority) of a Local Commercial license purchase."""
    text = (
        "A Local Commercial license was just purchased.\n\n"
        f"Customer: {customer_email}\n"
        f"Seats:    {seats}\n"
        f"Amount:   {amount}\n"
    )
    return await _send_operator_email(
        subject=f"[IMPORTANT] Local Commercial purchase: {customer_email}",
        text=text,
        important=True,
    )


async def notify_subscription_cancelled(
    *,
    who: str,
    product: str,
    plan: str,
) -> bool:
    """Notify the operator (normal priority) that a subscription was cancelled."""
    # Lead with a product-aware noun keyed off the canonical product value;
    # unknown products fall back to the generic Cloud lead (safe default).
    lead = _CANCELLED_LEADS.get(
        product, "A Contextify Cloud subscription was just cancelled."
    )
    text = (
        f"{lead}\n\n"
        f"Who:     {who}\n"
        f"Product: {product}\n"
        f"Plan:    {plan}\n"
    )
    subject = _CANCELLED_SUBJECTS.get(
        product, "Contextify Cloud cancellation: {who}"
    ).format(who=who)
    return await _send_operator_email(
        subject=subject,
        text=text,
    )
