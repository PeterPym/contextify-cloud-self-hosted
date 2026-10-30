"""Recognize operator test and QA signup addresses at tenant creation.

Internal tenants never emit funnel analytics or operator activation emails (see
``funnel_events.emit_funnel_event`` and ``operator_notifications``). The flag was
only ever set by hand or by the QA-run controller, so an operator test signup made
through the ordinary sign-up flow (``rob+<tag>@...``, a harness ``@example.test``
address) became an external tenant and its lifecycle events landed in the real
activation funnel, where monthly volumes are single digits.

The rule is deliberately narrow, so it can never classify a real customer:

- an address listed in ``settings.internal_account_emails``, or a plus-addressed
  variant of one (``rob+qa-1@banagale.com`` for ``rob@banagale.com``). Plus tags
  are stripped only for listed addresses; no other normalization applies.
- an address in a reserved top-level domain (RFC 2606 / RFC 6761: ``.test``,
  ``.example``, ``.invalid``, ``.localhost``). Nobody outside a test harness
  can receive mail there. ``example.com`` and its siblings are not included:
  they are ordinary registered domains in the DNS sense, and tests use them to
  stand for real users.
"""

from __future__ import annotations

from contextify_cloud.config import settings

RESERVED_TEST_TLDS: frozenset[str] = frozenset({"test", "example", "invalid", "localhost"})


def _split(email: str) -> tuple[str, str] | None:
    local, sep, domain = email.strip().lower().rpartition("@")
    if not sep or not local or not domain:
        return None
    return local, domain.rstrip(".")


def _listed_addresses() -> frozenset[tuple[str, str]]:
    listed: set[tuple[str, str]] = set()
    for entry in settings.internal_account_emails.split(","):
        parts = _split(entry)
        if parts is not None:
            listed.add(parts)
    return frozenset(listed)


def is_internal_account_email(email: str | None) -> bool:
    """True when ``email`` is an operator test address or a reserved-TLD address."""
    if not email:
        return False
    parts = _split(email)
    if parts is None:
        return False
    local, domain = parts
    if domain.rsplit(".", 1)[-1] in RESERVED_TEST_TLDS:
        return True
    listed = _listed_addresses()
    if (local, domain) in listed:
        return True
    base_local = local.split("+", 1)[0]
    return (base_local, domain) in listed
