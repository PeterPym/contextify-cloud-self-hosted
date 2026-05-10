"""Email-related helper utilities.

The single source of truth for email normalization across the cloud service.
Every site that reads, writes, or looks up an email MUST route through
``normalize_email`` so identity comparisons collapse to one canonical form.
See cloud-magic-link design spec §4 ("Email normalization (mandatory, applied
everywhere)") for the rationale and the mandated call sites.
"""

from __future__ import annotations

import hashlib

from contextify_cloud.config import settings


def normalize_email(s: str) -> str:
    """Canonicalize an email address for identity comparison.

    Strips leading/trailing whitespace and casefolds the entire address
    (local-part + domain). Deliberately preserves provider-specific aliases
    such as Gmail dots and ``+suffix`` tags --- those are intentional user
    aliases, not noise to discard.

    Uses ``str.casefold`` (not ``str.lower``) for parity with rows that were
    previously written under the same convention --- legacy
    ``accounts.email_normalized`` rows were stored via ``casefold``, so a
    lookup that goes through ``lower`` would miss them for any address
    containing characters whose lower / casefold differ (German ``ß`` ->
    ``ss``, Greek final sigma, etc.) and silently mint a duplicate account.
    The DB-side partial unique index on
    ``auth_tokens.metadata_json->>'signup_email'`` uses PostgreSQL
    ``lower(btrim(...))`` because PG has no ``casefold`` equivalent; for ASCII
    the two agree exactly, and for the rare non-ASCII cases the
    application-side casefold is the source of truth.
    """
    return s.strip().casefold()


def mask_email(email: str) -> str:
    """Return a privacy-preserving masked rendering of an email address.

    Used in API responses (e.g. ``email-init``) so the user gets a hint of
    which inbox the email landed in without echoing the full address back to
    the requester (which could be exploited by attackers). Format is
    ``<first-char>***@<domain>``; if the local part is one character, render
    ``<char>***@<domain>``. Falls back to ``***`` for malformed inputs.
    """
    candidate = email.strip()
    if "@" not in candidate:
        return "***"
    local, _, domain = candidate.partition("@")
    if not local or not domain:
        return "***"
    first = local[0]
    return f"{first}***@{domain}"


def hash_email_for_logs(email: str) -> str:
    """Return a deterministic non-reversible identifier for log correlation.

    Computed as ``sha256(email_normalized || api_secret_key)`` so logs can be
    correlated across funnel stages without storing PII. Spec §9. The salt is
    the cloud-wide ``api_secret_key`` so two different deployments cannot
    correlate hashes.
    """
    payload = f"{normalize_email(email)}|{settings.api_secret_key}".encode()
    return hashlib.sha256(payload).hexdigest()


def hash_ip_for_logs(client_ip: str | None) -> str:
    """Return a non-reversible identifier for client IP correlation.

    Computed as ``sha256(ip || api_secret_key)``. Returns ``"unknown"`` when
    the request had no client IP (typically in unit tests). Spec §9.
    """
    if not client_ip:
        return "unknown"
    payload = f"{client_ip}|{settings.api_secret_key}".encode()
    return hashlib.sha256(payload).hexdigest()


# Map device_authorization.client_name strings to user-facing device names
# rendered in transactional email bodies. Spec §7 calls out the
# "contextify-macos-app" → "your Mac" transform; the table is the central
# definition so future client_name additions stay consistent.
_DEVICE_NAME_DISPLAY: dict[str, str] = {
    "contextify-macos-app": "your Mac",
    "contextify-cli": "your terminal",
}


def display_device_name(client_name: str | None) -> str:
    """Translate a device_authorization client_name to email-display text."""
    if not client_name:
        return "your device"
    return _DEVICE_NAME_DISPLAY.get(client_name, client_name)
