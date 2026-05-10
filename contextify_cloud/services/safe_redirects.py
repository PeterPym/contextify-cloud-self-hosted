"""Shared validation for local dashboard redirect targets."""


def safe_cloud_path(value: str | None) -> str | None:
    """Return a safe local /cloud path or None.

    Accept only relative dashboard paths. This rejects schemes,
    protocol-relative URLs, and control characters so callers can use the
    returned value in Location headers without creating an open redirect.
    """
    if not value:
        return None
    if any(ch in value for ch in ("\r", "\n", "\x00")):
        return None
    if value.startswith("//"):
        return None
    if ":" in value.split("/", 1)[0]:
        return None
    if value != "/cloud" and not value.startswith("/cloud/"):
        return None
    return value
