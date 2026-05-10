"""Hash helpers for RFC 8628 device authorization codes."""

import hashlib
import hmac

from contextify_cloud.config import settings


def _hash_code(kind: str, code: str) -> str:
    payload = f"contextify-device-auth:{kind}:{code}".encode()
    return hmac.new(
        settings.api_secret_key.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).hexdigest()


def hash_device_code(device_code: str) -> str:
    """Return the keyed lookup digest for an opaque device code."""
    return _hash_code("device", device_code)


def hash_user_code(user_code: str) -> str:
    """Return the keyed lookup digest for a human-entered user code."""
    return _hash_code("user", user_code.strip().upper())
