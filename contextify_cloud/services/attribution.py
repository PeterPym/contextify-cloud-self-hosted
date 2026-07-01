"""Pseudonymous signup attribution helpers."""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from starlette.requests import Request
from starlette.responses import Response

ATTRIBUTION_COOKIE_NAME = "ctx_attr"
ATTRIBUTION_COOKIE_MAX_AGE_SECONDS = 30 * 24 * 60 * 60
ATTRIBUTION_REF_KEY = "ref"

_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
_UTM_RE = re.compile(r"^[A-Za-z0-9_.:/+-]{1,100}$")
_MAX_LANDING_PATH_LEN = 200
_COOKIE_PAYLOAD_MAX_LEN = 1200


@dataclass(frozen=True)
class AcquisitionAttribution:
    token: str
    source: str | None = None
    medium: str | None = None
    campaign: str | None = None
    content: str | None = None
    landing_path: str | None = None
    captured_at: datetime | None = None


def _clean_utm(value: str | None) -> str | None:
    if value is None:
        return None
    trimmed = value.strip()
    if not trimmed or not _UTM_RE.fullmatch(trimmed):
        return None
    return trimmed


def _clean_landing_path(value: str | None) -> str | None:
    if value is None:
        return None
    trimmed = value.strip()
    if (
        not trimmed
        or not trimmed.startswith("/")
        or trimmed.startswith("//")
        or "?" in trimmed
        or "#" in trimmed
    ):
        return None
    return trimmed[:_MAX_LANDING_PATH_LEN]


def _from_mapping(
    values: dict[str, str],
    *,
    fallback_path: str | None = None,
) -> AcquisitionAttribution | None:
    token = values.get(ATTRIBUTION_REF_KEY, "").strip()
    if not _TOKEN_RE.fullmatch(token):
        return None
    return AcquisitionAttribution(
        token=token,
        source=_clean_utm(values.get("utm_source")),
        medium=_clean_utm(values.get("utm_medium")),
        campaign=_clean_utm(values.get("utm_campaign")),
        content=_clean_utm(values.get("utm_content")),
        landing_path=(
            _clean_landing_path(values.get("landing_path"))
            or _clean_landing_path(fallback_path)
        ),
        captured_at=datetime.now(UTC),
    )


def parse_attribution_query(request: Request) -> AcquisitionAttribution | None:
    """Parse valid attribution query params from a public Cloud request."""
    return _from_mapping(
        {key: request.query_params.get(key, "") for key in _QUERY_KEYS},
        fallback_path=request.url.path,
    )


def parse_attribution_cookie(raw_cookie: str | None) -> AcquisitionAttribution | None:
    if not raw_cookie or len(raw_cookie) > _COOKIE_PAYLOAD_MAX_LEN:
        return None
    try:
        padded = raw_cookie + "=" * (-len(raw_cookie) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        payload = json.loads(decoded)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    values = {
        ATTRIBUTION_REF_KEY: _string_value(payload.get(ATTRIBUTION_REF_KEY)),
        "utm_source": _string_value(payload.get("utm_source")),
        "utm_medium": _string_value(payload.get("utm_medium")),
        "utm_campaign": _string_value(payload.get("utm_campaign")),
        "utm_content": _string_value(payload.get("utm_content")),
        "landing_path": _string_value(payload.get("landing_path")),
    }
    attribution = _from_mapping(values)
    if attribution is None:
        return None
    captured_at = _parse_datetime(_string_value(payload.get("captured_at")))
    return AcquisitionAttribution(
        token=attribution.token,
        source=attribution.source,
        medium=attribution.medium,
        campaign=attribution.campaign,
        content=attribution.content,
        landing_path=attribution.landing_path,
        captured_at=captured_at or attribution.captured_at,
    )


def attribution_from_request(request: Request) -> AcquisitionAttribution | None:
    """Prefer fresh query attribution, then fall back to the Cloud cookie."""
    return parse_attribution_query(request) or parse_attribution_cookie(
        request.cookies.get(ATTRIBUTION_COOKIE_NAME)
    )


def attribution_cookie_value(attribution: AcquisitionAttribution) -> str:
    payload = _to_wire_payload(attribution)
    encoded = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    return encoded.decode("ascii").rstrip("=")


def set_attribution_cookie(
    response: Response,
    *,
    attribution: AcquisitionAttribution | None,
    secure: bool,
) -> None:
    if attribution is None:
        return
    response.set_cookie(
        key=ATTRIBUTION_COOKIE_NAME,
        value=attribution_cookie_value(attribution),
        max_age=ATTRIBUTION_COOKIE_MAX_AGE_SECONDS,
        path="/cloud/",
        secure=secure,
        httponly=True,
        samesite="lax",
    )


def clear_attribution_cookie(response: Response, *, secure: bool) -> None:
    response.delete_cookie(
        key=ATTRIBUTION_COOKIE_NAME,
        path="/cloud/",
        secure=secure,
        httponly=True,
        samesite="lax",
    )


def attribution_to_metadata(attribution: AcquisitionAttribution | None) -> dict[str, object]:
    if attribution is None:
        return {}
    return {"acquisition_attribution": _to_wire_payload(attribution)}


def attribution_from_metadata(metadata: dict[str, object]) -> AcquisitionAttribution | None:
    raw = metadata.get("acquisition_attribution")
    if not isinstance(raw, dict):
        return None
    values = {
        ATTRIBUTION_REF_KEY: _string_value(raw.get(ATTRIBUTION_REF_KEY)),
        "utm_source": _string_value(raw.get("utm_source")),
        "utm_medium": _string_value(raw.get("utm_medium")),
        "utm_campaign": _string_value(raw.get("utm_campaign")),
        "utm_content": _string_value(raw.get("utm_content")),
        "landing_path": _string_value(raw.get("landing_path")),
    }
    attribution = _from_mapping(values)
    if attribution is None:
        return None
    captured_at = _parse_datetime(_string_value(raw.get("captured_at")))
    return AcquisitionAttribution(
        token=attribution.token,
        source=attribution.source,
        medium=attribution.medium,
        campaign=attribution.campaign,
        content=attribution.content,
        landing_path=attribution.landing_path,
        captured_at=captured_at or attribution.captured_at,
    )


def apply_attribution_to_tenant(tenant: Any, attribution: AcquisitionAttribution | None) -> None:
    """Persist acquisition fields without overwriting an existing tenant source."""
    if attribution is None or getattr(tenant, "acquisition_token", None):
        return
    tenant.acquisition_token = attribution.token
    tenant.acquisition_source = attribution.source
    tenant.acquisition_medium = attribution.medium
    tenant.acquisition_campaign = attribution.campaign
    tenant.acquisition_content = attribution.content
    tenant.acquisition_landing_path = attribution.landing_path
    tenant.acquisition_captured_at = attribution.captured_at or datetime.now(UTC)


def tenant_acquisition_properties(tenant: Any) -> dict[str, object]:
    token = getattr(tenant, "acquisition_token", None)
    if not isinstance(token, str) or not token:
        return {}
    properties: dict[str, object] = {ATTRIBUTION_REF_KEY: token}
    _add_property(properties, "utm_source", getattr(tenant, "acquisition_source", None))
    _add_property(properties, "utm_medium", getattr(tenant, "acquisition_medium", None))
    _add_property(properties, "utm_campaign", getattr(tenant, "acquisition_campaign", None))
    _add_property(properties, "utm_content", getattr(tenant, "acquisition_content", None))
    return properties


def with_tenant_acquisition_properties(
    tenant: Any,
    properties: dict[str, object],
) -> dict[str, object]:
    return {**properties, **tenant_acquisition_properties(tenant)}


_QUERY_KEYS = (
    ATTRIBUTION_REF_KEY,
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_content",
    "landing_path",
)


def _to_wire_payload(attribution: AcquisitionAttribution) -> dict[str, object]:
    payload: dict[str, object] = {ATTRIBUTION_REF_KEY: attribution.token}
    _add_property(payload, "utm_source", attribution.source)
    _add_property(payload, "utm_medium", attribution.medium)
    _add_property(payload, "utm_campaign", attribution.campaign)
    _add_property(payload, "utm_content", attribution.content)
    _add_property(payload, "landing_path", attribution.landing_path)
    captured_at = attribution.captured_at or datetime.now(UTC)
    payload["captured_at"] = captured_at.isoformat()
    return payload


def _string_value(value: object) -> str:
    return value if isinstance(value, str) else ""


def _parse_datetime(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def _add_property(properties: dict[str, object], key: str, value: object) -> None:
    if isinstance(value, str) and value:
        properties[key] = value
