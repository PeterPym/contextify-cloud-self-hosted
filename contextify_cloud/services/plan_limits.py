"""Plan-derived enforcement limits for sync, retention, and team features."""

import logging
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException, status

from contextify_cloud.config import Settings, settings
from contextify_cloud.profiles import CloudProfile, profile_from_settings

logger = logging.getLogger(__name__)

FREE_PLAN = "free"
PRO_PLAN = "pro"
TEAM_PLAN = "team"
ENTERPRISE_PLAN = "enterprise"
SELF_HOSTED_PLAN = "self_hosted"

_PLAN_FALLBACK = FREE_PLAN
RETENTION_BATCH_SIZE = 5_000


@dataclass(frozen=True)
class PlanLimits:
    """Capabilities and hard caps for a billing plan."""

    max_users: int | None
    max_devices_per_user: int | None
    history_retention_days: int
    team_features: bool


SELF_HOSTED_PERSONAL_LIMITS = PlanLimits(
    max_users=1,
    max_devices_per_user=None,
    history_retention_days=0,
    team_features=False,
)

SELF_HOSTED_COMMERCIAL_LIMITS = PlanLimits(
    max_users=None,
    max_devices_per_user=None,
    history_retention_days=0,
    team_features=True,
)

# Compatibility alias for the historical plan key. Bare SELF_HOSTED=true now
# means Personal Self-Hosted, not a team-capable commercial deployment.
SELF_HOSTED_LIMITS = SELF_HOSTED_PERSONAL_LIMITS


_PLAN_LIMITS: dict[str, PlanLimits] = {
    SELF_HOSTED_PLAN: SELF_HOSTED_LIMITS,
    FREE_PLAN: PlanLimits(
        max_users=1,
        max_devices_per_user=2,
        history_retention_days=60,
        team_features=False,
    ),
    PRO_PLAN: PlanLimits(
        max_users=1,
        max_devices_per_user=None,
        history_retention_days=0,
        team_features=False,
    ),
    TEAM_PLAN: PlanLimits(
        max_users=None,
        max_devices_per_user=None,
        history_retention_days=0,
        team_features=True,
    ),
    ENTERPRISE_PLAN: PlanLimits(
        max_users=None,
        max_devices_per_user=None,
        history_retention_days=0,
        team_features=True,
    ),
}


def is_unlimited(settings_obj: Settings = settings) -> bool:
    """Return whether this deployment should bypass hosted billing limits."""
    return profile_from_settings(settings_obj) is not CloudProfile.HOSTED


def require_hosted_billing_enabled() -> None:
    """Raise 404 when hosted Stripe billing surfaces are disabled."""
    if is_unlimited():
        profile = profile_from_settings(settings)
        mode = (
            "Personal Self-Hosted"
            if profile is CloudProfile.SELF_HOSTED_PERSONAL
            else "Commercial Self-Hosted"
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Billing is not available in {mode} mode.",
        )


def normalize_plan(plan: object) -> str:
    """Normalize a raw plan value to a supported plan key."""
    if isinstance(plan, str):
        normalized = plan.strip().lower()
        if normalized in _PLAN_LIMITS:
            return normalized
    if plan is not None:
        logger.warning(
            "Unknown billing plan %r; applying restrictive fallback %r",
            plan,
            _PLAN_FALLBACK,
        )
    return _PLAN_FALLBACK


def get_plan_limits(plan_or_tenant: object) -> PlanLimits:
    """Return enforcement limits for a plan key or tenant-like object."""
    profile = profile_from_settings(settings)
    if profile is CloudProfile.SELF_HOSTED_PERSONAL:
        return SELF_HOSTED_PERSONAL_LIMITS
    if profile is CloudProfile.SELF_HOSTED_COMMERCIAL:
        return SELF_HOSTED_COMMERCIAL_LIMITS

    if isinstance(plan_or_tenant, str):
        return _PLAN_LIMITS[normalize_plan(plan_or_tenant)]

    tenant_plan = getattr(plan_or_tenant, "plan", None)
    return _PLAN_LIMITS[normalize_plan(tenant_plan)]


def supports_team_features(plan_or_tenant: object) -> bool:
    """Return whether the plan includes team-management features."""
    return get_plan_limits(plan_or_tenant).team_features


def get_team_features_upgrade_message(plan_or_tenant: object) -> str:
    """Return a consistent upgrade prompt for invite-gated plans."""
    if profile_from_settings(settings) is CloudProfile.SELF_HOSTED_PERSONAL:
        return (
            "Personal Self-Hosted is limited to one operator. "
            "Team invitations require Commercial Self-Hosted or hosted Team."
        )
    plan = normalize_plan(
        plan_or_tenant
        if isinstance(plan_or_tenant, str)
        else getattr(plan_or_tenant, "plan", None)
    )
    if plan == FREE_PLAN:
        return (
            "Free includes a single user. Upgrade to Team or Enterprise in "
            "hosted billing to invite members."
        )
    return (
        "Team invitations require a Team or Enterprise plan. "
        "Upgrade in hosted billing to invite members."
    )


def require_team_features(plan_or_tenant: object) -> None:
    """Raise 403 when the current plan does not include team features."""
    if supports_team_features(plan_or_tenant):
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=get_team_features_upgrade_message(plan_or_tenant),
    )


def get_effective_history_retention_days(tenant: Any) -> int:
    """Return the effective retention window in days for a tenant.

    When multiple policies exist, the shortest positive window wins.
    """
    limits = get_plan_limits(tenant)
    candidates = [
        limits.history_retention_days,
        getattr(settings, "default_data_retention_days", 0),
        getattr(tenant, "data_retention_days", 0),
    ]
    positive_days = [days for days in candidates if isinstance(days, int) and days > 0]
    return min(positive_days) if positive_days else 0
