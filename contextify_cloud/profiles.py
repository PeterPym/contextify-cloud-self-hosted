"""Runtime profile selection for Contextify Cloud."""

from enum import StrEnum

from contextify_cloud.config import Settings


class CloudProfile(StrEnum):
    """Supported runtime and distribution profiles."""

    HOSTED = "hosted"
    HOSTED_QA = "hosted_qa"
    SELF_HOSTED_PERSONAL = "self_hosted_personal"
    SELF_HOSTED_COMMERCIAL = "self_hosted_commercial"


def profile_from_settings(settings_obj: Settings) -> CloudProfile:
    """Resolve the explicit runtime profile from settings.

    ``CLOUD_PROFILE`` is the canonical selector. ``SELF_HOSTED=true`` remains a
    compatibility shortcut for the Personal Self-Hosted profile.
    """
    explicit = settings_obj.cloud_profile.strip().lower()
    if explicit:
        try:
            profile = CloudProfile(explicit)
        except ValueError as exc:
            valid = ", ".join(profile.value for profile in CloudProfile)
            raise RuntimeError(
                f"CLOUD_PROFILE must be one of: {valid} (got {explicit!r})."
            ) from exc

        if profile in {CloudProfile.HOSTED, CloudProfile.HOSTED_QA} and settings_obj.self_hosted:
            raise RuntimeError(
                "SELF_HOSTED=true conflicts with CLOUD_PROFILE='hosted'. "
                "Unset SELF_HOSTED or choose a self-hosted CLOUD_PROFILE."
            )
        return profile
    if settings_obj.self_hosted:
        return CloudProfile.SELF_HOSTED_PERSONAL
    return CloudProfile.HOSTED
