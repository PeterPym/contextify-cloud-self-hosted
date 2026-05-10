"""Health check endpoints."""

from fastapi import APIRouter, Depends, Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from contextify_cloud.config import settings
from contextify_cloud.database import get_db
from contextify_cloud.profiles import CloudProfile, profile_from_settings
from contextify_cloud.schemas import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/api/v1/health", response_model=HealthResponse)
async def health(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> HealthResponse:
    """Health check - verifies API is running and database is reachable."""
    db_status = "connected"
    try:
        await db.execute(text("SELECT 1"))
    except Exception:
        db_status = "disconnected"

    profile = getattr(request.app.state, "cloud_profile", None)
    if profile is None:
        profile = profile_from_settings(settings)
    is_self_hosted = profile is not CloudProfile.HOSTED

    return HealthResponse(
        status="ok" if db_status == "connected" else "degraded",
        self_hosted=is_self_hosted,
    )
