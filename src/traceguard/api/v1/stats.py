"""Statistics API endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from traceguard.core.database import get_db_session
from traceguard.services.stats_service import StatsService
from traceguard.schemas.stats import DashboardStats

router = APIRouter(prefix="/stats", tags=["stats"])


def get_stats_service(session: AsyncSession = Depends(get_db_session)) -> StatsService:
    """Dependency to get StatsService instance."""
    return StatsService(session)


@router.get("/", response_model=DashboardStats)
async def get_dashboard_stats(
    stats_service: StatsService = Depends(get_stats_service),
) -> DashboardStats:
    """Get dashboard statistics."""
    return await stats_service.get_dashboard_stats()
