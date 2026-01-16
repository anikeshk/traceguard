"""Main API router combining all v1 routes."""

from fastapi import APIRouter

from traceguard.api.v1 import health, jobs, stats

api_router = APIRouter(prefix="/api/v1")

# Include all routers
api_router.include_router(health.router)
api_router.include_router(jobs.router)
api_router.include_router(stats.router)
