"""Health check endpoint."""

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check() -> dict:
    """Check if the service is healthy."""
    return {"status": "healthy", "service": "traceguard"}
