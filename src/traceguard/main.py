"""FastAPI application entry point."""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from traceguard.api.router import api_router
from traceguard.config import get_settings
from traceguard.core.database import init_db, close_db

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup and shutdown."""
    # Startup
    await init_db()
    yield
    # Shutdown
    await close_db()


app = FastAPI(
    title="TraceGuard",
    description="Agentic CVE triage and ownership automation tool",
    version="0.1.0",
    lifespan=lifespan,
)

# Include API routes
app.include_router(api_router)


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": "TraceGuard",
        "version": "0.1.0",
        "docs": "/docs",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "traceguard.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.api_debug,
    )
