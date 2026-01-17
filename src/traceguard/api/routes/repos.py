import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from traceguard.github.client import GitHubClient

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["repos"])


class RepoResponse(BaseModel):
    """Response model for repository data."""

    name: str
    full_name: str
    owner: str
    visibility: str
    url: str
    description: str | None


@router.get("/repos", response_model=list[RepoResponse])
async def list_repos() -> list[RepoResponse]:
    """List all repositories accessible by the configured GitHub token."""
    try:
        client = GitHubClient()
        repos = await client.list_repositories()
        return [
            RepoResponse(
                name=repo.name,
                full_name=repo.full_name,
                owner=repo.owner,
                visibility=repo.visibility,
                url=repo.url,
                description=repo.description,
            )
            for repo in repos
        ]
    except ValueError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to fetch repositories: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch repositories: {e}")
