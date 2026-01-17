import logging
from dataclasses import dataclass

import httpx

from traceguard.config import get_github_token

logger = logging.getLogger(__name__)


@dataclass
class Repository:
    """Represents a GitHub repository."""

    name: str
    full_name: str
    owner: str
    visibility: str
    url: str
    description: str | None


class GitHubClient:
    """Async client for GitHub API."""

    BASE_URL = "https://api.github.com"

    def __init__(self, token: str | None = None) -> None:
        self._token = token or get_github_token()

    def _get_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    async def list_repositories(self) -> list[Repository]:
        """List all repositories accessible by the authenticated user."""
        repositories: list[Repository] = []
        url = f"{self.BASE_URL}/user/repos"
        params = {"per_page": 100, "sort": "updated"}

        async with httpx.AsyncClient() as client:
            response = await client.get(
                url, headers=self._get_headers(), params=params
            )

            if response.status_code != 200:
                logger.error(f"GitHub API error {response.status_code}: {response.text}")

            response.raise_for_status()
            data = response.json()

            for repo in data:
                repositories.append(
                    Repository(
                        name=repo["name"],
                        full_name=repo["full_name"],
                        owner=repo["owner"]["login"],
                        visibility=repo["visibility"],
                        url=repo["html_url"],
                        description=repo.get("description"),
                    )
                )

        logger.info(f"Fetched {len(repositories)} repositories from GitHub")
        return repositories
