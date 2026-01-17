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


@dataclass
class DependabotAlert:
    """Represents a GitHub Dependabot security alert."""

    number: int
    state: str
    severity: str
    cve_id: str | None
    summary: str | None
    description: str | None
    package_name: str
    package_ecosystem: str
    vulnerable_version_range: str | None
    patched_version: str | None
    html_url: str


@dataclass
class GitHubUser:
    """Represents a GitHub user."""

    login: str
    name: str | None
    email: str | None


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
        params = {"per_page": 10, "sort": "updated", "affiliation": "owner"}

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

    async def get_dependabot_alerts(
        self, owner: str, repo: str, state: str = "open"
    ) -> list[DependabotAlert]:
        """Fetch Dependabot security alerts for a repository."""
        alerts: list[DependabotAlert] = []
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/dependabot/alerts"
        params = {"state": state, "per_page": 100}

        async with httpx.AsyncClient() as client:
            response = await client.get(
                url, headers=self._get_headers(), params=params
            )

            if response.status_code == 404:
                logger.warning(
                    f"Dependabot alerts not available for {owner}/{repo}. "
                    "This could mean the repo has no alerts or Dependabot is not enabled."
                )
                return []

            if response.status_code != 200:
                logger.error(
                    f"GitHub API error {response.status_code}: {response.text}"
                )

            response.raise_for_status()
            data = response.json()

            for alert in data:
                security_advisory = alert.get("security_advisory", {})
                vulnerability = alert.get("security_vulnerability", {})
                package = vulnerability.get("package", {})
                first_patched = vulnerability.get("first_patched_version", {})

                # Extract CVE ID from identifiers
                cve_id = None
                for identifier in security_advisory.get("identifiers", []):
                    if identifier.get("type") == "CVE":
                        cve_id = identifier.get("value")
                        break

                alerts.append(
                    DependabotAlert(
                        number=alert["number"],
                        state=alert["state"],
                        severity=security_advisory.get("severity", "unknown"),
                        cve_id=cve_id,
                        summary=security_advisory.get("summary"),
                        description=security_advisory.get("description"),
                        package_name=package.get("name", "unknown"),
                        package_ecosystem=package.get("ecosystem", "unknown"),
                        vulnerable_version_range=vulnerability.get(
                            "vulnerable_version_range"
                        ),
                        patched_version=first_patched.get("identifier")
                        if first_patched
                        else None,
                        html_url=alert["html_url"],
                    )
                )

        logger.info(
            f"Fetched {len(alerts)} Dependabot alerts for {owner}/{repo}"
        )
        return alerts

    async def get_user(self, username: str) -> GitHubUser:
        """Fetch a GitHub user's information."""
        url = f"{self.BASE_URL}/users/{username}"

        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=self._get_headers())

            if response.status_code != 200:
                logger.error(
                    f"GitHub API error {response.status_code}: {response.text}"
                )

            response.raise_for_status()
            data = response.json()

            return GitHubUser(
                login=data["login"],
                name=data.get("name"),
                email=data.get("email"),
            )
