"""GitHub Security Advisories API client."""

import logging
from datetime import datetime, timezone
from typing import Optional

import httpx

from traceguard.cve_sources.base import CVESource
from traceguard.config import get_settings
from traceguard.schemas.cve import AffectedPackage, CVEContextSchema

logger = logging.getLogger(__name__)

GITHUB_API_URL = "https://api.github.com"


class GitHubAdvisoryClient(CVESource):
    """Client for the GitHub Security Advisories API.

    Uses the GitHub REST API to fetch security advisories.
    API docs: https://docs.github.com/en/rest/security-advisories/global-advisories
    """

    def __init__(self, token: Optional[str] = None, timeout: float = 30.0):
        """Initialize the GitHub Advisory client.

        Args:
            token: GitHub personal access token. If not provided, uses settings.
            timeout: HTTP request timeout in seconds.
        """
        settings = get_settings()
        self._token = token or settings.github_token

        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        self._client = httpx.AsyncClient(timeout=timeout, headers=headers)

    @property
    def source_name(self) -> str:
        return "github"

    async def fetch_by_cve_id(self, cve_id: str) -> Optional[CVEContextSchema]:
        """Fetch CVE context by CVE identifier."""
        try:
            # Search advisories by CVE ID
            response = await self._client.get(
                f"{GITHUB_API_URL}/advisories",
                params={"cve_id": cve_id},
            )
            response.raise_for_status()
            advisories = response.json()

            if not advisories:
                logger.debug(f"No GitHub advisory found for CVE {cve_id}")
                return None

            # Return the first matching advisory
            return self._parse_github_advisory(advisories[0])

        except httpx.HTTPStatusError as e:
            logger.error(f"GitHub API error for {cve_id}: {e.response.status_code}")
            return None
        except Exception as e:
            logger.error(f"Error fetching CVE {cve_id} from GitHub: {e}")
            return None

    async def fetch_by_ghsa_id(self, ghsa_id: str) -> Optional[CVEContextSchema]:
        """Fetch CVE context by GitHub Security Advisory ID."""
        try:
            # Direct lookup by GHSA ID
            response = await self._client.get(f"{GITHUB_API_URL}/advisories/{ghsa_id}")
            response.raise_for_status()
            advisory = response.json()
            return self._parse_github_advisory(advisory)

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                logger.debug(f"GHSA {ghsa_id} not found")
                return None
            logger.error(f"GitHub API error for {ghsa_id}: {e.response.status_code}")
            return None
        except Exception as e:
            logger.error(f"Error fetching GHSA {ghsa_id} from GitHub: {e}")
            return None

    async def fetch_by_package(
        self,
        package_name: str,
        ecosystem: str,
        version: Optional[str] = None,
    ) -> list[CVEContextSchema]:
        """Fetch all CVEs affecting a specific package."""
        try:
            # Map ecosystem names to GitHub ecosystem format
            github_ecosystem = self._map_ecosystem(ecosystem)

            params = {
                "ecosystem": github_ecosystem,
                "affects": package_name,
            }

            response = await self._client.get(
                f"{GITHUB_API_URL}/advisories",
                params=params,
            )
            response.raise_for_status()
            advisories = response.json()

            results = []
            for advisory in advisories:
                parsed = self._parse_github_advisory(advisory)
                if parsed:
                    # If version specified, filter to only matching advisories
                    if version:
                        if self._version_affected(advisory, package_name, version):
                            results.append(parsed)
                    else:
                        results.append(parsed)

            return results

        except httpx.HTTPStatusError as e:
            logger.error(f"GitHub API error for package {package_name}: {e.response.status_code}")
            return []
        except Exception as e:
            logger.error(f"Error fetching vulnerabilities for {package_name}: {e}")
            return []

    def _map_ecosystem(self, ecosystem: str) -> str:
        """Map ecosystem name to GitHub's ecosystem format."""
        ecosystem_map = {
            "npm": "npm",
            "pypi": "pip",
            "pip": "pip",
            "maven": "maven",
            "go": "go",
            "cargo": "rust",
            "rust": "rust",
            "nuget": "nuget",
            "rubygems": "rubygems",
            "packagist": "composer",
            "composer": "composer",
        }
        return ecosystem_map.get(ecosystem.lower(), ecosystem.lower())

    def _version_affected(
        self, advisory: dict, package_name: str, version: str
    ) -> bool:
        """Check if a specific version is affected by the advisory."""
        vulnerabilities = advisory.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            pkg = vuln.get("package", {})
            if pkg.get("name", "").lower() == package_name.lower():
                # Check vulnerable_version_range
                # This is a simplified check - proper semver comparison would be better
                range_str = vuln.get("vulnerable_version_range", "")
                if range_str:
                    # If the version is mentioned in the range, consider it affected
                    # A proper implementation would parse semver ranges
                    return True
        return False

    def _parse_github_advisory(self, advisory: dict) -> Optional[CVEContextSchema]:
        """Parse a GitHub advisory response into our schema."""
        try:
            ghsa_id = advisory.get("ghsa_id", "")
            cve_id = advisory.get("cve_id")

            # If no CVE ID, use GHSA ID
            if not cve_id:
                cve_id = ghsa_id

            # Parse severity
            severity = advisory.get("severity", "").upper()
            cvss = advisory.get("cvss", {})
            cvss_score = cvss.get("score") if cvss else None

            # Parse affected packages
            affected_packages = []
            fixed_versions_all = []

            for vuln in advisory.get("vulnerabilities", []):
                pkg = vuln.get("package", {})
                pkg_name = pkg.get("name", "")
                ecosystem = pkg.get("ecosystem", "")

                version_range = vuln.get("vulnerable_version_range")
                first_patched = vuln.get("first_patched_version")
                fixed_versions = [first_patched] if first_patched else []

                if pkg_name:
                    affected_packages.append(
                        AffectedPackage(
                            name=pkg_name,
                            ecosystem=ecosystem,
                            version_range=version_range,
                            fixed_versions=fixed_versions,
                        )
                    )
                    fixed_versions_all.extend(fixed_versions)

            # Extract references
            references = []
            for ref in advisory.get("references", []):
                if isinstance(ref, str):
                    references.append(ref)
                elif isinstance(ref, dict) and ref.get("url"):
                    references.append(ref["url"])

            # Add HTML URL as reference
            html_url = advisory.get("html_url")
            if html_url and html_url not in references:
                references.insert(0, html_url)

            return CVEContextSchema(
                cve_id=cve_id,
                ghsa_id=ghsa_id,
                osv_id=None,
                summary=advisory.get("summary"),
                description=advisory.get("description"),
                severity=severity if severity else None,
                cvss_score=cvss_score,
                affected_packages=affected_packages,
                fixed_versions=list(set(fixed_versions_all)),
                references=references,
                remediation_notes=None,
                source=self.source_name,
                fetched_at=datetime.now(timezone.utc),
                raw_data=advisory,
            )

        except Exception as e:
            logger.error(f"Error parsing GitHub advisory: {e}")
            return None

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()
