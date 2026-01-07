"""GitHub Security Advisory Database client."""

import logging
from datetime import datetime

import httpx

from src.config import get_settings
from src.cve_sources.base import CVEData, CVESource

logger = logging.getLogger(__name__)

GITHUB_GRAPHQL_API = "https://api.github.com/graphql"


class GitHubAdvisorySource(CVESource):
    """CVE source using the GitHub Security Advisory API."""

    def __init__(self) -> None:
        self.settings = get_settings()

    @property
    def name(self) -> str:
        return "github"

    async def fetch_cves(
        self,
        keywords: list[str] | None = None,
        package_name: str | None = None,
        ecosystem: str | None = None,
        since: datetime | None = None,
        limit: int = 100,
    ) -> list[CVEData]:
        """Fetch security advisories from GitHub."""
        if not self.settings.github_token:
            logger.warning("GitHub token not configured, skipping GitHub Advisory source")
            return []

        # Build GraphQL query
        query_parts = []
        if ecosystem:
            ecosystem_map = {
                "pypi": "PIP",
                "npm": "NPM",
                "go": "GO",
                "maven": "MAVEN",
                "nuget": "NUGET",
                "rubygems": "RUBYGEMS",
                "rust": "RUST",
            }
            gh_ecosystem = ecosystem_map.get(ecosystem.lower(), ecosystem.upper())
            query_parts.append(f"ecosystem:{gh_ecosystem}")

        if package_name:
            query_parts.append(f"package:{package_name}")

        if since:
            query_parts.append(f"updated:>{since.strftime('%Y-%m-%d')}")

        query_string = " ".join(query_parts) if query_parts else ""

        graphql_query = """
        query($query: String!, $first: Int!) {
            securityAdvisories(first: $first, orderBy: {field: UPDATED_AT, direction: DESC}, query: $query) {
                nodes {
                    ghsaId
                    summary
                    description
                    severity
                    cvss {
                        score
                        vectorString
                    }
                    identifiers {
                        type
                        value
                    }
                    references {
                        url
                    }
                    publishedAt
                    updatedAt
                    vulnerabilities(first: 25) {
                        nodes {
                            package {
                                ecosystem
                                name
                            }
                            vulnerableVersionRange
                            firstPatchedVersion {
                                identifier
                            }
                        }
                    }
                }
            }
        }
        """

        headers = {
            "Authorization": f"Bearer {self.settings.github_token}",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.post(
                    GITHUB_GRAPHQL_API,
                    json={
                        "query": graphql_query,
                        "variables": {"query": query_string, "first": min(limit, 100)},
                    },
                    headers=headers,
                )
                response.raise_for_status()
                data = response.json()
            except httpx.HTTPError as e:
                logger.error(f"GitHub API error: {e}")
                return []

        if "errors" in data:
            logger.error(f"GitHub GraphQL errors: {data['errors']}")
            return []

        advisories = data.get("data", {}).get("securityAdvisories", {}).get("nodes", [])
        return [
            cve for advisory in advisories
            if (cve := self._parse_advisory(advisory))
        ]

    async def get_cve(self, cve_id: str) -> CVEData | None:
        """Get a specific advisory by CVE or GHSA ID."""
        if not self.settings.github_token:
            logger.warning("GitHub token not configured")
            return None

        # Determine if it's a GHSA or CVE ID
        id_type = "GHSA" if cve_id.startswith("GHSA-") else "CVE"

        graphql_query = """
        query($id: String!) {
            securityAdvisory(ghsaId: $id) {
                ghsaId
                summary
                description
                severity
                cvss {
                    score
                    vectorString
                }
                identifiers {
                    type
                    value
                }
                references {
                    url
                }
                publishedAt
                updatedAt
                vulnerabilities(first: 25) {
                    nodes {
                        package {
                            ecosystem
                            name
                        }
                        vulnerableVersionRange
                        firstPatchedVersion {
                            identifier
                        }
                    }
                }
            }
        }
        """

        headers = {
            "Authorization": f"Bearer {self.settings.github_token}",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            # If it's a CVE, we need to search for it
            if id_type == "CVE":
                search_query = """
                query($query: String!) {
                    securityAdvisories(first: 1, query: $query) {
                        nodes {
                            ghsaId
                        }
                    }
                }
                """
                try:
                    response = await client.post(
                        GITHUB_GRAPHQL_API,
                        json={"query": search_query, "variables": {"query": cve_id}},
                        headers=headers,
                    )
                    response.raise_for_status()
                    data = response.json()
                    nodes = data.get("data", {}).get("securityAdvisories", {}).get("nodes", [])
                    if not nodes:
                        return None
                    ghsa_id = nodes[0].get("ghsaId")
                except httpx.HTTPError as e:
                    logger.error(f"GitHub API error searching for {cve_id}: {e}")
                    return None
            else:
                ghsa_id = cve_id

            try:
                response = await client.post(
                    GITHUB_GRAPHQL_API,
                    json={"query": graphql_query, "variables": {"id": ghsa_id}},
                    headers=headers,
                )
                response.raise_for_status()
                data = response.json()
            except httpx.HTTPError as e:
                logger.error(f"GitHub API error fetching {cve_id}: {e}")
                return None

        advisory = data.get("data", {}).get("securityAdvisory")
        if advisory:
            return self._parse_advisory(advisory)
        return None

    def _parse_advisory(self, advisory: dict) -> CVEData | None:
        """Parse GitHub advisory into CVEData."""
        ghsa_id = advisory.get("ghsaId")
        if not ghsa_id:
            return None

        # Get CVE ID from identifiers
        identifiers = advisory.get("identifiers", [])
        cve_id = next(
            (i["value"] for i in identifiers if i.get("type") == "CVE"),
            ghsa_id,
        )

        # Get CVSS
        cvss = advisory.get("cvss", {})
        cvss_score = cvss.get("score")
        cvss_vector = cvss.get("vectorString")

        # Get severity
        severity = advisory.get("severity", "").lower()
        if severity not in ["critical", "high", "medium", "low"]:
            severity = self._normalize_severity(cvss_score)

        # Get affected packages
        affected_packages: list[str] = []
        affected_versions: dict[str, list[str]] = {}

        for vuln in advisory.get("vulnerabilities", {}).get("nodes", []):
            pkg = vuln.get("package", {})
            pkg_name = pkg.get("name")
            if pkg_name and pkg_name not in affected_packages:
                affected_packages.append(pkg_name)

            version_range = vuln.get("vulnerableVersionRange")
            if version_range and pkg_name:
                affected_versions.setdefault(pkg_name, []).append(version_range)

        # Get references
        references = [
            ref.get("url") for ref in advisory.get("references", [])
            if ref.get("url")
        ]

        # Parse dates
        published_at = None
        modified_at = None
        if advisory.get("publishedAt"):
            try:
                published_at = datetime.fromisoformat(
                    advisory["publishedAt"].replace("Z", "+00:00")
                )
            except ValueError:
                pass
        if advisory.get("updatedAt"):
            try:
                modified_at = datetime.fromisoformat(
                    advisory["updatedAt"].replace("Z", "+00:00")
                )
            except ValueError:
                pass

        return CVEData(
            id=cve_id,
            title=advisory.get("summary"),
            description=advisory.get("description", ""),
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            source="github",
            source_url=f"https://github.com/advisories/{ghsa_id}",
            published_at=published_at,
            modified_at=modified_at,
            affected_packages=affected_packages,
            affected_versions=affected_versions,
            references=references,
        )
