"""CVE aggregator that combines data from multiple sources."""

import asyncio
import logging
from datetime import datetime

from src.cve_sources.base import CVEData, CVESource
from src.cve_sources.github_advisory import GitHubAdvisorySource
from src.cve_sources.nvd import NVDSource
from src.cve_sources.osv import OSVSource

logger = logging.getLogger(__name__)


class CVEAggregator:
    """Aggregates CVE data from multiple sources."""

    def __init__(
        self,
        sources: list[CVESource] | None = None,
    ) -> None:
        """
        Initialize the aggregator.

        Args:
            sources: List of CVE sources to use. If None, uses all available sources.
        """
        if sources is None:
            sources = [
                # NVDSource(),  # Disabled: requires API key for reasonable rate limits
                OSVSource(),
                # GitHubAdvisorySource(),  # Disabled: requires GitHub token
            ]
        self.sources = sources

    async def fetch_cves(
        self,
        keywords: list[str] | None = None,
        package_name: str | None = None,
        ecosystem: str | None = None,
        since: datetime | None = None,
        limit: int = 100,
    ) -> list[CVEData]:
        """
        Fetch and deduplicate CVEs from all sources.

        Args:
            keywords: Search keywords
            package_name: Filter by affected package name
            ecosystem: Filter by ecosystem (e.g., "pypi", "npm")
            since: Only return CVEs modified after this date
            limit: Maximum number of CVEs to return per source

        Returns:
            Deduplicated list of CVEData objects
        """
        # Fetch from all sources concurrently
        tasks = [
            source.fetch_cves(
                keywords=keywords,
                package_name=package_name,
                ecosystem=ecosystem,
                since=since,
                limit=limit,
            )
            for source in self.sources
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect and deduplicate CVEs
        cves_by_id: dict[str, CVEData] = {}

        for result, source in zip(results, self.sources):
            if isinstance(result, Exception):
                logger.error(f"Error fetching from {source.name}: {result}")
                continue

            for cve in result:
                existing = cves_by_id.get(cve.id)
                if existing is None:
                    cves_by_id[cve.id] = cve
                else:
                    # Merge data from multiple sources
                    cves_by_id[cve.id] = self._merge_cves(existing, cve)

        # Sort by severity and modification date
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
        cves = sorted(
            cves_by_id.values(),
            key=lambda c: (
                severity_order.get(c.severity, 5),
                -(c.modified_at or c.published_at or datetime.min).timestamp(),
            ),
        )

        return cves

    async def get_cve(self, cve_id: str) -> CVEData | None:
        """
        Get a specific CVE from any source.

        Tries each source until the CVE is found, then enriches with other sources.
        """
        cve: CVEData | None = None

        # Try each source
        for source in self.sources:
            try:
                result = await source.get_cve(cve_id)
                if result:
                    if cve is None:
                        cve = result
                    else:
                        cve = self._merge_cves(cve, result)
            except Exception as e:
                logger.error(f"Error fetching {cve_id} from {source.name}: {e}")

        return cve

    async def query_packages(
        self,
        packages: list[tuple[str, str | None, str]],
    ) -> list[CVEData]:
        """
        Query CVEs for multiple packages.

        Args:
            packages: List of (package_name, version, ecosystem) tuples

        Returns:
            List of CVEs affecting any of the specified packages
        """
        all_cves: dict[str, CVEData] = {}

        # Query OSV for each package (most efficient for package queries)
        osv = next((s for s in self.sources if isinstance(s, OSVSource)), OSVSource())

        tasks = []
        for name, version, ecosystem in packages:
            tasks.append(osv.query_by_package(name, version, ecosystem))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Error querying packages: {result}")
                continue

            for cve in result:
                if cve.id not in all_cves:
                    all_cves[cve.id] = cve

        return list(all_cves.values())

    def _merge_cves(self, existing: CVEData, new: CVEData) -> CVEData:
        """Merge CVE data from multiple sources, preferring more complete data."""
        # Prefer higher CVSS score (more conservative)
        cvss_score = existing.cvss_score
        cvss_vector = existing.cvss_vector
        if new.cvss_score and (not cvss_score or new.cvss_score > cvss_score):
            cvss_score = new.cvss_score
            cvss_vector = new.cvss_vector

        # Merge affected packages
        affected_packages = list(set(existing.affected_packages + new.affected_packages))

        # Merge affected versions
        affected_versions = dict(existing.affected_versions)
        for pkg, versions in new.affected_versions.items():
            if pkg in affected_versions:
                affected_versions[pkg] = list(set(affected_versions[pkg] + versions))
            else:
                affected_versions[pkg] = versions

        # Merge references
        references = list(set(existing.references + new.references))

        return CVEData(
            id=existing.id,
            title=existing.title or new.title,
            description=existing.description or new.description,
            severity=existing.severity if existing.severity != "unknown" else new.severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            source=f"{existing.source},{new.source}",
            source_url=existing.source_url or new.source_url,
            published_at=existing.published_at or new.published_at,
            modified_at=max(
                filter(None, [existing.modified_at, new.modified_at]),
                default=None,
            ),
            affected_packages=affected_packages,
            affected_versions=affected_versions,
            references=references,
        )
