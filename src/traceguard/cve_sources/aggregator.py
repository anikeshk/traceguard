"""CVE source aggregator that combines multiple CVE sources."""

import logging
from typing import Optional

from traceguard.cve_sources.base import CVESource
from traceguard.schemas.cve import CVEContextSchema

logger = logging.getLogger(__name__)


class CVESourceAggregator:
    """Aggregates multiple CVE sources and provides a unified interface.

    Queries sources in order of priority and returns the first successful result.
    Can also merge results from multiple sources for enrichment.
    """

    def __init__(self, sources: list[CVESource]):
        """Initialize the aggregator with a list of CVE sources.

        Args:
            sources: List of CVE sources in priority order.
        """
        self._sources = sources

    async def fetch_by_cve_id(
        self, cve_id: str, merge: bool = False
    ) -> Optional[CVEContextSchema]:
        """Fetch CVE context by CVE identifier from available sources.

        Args:
            cve_id: The CVE identifier to look up.
            merge: If True, merge results from all sources. Otherwise, return first match.

        Returns:
            CVEContextSchema if found, None otherwise.
        """
        if not self._sources:
            logger.warning("No CVE sources configured")
            return None

        results: list[CVEContextSchema] = []

        for source in self._sources:
            try:
                result = await source.fetch_by_cve_id(cve_id)
                if result:
                    if not merge:
                        return result
                    results.append(result)
            except Exception as e:
                logger.error(f"Error fetching {cve_id} from {source.source_name}: {e}")
                continue

        if not results:
            return None

        if len(results) == 1:
            return results[0]

        # Merge results if multiple sources returned data
        return self._merge_results(results)

    async def fetch_by_ghsa_id(
        self, ghsa_id: str, merge: bool = False
    ) -> Optional[CVEContextSchema]:
        """Fetch CVE context by GitHub Security Advisory ID.

        Args:
            ghsa_id: The GHSA identifier to look up.
            merge: If True, merge results from all sources.

        Returns:
            CVEContextSchema if found, None otherwise.
        """
        if not self._sources:
            return None

        results: list[CVEContextSchema] = []

        for source in self._sources:
            try:
                result = await source.fetch_by_ghsa_id(ghsa_id)
                if result:
                    if not merge:
                        return result
                    results.append(result)
            except Exception as e:
                logger.error(f"Error fetching {ghsa_id} from {source.source_name}: {e}")
                continue

        if not results:
            return None

        if len(results) == 1:
            return results[0]

        return self._merge_results(results)

    async def fetch_by_package(
        self,
        package_name: str,
        ecosystem: str,
        version: Optional[str] = None,
    ) -> list[CVEContextSchema]:
        """Fetch all CVEs affecting a specific package from all sources.

        Args:
            package_name: Name of the package.
            ecosystem: Package ecosystem (e.g., 'npm', 'PyPI').
            version: Optional specific version to check.

        Returns:
            List of CVEContextSchema objects for matching CVEs.
        """
        all_results: dict[str, CVEContextSchema] = {}

        for source in self._sources:
            try:
                results = await source.fetch_by_package(package_name, ecosystem, version)
                for result in results:
                    # Use CVE ID as key to deduplicate
                    if result.cve_id not in all_results:
                        all_results[result.cve_id] = result
                    else:
                        # Merge with existing result
                        all_results[result.cve_id] = self._merge_results(
                            [all_results[result.cve_id], result]
                        )
            except Exception as e:
                logger.error(
                    f"Error fetching {package_name} from {source.source_name}: {e}"
                )
                continue

        return list(all_results.values())

    def _merge_results(self, results: list[CVEContextSchema]) -> CVEContextSchema:
        """Merge multiple CVE contexts into one, preferring more complete data.

        Args:
            results: List of CVEContextSchema objects to merge.

        Returns:
            Merged CVEContextSchema.
        """
        if len(results) == 1:
            return results[0]

        # Start with the first result as base
        base = results[0]

        # Collect all unique data
        all_affected = []
        all_fixed = set()
        all_refs = set()
        sources = []

        for result in results:
            sources.append(result.source)

            # Merge affected packages (dedupe by name+ecosystem)
            seen_packages = {(p.name, p.ecosystem) for p in all_affected}
            for pkg in result.affected_packages:
                key = (pkg.name, pkg.ecosystem)
                if key not in seen_packages:
                    all_affected.append(pkg)
                    seen_packages.add(key)

            # Merge fixed versions
            all_fixed.update(result.fixed_versions)

            # Merge references
            all_refs.update(result.references)

        # Prefer non-None values, choosing from results in order
        cve_id = base.cve_id
        ghsa_id = next((r.ghsa_id for r in results if r.ghsa_id), None)
        osv_id = next((r.osv_id for r in results if r.osv_id), None)
        summary = next((r.summary for r in results if r.summary), None)
        description = next((r.description for r in results if r.description), None)
        severity = next((r.severity for r in results if r.severity), None)
        cvss_score = next((r.cvss_score for r in results if r.cvss_score), None)
        remediation_notes = next(
            (r.remediation_notes for r in results if r.remediation_notes), None
        )

        return CVEContextSchema(
            cve_id=cve_id,
            ghsa_id=ghsa_id,
            osv_id=osv_id,
            summary=summary,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            affected_packages=all_affected,
            fixed_versions=list(all_fixed),
            references=list(all_refs),
            remediation_notes=remediation_notes,
            source="+".join(sources),
            fetched_at=base.fetched_at,
            raw_data=None,  # Don't merge raw data
        )

    async def close(self) -> None:
        """Close all CVE sources."""
        for source in self._sources:
            try:
                await source.close()
            except Exception as e:
                logger.error(f"Error closing source {source.source_name}: {e}")
