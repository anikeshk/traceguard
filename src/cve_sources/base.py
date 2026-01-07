"""Base class for CVE data sources."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class CVEData:
    """Standardized CVE data from any source."""

    id: str
    title: str | None = None
    description: str = ""
    severity: str = "unknown"
    cvss_score: float | None = None
    cvss_vector: str | None = None
    source: str = ""
    source_url: str | None = None
    published_at: datetime | None = None
    modified_at: datetime | None = None
    affected_packages: list[str] = field(default_factory=list)
    affected_versions: dict[str, list[str]] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)


class CVESource(ABC):
    """Abstract base class for CVE data sources."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the name of this CVE source."""
        pass

    @abstractmethod
    async def fetch_cves(
        self,
        keywords: list[str] | None = None,
        package_name: str | None = None,
        ecosystem: str | None = None,
        since: datetime | None = None,
        limit: int = 100,
    ) -> list[CVEData]:
        """
        Fetch CVEs from this source.

        Args:
            keywords: Search keywords
            package_name: Filter by affected package name
            ecosystem: Filter by ecosystem (e.g., "pypi", "npm")
            since: Only return CVEs modified after this date
            limit: Maximum number of CVEs to return

        Returns:
            List of CVEData objects
        """
        pass

    @abstractmethod
    async def get_cve(self, cve_id: str) -> CVEData | None:
        """
        Get a specific CVE by ID.

        Args:
            cve_id: The CVE ID (e.g., "CVE-2024-1234")

        Returns:
            CVEData if found, None otherwise
        """
        pass

    def _normalize_severity(self, cvss_score: float | None) -> str:
        """Normalize CVSS score to severity level."""
        if cvss_score is None:
            return "unknown"
        if cvss_score >= 9.0:
            return "critical"
        if cvss_score >= 7.0:
            return "high"
        if cvss_score >= 4.0:
            return "medium"
        if cvss_score > 0:
            return "low"
        return "unknown"
