"""Abstract base class for CVE data sources."""

from abc import ABC, abstractmethod
from typing import Optional

from traceguard.schemas.cve import CVEContextSchema


class CVESource(ABC):
    """Abstract base class for CVE data sources.

    Implementations should fetch CVE information from external sources
    like OSV, GitHub Security Advisories, or NVD.
    """

    @property
    @abstractmethod
    def source_name(self) -> str:
        """Get the identifier for this CVE source."""
        pass

    @abstractmethod
    async def fetch_by_cve_id(self, cve_id: str) -> Optional[CVEContextSchema]:
        """Fetch CVE context by CVE identifier (e.g., CVE-2021-44228).

        Args:
            cve_id: The CVE identifier to look up.

        Returns:
            CVEContextSchema if found, None otherwise.
        """
        pass

    @abstractmethod
    async def fetch_by_ghsa_id(self, ghsa_id: str) -> Optional[CVEContextSchema]:
        """Fetch CVE context by GitHub Security Advisory ID.

        Args:
            ghsa_id: The GHSA identifier to look up (e.g., GHSA-xxxx-xxxx-xxxx).

        Returns:
            CVEContextSchema if found, None otherwise.
        """
        pass

    @abstractmethod
    async def fetch_by_package(
        self,
        package_name: str,
        ecosystem: str,
        version: Optional[str] = None,
    ) -> list[CVEContextSchema]:
        """Fetch all CVEs affecting a specific package.

        Args:
            package_name: Name of the package.
            ecosystem: Package ecosystem (e.g., 'npm', 'PyPI').
            version: Optional specific version to check.

        Returns:
            List of CVEContextSchema objects for matching CVEs.
        """
        pass

    async def close(self) -> None:
        """Clean up any resources used by this source.

        Override this method if the source uses resources that need cleanup.
        """
        pass
