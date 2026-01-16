"""Abstract base class for dependency analyzers."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from traceguard.schemas.analysis import UsageEvidenceSchema


class DependencyAnalyzer(ABC):
    """Abstract base class for dependency usage analyzers.

    Implementations should scan codebases to find usage of specific packages.
    """

    @property
    @abstractmethod
    def supported_ecosystems(self) -> list[str]:
        """Get list of ecosystems this analyzer can handle.

        Returns:
            List of ecosystem names (e.g., ['npm', 'yarn']).
        """
        pass

    @abstractmethod
    async def find_package_usage(
        self,
        codebase_path: Path,
        package_name: str,
        ecosystem: str,
    ) -> list[UsageEvidenceSchema]:
        """Scan codebase for usage of the specified package.

        Args:
            codebase_path: Path to the codebase root directory.
            package_name: Name of the package to search for.
            ecosystem: Package ecosystem (e.g., 'npm', 'PyPI').

        Returns:
            List of UsageEvidenceSchema with file paths, line numbers, and usage types.
        """
        pass

    @abstractmethod
    async def get_installed_version(
        self,
        codebase_path: Path,
        package_name: str,
        ecosystem: str,
    ) -> Optional[str]:
        """Determine the installed version of a package from lockfiles.

        Args:
            codebase_path: Path to the codebase root directory.
            package_name: Name of the package.
            ecosystem: Package ecosystem.

        Returns:
            Version string if found, None otherwise.
        """
        pass

    def supports_ecosystem(self, ecosystem: str) -> bool:
        """Check if this analyzer supports the given ecosystem.

        Args:
            ecosystem: The ecosystem to check.

        Returns:
            True if supported, False otherwise.
        """
        return ecosystem.lower() in [e.lower() for e in self.supported_ecosystems]
