"""CODEOWNERS file parser and ownership resolution."""

import logging
from pathlib import Path
from typing import Optional

from codeowners import CodeOwners

from traceguard.core.exceptions import CodeOwnersNotFoundError
from traceguard.schemas.analysis import ResolvedOwnerSchema

logger = logging.getLogger(__name__)

# Common locations for CODEOWNERS file
CODEOWNERS_LOCATIONS = [
    "CODEOWNERS",
    ".github/CODEOWNERS",
    "docs/CODEOWNERS",
]


class CodeOwnersParser:
    """Parser for GitHub CODEOWNERS files.

    Resolves file ownership based on CODEOWNERS patterns.
    """

    def __init__(self, codebase_path: Path):
        """Initialize the parser.

        Args:
            codebase_path: Path to the codebase root directory.
        """
        self._codebase_path = Path(codebase_path)
        self._codeowners: Optional[CodeOwners] = None
        self._codeowners_path: Optional[Path] = None

    def find_codeowners_file(self) -> Optional[Path]:
        """Find the CODEOWNERS file in the repository.

        Returns:
            Path to CODEOWNERS file if found, None otherwise.
        """
        for location in CODEOWNERS_LOCATIONS:
            path = self._codebase_path / location
            if path.exists() and path.is_file():
                self._codeowners_path = path
                return path

        return None

    def load(self) -> bool:
        """Load and parse the CODEOWNERS file.

        Returns:
            True if loaded successfully, False otherwise.

        Raises:
            CodeOwnersNotFoundError: If CODEOWNERS file is not found.
        """
        codeowners_path = self.find_codeowners_file()
        if not codeowners_path:
            raise CodeOwnersNotFoundError(str(self._codebase_path))

        try:
            content = codeowners_path.read_text()
            self._codeowners = CodeOwners(content)
            logger.info(f"Loaded CODEOWNERS from {codeowners_path}")
            return True
        except Exception as e:
            logger.error(f"Error parsing CODEOWNERS: {e}")
            return False

    def get_owners(self, file_path: str) -> list[ResolvedOwnerSchema]:
        """Get owners for a specific file path.

        Args:
            file_path: Path to the file relative to the codebase root.

        Returns:
            List of resolved owners for the file.
        """
        if not self._codeowners:
            return []

        # Normalize the path
        file_path = file_path.lstrip("/").lstrip("\\")

        # Get owners from codeowners library
        owners = self._codeowners.of(file_path)

        if not owners:
            return []

        resolved = []
        for owner_tuple in owners:
            # The codeowners library returns tuples of (pattern, [owners])
            # We flatten this to individual owner entries
            pattern, owner_list = owner_tuple if isinstance(owner_tuple, tuple) else (None, [owner_tuple])

            if isinstance(owner_list, str):
                owner_list = [owner_list]

            for owner in owner_list:
                if not owner:
                    continue

                # Determine owner type
                owner_type = "team" if owner.startswith("@") and "/" in owner else "user"

                resolved.append(
                    ResolvedOwnerSchema(
                        file_path=file_path,
                        owner=owner,
                        owner_type=owner_type,
                        reasoning=f"Matched CODEOWNERS pattern: {pattern}" if pattern else None,
                    )
                )

        return resolved

    def resolve_owners_for_files(
        self, file_paths: list[str]
    ) -> dict[str, list[ResolvedOwnerSchema]]:
        """Resolve owners for multiple files.

        Args:
            file_paths: List of file paths to resolve.

        Returns:
            Dictionary mapping file paths to their owners.
        """
        results: dict[str, list[ResolvedOwnerSchema]] = {}

        for file_path in file_paths:
            owners = self.get_owners(file_path)
            results[file_path] = owners

        return results

    def get_unique_owners(
        self, file_paths: list[str]
    ) -> list[ResolvedOwnerSchema]:
        """Get deduplicated list of owners for multiple files.

        Args:
            file_paths: List of file paths to resolve.

        Returns:
            Deduplicated list of owners across all files.
        """
        all_owners: dict[str, ResolvedOwnerSchema] = {}

        for file_path in file_paths:
            owners = self.get_owners(file_path)
            for owner in owners:
                # Use owner name as key for deduplication
                if owner.owner not in all_owners:
                    all_owners[owner.owner] = owner

        return list(all_owners.values())

    @property
    def codeowners_path(self) -> Optional[Path]:
        """Get the path to the loaded CODEOWNERS file."""
        return self._codeowners_path
