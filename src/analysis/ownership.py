"""Ownership resolution using CODEOWNERS and git blame."""

import logging
import re
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

import git

logger = logging.getLogger(__name__)


@dataclass
class Owner:
    """Represents a code owner."""

    identifier: str  # Email, username, or team name
    source: str  # "codeowners" or "git_blame"
    file_path: str | None = None
    confidence: float = 1.0


@dataclass
class OwnershipResult:
    """Result of ownership resolution."""

    owners: list[Owner] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class OwnershipResolver:
    """Resolves code ownership from CODEOWNERS and git blame."""

    # Possible CODEOWNERS file locations
    CODEOWNERS_PATHS = [
        "CODEOWNERS",
        ".github/CODEOWNERS",
        "docs/CODEOWNERS",
    ]

    def __init__(self, codebase_path: str | Path) -> None:
        self.codebase_path = Path(codebase_path)
        self._codeowners_rules: list[tuple[str, list[str]]] | None = None
        self._repo: git.Repo | None = None

    def _load_codeowners(self) -> list[tuple[str, list[str]]]:
        """Load and parse CODEOWNERS file."""
        if self._codeowners_rules is not None:
            return self._codeowners_rules

        self._codeowners_rules = []

        for codeowners_path in self.CODEOWNERS_PATHS:
            full_path = self.codebase_path / codeowners_path
            if full_path.exists():
                content = full_path.read_text(encoding="utf-8", errors="ignore")
                self._codeowners_rules = self._parse_codeowners(content)
                logger.info(f"Loaded CODEOWNERS from {full_path}")
                break

        return self._codeowners_rules

    def _parse_codeowners(self, content: str) -> list[tuple[str, list[str]]]:
        """Parse CODEOWNERS file content."""
        rules = []

        for line in content.splitlines():
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue

            # Split pattern and owners
            parts = line.split()
            if len(parts) >= 2:
                pattern = parts[0]
                owners = [o for o in parts[1:] if o.startswith("@") or "@" in o]
                if owners:
                    rules.append((pattern, owners))

        # Rules are applied in order, last match wins
        return rules

    def _get_repo(self) -> git.Repo | None:
        """Get git repository object."""
        if self._repo is not None:
            return self._repo

        try:
            self._repo = git.Repo(self.codebase_path, search_parent_directories=True)
        except git.InvalidGitRepositoryError:
            logger.warning(f"No git repository found at {self.codebase_path}")
            self._repo = None

        return self._repo

    async def resolve_owners(
        self,
        file_paths: list[str],
        use_git_blame: bool = True,
    ) -> OwnershipResult:
        """
        Resolve owners for a list of files.

        Uses CODEOWNERS first, falls back to git blame.
        """
        result = OwnershipResult()

        for file_path in file_paths:
            # Try CODEOWNERS first
            codeowners = self.get_codeowners_for_file(file_path)
            for owner in codeowners:
                result.owners.append(
                    Owner(
                        identifier=owner,
                        source="codeowners",
                        file_path=file_path,
                        confidence=1.0,
                    )
                )

            # Fall back to git blame if no CODEOWNERS match
            if not codeowners and use_git_blame:
                try:
                    blame_owners = await self.get_git_blame_owners(file_path)
                    result.owners.extend(blame_owners)
                except Exception as e:
                    error = f"Error getting git blame for {file_path}: {e}"
                    logger.warning(error)
                    result.errors.append(error)

        # Deduplicate and sort by confidence
        unique_owners: dict[str, Owner] = {}
        for owner in result.owners:
            key = owner.identifier.lower()
            if key not in unique_owners or owner.confidence > unique_owners[key].confidence:
                unique_owners[key] = owner

        result.owners = sorted(
            unique_owners.values(),
            key=lambda o: (-o.confidence, o.identifier),
        )

        return result

    def get_codeowners_for_file(self, file_path: str) -> list[str]:
        """Get owners from CODEOWNERS for a specific file."""
        rules = self._load_codeowners()
        if not rules:
            return []

        # Normalize file path (relative to repo root)
        rel_path = file_path
        try:
            rel_path = str(Path(file_path).relative_to(self.codebase_path))
        except ValueError:
            pass

        # Apply rules in order (last match wins)
        matching_owners: list[str] = []

        for pattern, owners in rules:
            if self._matches_pattern(rel_path, pattern):
                matching_owners = owners

        return matching_owners

    def _matches_pattern(self, file_path: str, pattern: str) -> bool:
        """Check if file matches CODEOWNERS pattern."""
        # Normalize paths
        file_path = file_path.replace("\\", "/")
        pattern = pattern.lstrip("/")

        # Handle ** patterns
        if pattern.startswith("**/"):
            # Match at any level
            pattern_suffix = pattern[3:]
            return (
                fnmatch(file_path, pattern_suffix)
                or fnmatch(file_path, f"*/{pattern_suffix}")
                or fnmatch(file_path, f"**/{pattern_suffix}")
            )

        # Handle patterns ending with /
        if pattern.endswith("/"):
            return file_path.startswith(pattern) or fnmatch(file_path, f"{pattern}*")

        # Direct match or glob
        return fnmatch(file_path, pattern) or fnmatch(file_path, f"**/{pattern}")

    async def get_git_blame_owners(
        self,
        file_path: str,
        limit: int = 5,
    ) -> list[Owner]:
        """Get owners from git blame analysis."""
        repo = self._get_repo()
        if repo is None:
            return []

        try:
            rel_path = file_path
            try:
                rel_path = str(Path(file_path).relative_to(self.codebase_path))
            except ValueError:
                pass

            # Get blame info
            blame = repo.blame("HEAD", rel_path)
        except git.GitCommandError as e:
            logger.warning(f"Git blame failed for {file_path}: {e}")
            return []
        except Exception as e:
            logger.warning(f"Error getting git blame: {e}")
            return []

        # Count lines by author
        author_lines: dict[str, int] = {}
        total_lines = 0

        for commit, lines in blame:
            author = commit.author.email or commit.author.name
            if author:
                author_lines[author] = author_lines.get(author, 0) + len(lines)
                total_lines += len(lines)

        if total_lines == 0:
            return []

        # Convert to Owner objects with confidence based on line ownership
        owners = []
        sorted_authors = sorted(author_lines.items(), key=lambda x: -x[1])

        for author, line_count in sorted_authors[:limit]:
            confidence = line_count / total_lines
            owners.append(
                Owner(
                    identifier=author,
                    source="git_blame",
                    file_path=file_path,
                    confidence=round(confidence, 2),
                )
            )

        return owners

    async def get_recent_contributors(
        self,
        file_path: str,
        limit: int = 5,
    ) -> list[str]:
        """Get recent contributors to a file."""
        repo = self._get_repo()
        if repo is None:
            return []

        try:
            rel_path = file_path
            try:
                rel_path = str(Path(file_path).relative_to(self.codebase_path))
            except ValueError:
                pass

            # Get recent commits for this file
            commits = list(repo.iter_commits(paths=rel_path, max_count=20))
        except Exception as e:
            logger.warning(f"Error getting commits for {file_path}: {e}")
            return []

        # Get unique authors
        seen = set()
        authors = []
        for commit in commits:
            author = commit.author.email or commit.author.name
            if author and author not in seen:
                seen.add(author)
                authors.append(author)
                if len(authors) >= limit:
                    break

        return authors
