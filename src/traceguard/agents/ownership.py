"""Ownership Resolution Agent.

Resolves file ownership from CODEOWNERS file.
"""

import logging
from pathlib import Path
from typing import Any

from traceguard.agents.base import BaseAgent
from traceguard.agents.state import PipelineState
from traceguard.analyzers import CodeOwnersParser
from traceguard.core.exceptions import CodeOwnersNotFoundError

logger = logging.getLogger(__name__)


class OwnershipAgent(BaseAgent):
    """Agent that resolves ownership from CODEOWNERS file.

    This agent:
    1. Parses the CODEOWNERS file in the repository
    2. Maps affected file paths to responsible owners
    3. Returns a deduplicated list of owners for assignment
    """

    @property
    def agent_name(self) -> str:
        return "ownership"

    @property
    def description(self) -> str:
        return "Resolves file ownership from CODEOWNERS"

    @property
    def step_order(self) -> int:
        return 3

    def validate_inputs(self, state: PipelineState) -> list[str]:
        """Validate required inputs."""
        errors = []
        if not state.get("codebase_path"):
            errors.append("codebase_path is required")
        return errors

    def should_skip(self, state: PipelineState) -> bool:
        """Skip if CVE is not applicable or previous step failed."""
        # Skip if not applicable
        if state.get("is_applicable") is False:
            return True
        # Skip if there was a context error
        if state.get("cve_context_error"):
            return True
        return False

    async def execute(self, state: PipelineState) -> dict[str, Any]:
        """Resolve ownership for affected files.

        Args:
            state: Current pipeline state with codebase_path and usage_evidence.

        Returns:
            State updates with owners or ownership_error.
        """
        codebase_path = Path(state["codebase_path"])
        usage_evidence = state.get("usage_evidence", [])

        logger.info(f"Resolving ownership for {len(usage_evidence)} affected files")

        # Initialize parser
        parser = CodeOwnersParser(codebase_path)

        try:
            # Load CODEOWNERS file
            parser.load()
        except CodeOwnersNotFoundError:
            error_msg = f"CODEOWNERS file not found in {codebase_path}"
            logger.warning(error_msg)
            return {
                "owners": [],
                "ownership_error": error_msg,
                "current_step": "ownership_failed",
                "errors": [error_msg],
            }
        except Exception as e:
            error_msg = f"Error loading CODEOWNERS: {str(e)}"
            logger.error(error_msg)
            return {
                "owners": [],
                "ownership_error": error_msg,
                "current_step": "ownership_failed",
                "errors": [error_msg],
            }

        # Extract unique file paths from usage evidence
        affected_files = list(set(e.get("file_path", "") for e in usage_evidence if e.get("file_path")))

        if not affected_files:
            logger.info("No affected files to resolve ownership for")
            return {
                "owners": [],
                "ownership_error": None,
                "current_step": "ownership_complete",
            }

        # Make paths relative to codebase
        relative_files = []
        for file_path in affected_files:
            try:
                path = Path(file_path)
                if path.is_absolute():
                    path = path.relative_to(codebase_path)
                relative_files.append(str(path))
            except ValueError:
                # Path is not relative to codebase, use as-is
                relative_files.append(file_path)

        # Get unique owners across all affected files
        unique_owners = parser.get_unique_owners(relative_files)

        if not unique_owners:
            error_msg = f"No owners found for affected files: {relative_files}"
            logger.warning(error_msg)
            return {
                "owners": [],
                "ownership_error": error_msg,
                "current_step": "ownership_failed",
                "errors": [error_msg],
            }

        # Also get per-file ownership for detailed reporting
        file_owners = parser.resolve_owners_for_files(relative_files)

        # Convert to serializable format
        owners_data = [owner.model_dump() for owner in unique_owners]

        logger.info(f"Resolved {len(unique_owners)} unique owner(s) for affected files")
        for owner in unique_owners:
            logger.info(f"  - {owner.owner} ({owner.owner_type})")

        return {
            "owners": owners_data,
            "ownership_error": None,
            "current_step": "ownership_complete",
        }
