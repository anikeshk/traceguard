"""CVE Context Collection Agent.

Fetches CVE context from external sources and normalizes the data.
"""

import logging
from typing import Any

from traceguard.agents.base import BaseAgent
from traceguard.agents.state import PipelineState
from traceguard.cve_sources import CVESourceAggregator, GitHubAdvisoryClient, OSVClient

logger = logging.getLogger(__name__)


class CVEContextAgent(BaseAgent):
    """Agent that fetches and normalizes CVE context from multiple sources.

    This is typically the first agent in the pipeline. It:
    1. Fetches CVE data from GitHub Security Advisories
    2. Fetches CVE data from OSV (as fallback/enrichment)
    3. Normalizes and combines the data
    4. Stores the result in the pipeline state
    """

    def __init__(self):
        """Initialize the CVE Context Agent."""
        self._osv_client = OSVClient()
        self._github_client = GitHubAdvisoryClient()
        self._aggregator = CVESourceAggregator([
            self._github_client,
            self._osv_client,
        ])

    @property
    def agent_name(self) -> str:
        return "cve_context"

    @property
    def description(self) -> str:
        return "Fetches and normalizes CVE context from GitHub and OSV"

    @property
    def step_order(self) -> int:
        return 1

    def validate_inputs(self, state: PipelineState) -> list[str]:
        """Validate that cve_id is present."""
        errors = []
        if not state.get("cve_id"):
            errors.append("cve_id is required")
        return errors

    async def execute(self, state: PipelineState) -> dict[str, Any]:
        """Fetch CVE context from available sources.

        Args:
            state: Current pipeline state with cve_id.

        Returns:
            State updates with cve_context or cve_context_error.
        """
        cve_id = state["cve_id"]
        logger.info(f"Fetching CVE context for {cve_id}")

        try:
            # Try to fetch by CVE ID first
            context = await self._aggregator.fetch_by_cve_id(cve_id, merge=True)

            if not context:
                # If it looks like a GHSA ID, try that
                if cve_id.startswith("GHSA-"):
                    context = await self._aggregator.fetch_by_ghsa_id(cve_id, merge=True)

            if not context:
                error_msg = f"Could not find CVE context for {cve_id} in any source"
                logger.warning(error_msg)
                return {
                    "cve_context": None,
                    "cve_context_error": error_msg,
                    "current_step": "cve_context_failed",
                    "errors": [error_msg],
                }

            logger.info(
                f"Found CVE context for {cve_id} from {context.source}: "
                f"severity={context.severity}, packages={len(context.affected_packages)}"
            )

            return {
                "cve_context": context.model_dump(mode="json"),
                "cve_context_error": None,
                "current_step": "cve_context_complete",
            }

        except Exception as e:
            error_msg = f"Error fetching CVE context for {cve_id}: {str(e)}"
            logger.error(error_msg)
            return {
                "cve_context": None,
                "cve_context_error": error_msg,
                "current_step": "cve_context_failed",
                "errors": [error_msg],
            }

    async def close(self) -> None:
        """Clean up resources."""
        await self._aggregator.close()
