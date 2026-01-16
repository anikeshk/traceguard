"""Dependency Usage Detection Agent.

Uses static analysis to find evidence of package usage in the codebase.
"""

import logging
from pathlib import Path
from typing import Any

from traceguard.agents.base import BaseAgent
from traceguard.agents.state import PipelineState
from traceguard.analyzers import JavaScriptAnalyzer

logger = logging.getLogger(__name__)


class DependencyUsageAgent(BaseAgent):
    """Agent that detects dependency usage in the codebase.

    Uses Tree-sitter based static analysis to:
    1. Find import/require statements for affected packages
    2. Determine if the CVE is applicable based on usage
    3. Collect file-level evidence of usage
    """

    def __init__(self):
        """Initialize the Dependency Usage Agent."""
        self._js_analyzer = JavaScriptAnalyzer()

    @property
    def agent_name(self) -> str:
        return "dependency_usage"

    @property
    def description(self) -> str:
        return "Detects package usage in codebase using static analysis"

    @property
    def step_order(self) -> int:
        return 2

    def validate_inputs(self, state: PipelineState) -> list[str]:
        """Validate required inputs."""
        errors = []
        if not state.get("cve_context"):
            errors.append("cve_context is required (CVE Context Agent must run first)")
        if not state.get("codebase_path"):
            errors.append("codebase_path is required")
        return errors

    def should_skip(self, state: PipelineState) -> bool:
        """Skip if CVE context fetch failed."""
        return bool(state.get("cve_context_error"))

    async def execute(self, state: PipelineState) -> dict[str, Any]:
        """Analyze codebase for package usage.

        Args:
            state: Current pipeline state with cve_context and codebase_path.

        Returns:
            State updates with usage_evidence and applicability determination.
        """
        codebase_path = Path(state["codebase_path"])
        cve_context = state["cve_context"]
        cve_id = state["cve_id"]

        if not codebase_path.exists():
            error_msg = f"Codebase path does not exist: {codebase_path}"
            logger.error(error_msg)
            return {
                "is_applicable": None,
                "applicability_reason": error_msg,
                "current_step": "dependency_usage_failed",
                "errors": [error_msg],
            }

        affected_packages = cve_context.get("affected_packages", [])
        if not affected_packages:
            return {
                "is_applicable": False,
                "applicability_reason": "No affected packages listed in CVE context",
                "usage_evidence": [],
                "current_step": "dependency_usage_complete",
            }

        logger.info(f"Analyzing {len(affected_packages)} affected packages for {cve_id}")

        all_evidence = []
        packages_found = []

        for pkg_info in affected_packages:
            package_name = pkg_info.get("name", "")
            ecosystem = pkg_info.get("ecosystem", "")

            if not package_name:
                continue

            # Select analyzer based on ecosystem
            if self._js_analyzer.supports_ecosystem(ecosystem):
                analyzer = self._js_analyzer
            else:
                logger.warning(f"No analyzer available for ecosystem: {ecosystem}")
                continue

            logger.info(f"Scanning for {package_name} ({ecosystem}) usage")

            # Find package usage
            evidence = await analyzer.find_package_usage(
                codebase_path, package_name, ecosystem
            )

            if evidence:
                packages_found.append(package_name)
                for e in evidence:
                    all_evidence.append(e.model_dump())

            # Get installed version
            installed_version = await analyzer.get_installed_version(
                codebase_path, package_name, ecosystem
            )
            if installed_version:
                logger.info(f"Found installed version of {package_name}: {installed_version}")

        # Determine applicability
        if all_evidence:
            is_applicable = True
            reason = (
                f"Found {len(all_evidence)} usage(s) of affected package(s) "
                f"({', '.join(packages_found)}) in the codebase"
            )
            logger.info(f"{cve_id} is APPLICABLE: {reason}")
        else:
            is_applicable = False
            package_names = [p.get("name", "unknown") for p in affected_packages]
            reason = (
                f"No usage of affected package(s) ({', '.join(package_names)}) "
                f"found in the codebase"
            )
            logger.info(f"{cve_id} is NOT APPLICABLE: {reason}")

        return {
            "usage_evidence": all_evidence,
            "is_applicable": is_applicable,
            "applicability_reason": reason,
            "installed_version": installed_version if packages_found else None,
            "current_step": "dependency_usage_complete",
        }
