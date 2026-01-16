"""Ticket Generation Agent.

Generates GitHub issue content for CVE remediation.
"""

import logging
import urllib.parse
from typing import Any, Optional

from langchain_openai import ChatOpenAI

from traceguard.agents.base import BaseAgent
from traceguard.agents.state import PipelineState
from traceguard.config import get_settings

logger = logging.getLogger(__name__)


class TicketGenerationAgent(BaseAgent):
    """Agent that generates GitHub issue content for CVE remediation.

    This agent:
    1. Analyzes CVE context and usage evidence
    2. Uses AI to generate an impact assessment
    3. Creates a structured issue body with all relevant information
    4. Generates a GitHub issue creation URL with pre-filled content
    """

    def __init__(self, use_ai: bool = True):
        """Initialize the Ticket Generation Agent.

        Args:
            use_ai: Whether to use AI for impact assessment. Set to False for testing.
        """
        self._use_ai = use_ai
        settings = get_settings()
        if use_ai and settings.openai_api_key:
            self._llm = ChatOpenAI(
                api_key=settings.openai_api_key,
                model=settings.openai_model,
                temperature=0.3,
            )
        else:
            self._llm = None

    @property
    def agent_name(self) -> str:
        return "ticket_generation"

    @property
    def description(self) -> str:
        return "Generates GitHub issue content for CVE remediation"

    @property
    def step_order(self) -> int:
        return 4

    def validate_inputs(self, state: PipelineState) -> list[str]:
        """Validate required inputs."""
        errors = []
        if not state.get("cve_context"):
            errors.append("cve_context is required")
        return errors

    def should_skip(self, state: PipelineState) -> bool:
        """Skip if CVE is not applicable or previous steps failed."""
        if state.get("is_applicable") is False:
            return True
        if state.get("cve_context_error"):
            return True
        return False

    async def execute(self, state: PipelineState) -> dict[str, Any]:
        """Generate GitHub issue content.

        Args:
            state: Current pipeline state with CVE context and analysis results.

        Returns:
            State updates with generated issue title, body, and URL.
        """
        cve_context = state["cve_context"]
        cve_id = state["cve_id"]
        usage_evidence = state.get("usage_evidence", [])
        owners = state.get("owners", [])
        installed_version = state.get("installed_version")

        logger.info(f"Generating issue for {cve_id}")

        # Generate issue title
        severity = cve_context.get("severity", "").upper() or "UNKNOWN"
        summary = cve_context.get("summary", f"Security vulnerability {cve_id}")
        title = f"[{severity}] {cve_id}: {summary[:80]}"

        # Generate impact assessment using AI
        impact_assessment = await self._generate_impact_assessment(
            cve_context, usage_evidence, installed_version
        )

        # Build issue body
        body = self._build_issue_body(
            cve_context=cve_context,
            usage_evidence=usage_evidence,
            owners=owners,
            impact_assessment=impact_assessment,
            installed_version=installed_version,
        )

        # Generate GitHub issue URL
        github_url = self._generate_github_issue_url(
            title=title,
            body=body,
            labels=["security", f"severity:{severity.lower()}"],
            assignees=[o.get("owner", "").lstrip("@") for o in owners if o.get("owner_type") == "user"],
        )

        logger.info(f"Generated issue for {cve_id}: {title}")

        return {
            "generated_issue_title": title,
            "generated_issue_body": body,
            "github_issue_url": github_url,
            "current_step": "ticket_generation_complete",
        }

    async def _generate_impact_assessment(
        self,
        cve_context: dict,
        usage_evidence: list[dict],
        installed_version: Optional[str],
    ) -> str:
        """Generate an AI-powered impact assessment.

        Args:
            cve_context: CVE context data.
            usage_evidence: List of usage evidence.
            installed_version: Installed package version.

        Returns:
            Impact assessment text.
        """
        if not self._llm:
            # Fallback to template-based assessment
            return self._generate_template_assessment(
                cve_context, usage_evidence, installed_version
            )

        try:
            # Build prompt for AI
            affected_packages = cve_context.get("affected_packages", [])
            package_names = [p.get("name", "unknown") for p in affected_packages]

            prompt = f"""Analyze the following CVE and provide a brief impact assessment (2-3 sentences).

CVE ID: {cve_context.get('cve_id')}
Severity: {cve_context.get('severity', 'Unknown')}
CVSS Score: {cve_context.get('cvss_score', 'N/A')}

Description:
{cve_context.get('description', 'No description available')}

Affected Packages: {', '.join(package_names)}
Installed Version: {installed_version or 'Unknown'}
Files with Usage: {len(usage_evidence)}

Provide a concise impact assessment that:
1. Explains the potential risk to this codebase
2. Notes any mitigating factors
3. Provides a brief recommendation

Keep it to 2-3 sentences."""

            response = await self._llm.ainvoke(prompt)
            return response.content

        except Exception as e:
            logger.warning(f"AI impact assessment failed, using template: {e}")
            return self._generate_template_assessment(
                cve_context, usage_evidence, installed_version
            )

    def _generate_template_assessment(
        self,
        cve_context: dict,
        usage_evidence: list[dict],
        installed_version: Optional[str],
    ) -> str:
        """Generate a template-based impact assessment.

        Args:
            cve_context: CVE context data.
            usage_evidence: List of usage evidence.
            installed_version: Installed package version.

        Returns:
            Impact assessment text.
        """
        severity = cve_context.get("severity", "Unknown").upper()
        num_files = len(usage_evidence)
        fixed_versions = cve_context.get("fixed_versions", [])

        assessment = f"This {severity} severity vulnerability affects {num_files} file(s) in the codebase. "

        if fixed_versions:
            assessment += f"Update to version {fixed_versions[0]} or later to remediate. "
        else:
            assessment += "Review the CVE references for remediation guidance. "

        if installed_version:
            assessment += f"Currently installed version: {installed_version}."

        return assessment

    def _build_issue_body(
        self,
        cve_context: dict,
        usage_evidence: list[dict],
        owners: list[dict],
        impact_assessment: str,
        installed_version: Optional[str],
    ) -> str:
        """Build the GitHub issue body.

        Args:
            cve_context: CVE context data.
            usage_evidence: List of usage evidence.
            owners: List of resolved owners.
            impact_assessment: AI-generated impact assessment.
            installed_version: Installed package version.

        Returns:
            Formatted issue body as Markdown.
        """
        cve_id = cve_context.get("cve_id", "Unknown")
        severity = cve_context.get("severity", "Unknown").upper()
        cvss_score = cve_context.get("cvss_score")
        description = cve_context.get("description", "No description available")
        affected_packages = cve_context.get("affected_packages", [])
        fixed_versions = cve_context.get("fixed_versions", [])
        references = cve_context.get("references", [])

        body_parts = []

        # Header section
        body_parts.append("## Security Vulnerability Report\n")
        body_parts.append(f"**CVE ID:** {cve_id}  ")
        body_parts.append(f"**Severity:** {severity}")
        if cvss_score:
            body_parts.append(f" (CVSS: {cvss_score})")
        body_parts.append("\n")

        # Description
        body_parts.append("\n### Description\n")
        body_parts.append(description)
        body_parts.append("\n")

        # Impact Assessment
        body_parts.append("\n### Impact Assessment\n")
        body_parts.append(impact_assessment)
        body_parts.append("\n")

        # Affected Packages
        body_parts.append("\n### Affected Packages\n")
        for pkg in affected_packages:
            name = pkg.get("name", "Unknown")
            ecosystem = pkg.get("ecosystem", "Unknown")
            version_range = pkg.get("version_range", "All versions")
            body_parts.append(f"- **{name}** ({ecosystem}): {version_range}")
            if installed_version:
                body_parts.append(f" (Installed: {installed_version})")
            body_parts.append("\n")

        # Evidence of Usage
        if usage_evidence:
            body_parts.append("\n### Evidence of Usage\n")
            body_parts.append(f"Found {len(usage_evidence)} usage(s) in the codebase:\n")
            for evidence in usage_evidence[:10]:  # Limit to first 10
                file_path = evidence.get("file_path", "Unknown")
                line_num = evidence.get("line_number", "?")
                usage_type = evidence.get("usage_type", "usage")
                code = evidence.get("code_snippet", "")
                body_parts.append(f"\n**{file_path}:{line_num}** ({usage_type})\n")
                if code:
                    body_parts.append(f"```javascript\n{code}\n```\n")
            if len(usage_evidence) > 10:
                body_parts.append(f"\n_...and {len(usage_evidence) - 10} more occurrences_\n")

        # Recommended Fix
        body_parts.append("\n### Recommended Fix\n")
        if fixed_versions:
            body_parts.append(f"Update to one of the following fixed versions: **{', '.join(fixed_versions)}**\n")
        else:
            body_parts.append("No fixed version is currently available. Monitor the CVE for updates.\n")

        # Assigned Owners
        if owners:
            body_parts.append("\n### Assigned Owners\n")
            for owner in owners:
                owner_name = owner.get("owner", "Unknown")
                body_parts.append(f"- {owner_name}\n")

        # References
        if references:
            body_parts.append("\n### References\n")
            for ref in references[:5]:  # Limit to first 5
                body_parts.append(f"- {ref}\n")

        # Footer
        body_parts.append("\n---\n")
        body_parts.append("*Generated by TraceGuard CVE Triage*\n")

        return "".join(body_parts)

    def _generate_github_issue_url(
        self,
        title: str,
        body: str,
        labels: Optional[list[str]] = None,
        assignees: Optional[list[str]] = None,
    ) -> str:
        """Generate a GitHub issue creation URL with pre-filled content.

        Note: This generates a URL template. The actual repository URL
        needs to be prepended by the caller.

        Args:
            title: Issue title.
            body: Issue body.
            labels: List of labels to apply.
            assignees: List of usernames to assign.

        Returns:
            URL query string for GitHub issue creation.
        """
        params = {
            "title": title,
            "body": body,
        }

        if labels:
            params["labels"] = ",".join(labels)

        if assignees:
            params["assignees"] = ",".join(assignees)

        query_string = urllib.parse.urlencode(params)

        # Return just the query string - caller should prepend repo URL
        # e.g., https://github.com/owner/repo/issues/new?{query_string}
        return f"/issues/new?{query_string}"
