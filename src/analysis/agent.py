"""Agentic AI CVE triage system using OpenAI GPT."""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from openai import AsyncOpenAI

from src.analysis.code_scanner import CodeMatch, CodeScanner
from src.analysis.dependency_scanner import Dependency, DependencyScanner
from src.analysis.ownership import Owner, OwnershipResolver
from src.config import get_settings
from src.cve_sources.base import CVEData

logger = logging.getLogger(__name__)


@dataclass
class TriageContext:
    """Context gathered for CVE triage."""

    cve: CVEData
    codebase_path: str
    affected_dependencies: list[Dependency] = field(default_factory=list)
    code_matches: list[CodeMatch] = field(default_factory=list)
    owners: list[Owner] = field(default_factory=list)
    ecosystem: str = "pypi"


@dataclass
class TriageDecision:
    """Result of AI triage analysis."""

    cve_id: str
    is_affected: bool
    confidence: float  # 0.0 to 1.0
    reasoning: str
    severity_assessment: str
    priority_score: float  # 1-10, based on severity and applicability
    remediation: str
    affected_files: list[str] = field(default_factory=list)
    affected_dependencies: list[str] = field(default_factory=list)


class TriageAgent:
    """AI agent for CVE triage analysis."""

    SYSTEM_PROMPT = """You are an expert security analyst specializing in CVE triage and vulnerability assessment.

Your task is to analyze CVEs against a specific codebase to determine:
1. Whether the codebase is actually affected by the vulnerability
2. The severity and priority of the issue if affected
3. Recommended remediation steps

You will be provided with:
- CVE details (description, severity, affected packages/versions)
- Dependency information from the codebase
- Code matches showing where affected packages are used
- Ownership information for affected files

Analyze the information carefully and provide a thorough assessment. Be precise about whether the vulnerability actually applies - many CVEs have specific conditions that must be met.

Always respond in valid JSON format with the following structure:
{
    "is_affected": boolean,
    "confidence": number (0.0-1.0),
    "reasoning": "detailed explanation",
    "severity_assessment": "your assessment of actual severity in this context",
    "priority_score": number (1-10),
    "remediation": "specific remediation steps",
    "affected_files": ["list", "of", "files"],
    "notes": "any additional observations"
}"""

    def __init__(self) -> None:
        self.settings = get_settings()
        self.client = AsyncOpenAI(api_key=self.settings.openai_api_key)

    async def triage_cve(self, context: TriageContext) -> TriageDecision:
        """
        Perform AI-powered triage analysis of a CVE.

        This is the main entry point for CVE triage.
        """
        # Build the analysis prompt
        prompt = self._build_analysis_prompt(context)

        # Get AI analysis
        try:
            response = await self.client.chat.completions.create(
                model=self.settings.openai_model,
                messages=[
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,  # Lower temperature for more consistent analysis
                response_format={"type": "json_object"},
            )

            result = json.loads(response.choices[0].message.content)

        except Exception as e:
            logger.error(f"AI analysis failed for {context.cve.id}: {e}")
            # Return a conservative default
            return TriageDecision(
                cve_id=context.cve.id,
                is_affected=bool(context.affected_dependencies or context.code_matches),
                confidence=0.3,
                reasoning=f"AI analysis failed: {e}. Based on static analysis only.",
                severity_assessment=context.cve.severity,
                priority_score=5.0,
                remediation="Manual review required.",
                affected_files=[m.file_path for m in context.code_matches],
                affected_dependencies=[d.name for d in context.affected_dependencies],
            )

        return TriageDecision(
            cve_id=context.cve.id,
            is_affected=result.get("is_affected", False),
            confidence=float(result.get("confidence", 0.5)),
            reasoning=result.get("reasoning", ""),
            severity_assessment=result.get("severity_assessment", context.cve.severity),
            priority_score=float(result.get("priority_score", 5.0)),
            remediation=result.get("remediation", ""),
            affected_files=result.get("affected_files", []),
            affected_dependencies=[d.name for d in context.affected_dependencies],
        )

    def _build_analysis_prompt(self, context: TriageContext) -> str:
        """Build the analysis prompt with all context."""
        sections = []

        # CVE Information
        sections.append(f"""## CVE Information
- **ID**: {context.cve.id}
- **Title**: {context.cve.title or 'N/A'}
- **Severity**: {context.cve.severity.upper()} (CVSS: {context.cve.cvss_score or 'N/A'})
- **Published**: {context.cve.published_at or 'Unknown'}

### Description
{context.cve.description}

### Affected Packages
{', '.join(context.cve.affected_packages) or 'Not specified'}

### Affected Versions
{json.dumps(context.cve.affected_versions, indent=2) if context.cve.affected_versions else 'Not specified'}
""")

        # Dependency Matches
        if context.affected_dependencies:
            dep_info = "\n".join([
                f"- **{d.name}** (version: {d.version or 'unknown'}) in `{d.file_path}`"
                for d in context.affected_dependencies
            ])
            sections.append(f"""## Dependency Analysis
The following dependencies in this codebase match the affected packages:

{dep_info}
""")
        else:
            sections.append("""## Dependency Analysis
No matching dependencies found in the codebase.
""")

        # Code Matches
        if context.code_matches:
            code_info = []
            for match in context.code_matches[:10]:  # Limit to first 10
                code_info.append(
                    f"- `{match.file_path}:{match.line_number}` - {match.match_type}: "
                    f"`{match.line_content[:100]}`"
                )
            sections.append(f"""## Code Usage Analysis
The following code locations reference the affected packages:

{chr(10).join(code_info)}
""")
        else:
            sections.append("""## Code Usage Analysis
No direct code usage of affected packages found.
""")

        # Ownership
        if context.owners:
            owner_info = "\n".join([
                f"- {o.identifier} ({o.source}, confidence: {o.confidence})"
                for o in context.owners[:5]
            ])
            sections.append(f"""## Code Owners
{owner_info}
""")

        sections.append("""## Task
Analyze whether this codebase is affected by the CVE. Consider:
1. Are the affected packages actually used in dependencies?
2. Are the affected versions in use?
3. Is the vulnerable functionality actually called in the code?
4. What is the actual impact given how the package is used?

Provide your assessment in JSON format.
""")

        return "\n".join(sections)

    async def analyze_codebase(
        self,
        codebase_path: str | Path,
        cves: list[CVEData],
        ecosystem: str = "pypi",
        callback=None,
    ) -> list[TriageDecision]:
        """
        Analyze a codebase against multiple CVEs.

        Args:
            codebase_path: Path to the codebase
            cves: List of CVEs to check
            ecosystem: Package ecosystem
            callback: Optional async callback for progress updates

        Returns:
            List of triage decisions
        """
        codebase_path = Path(codebase_path)

        # Initialize scanners
        dep_scanner = DependencyScanner(codebase_path)
        code_scanner = CodeScanner(codebase_path)
        ownership_resolver = OwnershipResolver(codebase_path)

        # Scan dependencies once
        dep_result = await dep_scanner.scan()
        all_deps = dep_result.dependencies

        decisions = []

        for i, cve in enumerate(cves):
            if callback:
                await callback(i, len(cves), cve.id)

            # Find matching dependencies
            affected_deps = dep_scanner.find_vulnerable_dependencies(
                all_deps,
                cve.affected_packages,
            )

            # Scan for code usage of affected packages
            code_result = await code_scanner.scan_for_packages(
                cve.affected_packages,
                ecosystem=ecosystem,
            )

            # Resolve ownership for affected files
            affected_files = list(set(
                [d.file_path for d in affected_deps] +
                [m.file_path for m in code_result.matches]
            ))
            ownership_result = await ownership_resolver.resolve_owners(
                affected_files,
                use_git_blame=True,
            )

            # Build context
            context = TriageContext(
                cve=cve,
                codebase_path=str(codebase_path),
                affected_dependencies=affected_deps,
                code_matches=code_result.matches,
                owners=ownership_result.owners,
                ecosystem=ecosystem,
            )

            # Get AI triage decision
            decision = await self.triage_cve(context)
            decisions.append(decision)

        return decisions


class TriageOrchestrator:
    """Orchestrates the full triage pipeline."""

    def __init__(self) -> None:
        self.agent = TriageAgent()

    async def run_triage(
        self,
        codebase_path: str | Path,
        cves: list[CVEData],
        ecosystem: str = "pypi",
        progress_callback=None,
    ) -> list[TriageDecision]:
        """
        Run the complete triage pipeline.

        Args:
            codebase_path: Path to analyze
            cves: CVEs to check
            ecosystem: Package ecosystem
            progress_callback: Optional callback for progress updates

        Returns:
            List of triage decisions
        """
        return await self.agent.analyze_codebase(
            codebase_path=codebase_path,
            cves=cves,
            ecosystem=ecosystem,
            callback=progress_callback,
        )
