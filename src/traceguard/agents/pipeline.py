"""LangGraph pipeline orchestrator for CVE triage.

Defines the agent workflow using LangGraph's StateGraph.
"""

import logging
from typing import Literal

from langgraph.graph import END, StateGraph

from traceguard.agents.state import PipelineState
from traceguard.agents.cve_context import CVEContextAgent
from traceguard.agents.dependency_usage import DependencyUsageAgent
from traceguard.agents.ownership import OwnershipAgent
from traceguard.agents.ticket_gen import TicketGenerationAgent

logger = logging.getLogger(__name__)


def create_triage_pipeline(use_ai: bool = True):
    """Create the LangGraph pipeline for CVE triage.

    The pipeline executes these steps in order:
    1. CVE Context Collection - Fetch CVE data from sources
    2. Dependency Usage Detection - Scan codebase for package usage
    3. Ownership Resolution - Resolve file owners from CODEOWNERS
    4. Ticket Generation - Generate GitHub issue content

    Args:
        use_ai: Whether to use AI for ticket generation.

    Returns:
        Compiled LangGraph pipeline.
    """
    # Initialize agents
    cve_context_agent = CVEContextAgent()
    dependency_usage_agent = DependencyUsageAgent()
    ownership_agent = OwnershipAgent()
    ticket_gen_agent = TicketGenerationAgent(use_ai=use_ai)

    # Define node functions that wrap agent execution
    async def run_cve_context(state: PipelineState) -> dict:
        """Run the CVE Context Collection agent."""
        logger.info("Running CVE Context Collection agent")
        return await cve_context_agent.execute(state)

    async def run_dependency_usage(state: PipelineState) -> dict:
        """Run the Dependency Usage Detection agent."""
        logger.info("Running Dependency Usage Detection agent")
        return await dependency_usage_agent.execute(state)

    async def run_ownership(state: PipelineState) -> dict:
        """Run the Ownership Resolution agent."""
        logger.info("Running Ownership Resolution agent")
        return await ownership_agent.execute(state)

    async def run_ticket_gen(state: PipelineState) -> dict:
        """Run the Ticket Generation agent."""
        logger.info("Running Ticket Generation agent")
        return await ticket_gen_agent.execute(state)

    # Define routing functions
    def route_after_cve_context(
        state: PipelineState,
    ) -> Literal["dependency_usage", "__end__"]:
        """Route after CVE context collection.

        If context fetch failed, end the pipeline.
        """
        if state.get("cve_context_error"):
            logger.info("CVE context fetch failed, ending pipeline")
            return END
        return "dependency_usage"

    def route_after_dependency_usage(
        state: PipelineState,
    ) -> Literal["ownership", "__end__"]:
        """Route after dependency usage detection.

        If CVE is not applicable, end the pipeline (success case).
        """
        if state.get("is_applicable") is False:
            logger.info("CVE is not applicable, ending pipeline")
            return END
        return "ownership"

    def route_after_ownership(
        state: PipelineState,
    ) -> Literal["ticket_generation", "__end__"]:
        """Route after ownership resolution.

        Continue to ticket generation even if ownership resolution failed,
        as we can still generate an issue without assignees.
        """
        # Always continue to ticket generation for applicable CVEs
        return "ticket_generation"

    # Build the state graph
    workflow = StateGraph(PipelineState)

    # Add nodes
    workflow.add_node("cve_context", run_cve_context)
    workflow.add_node("dependency_usage", run_dependency_usage)
    workflow.add_node("ownership", run_ownership)
    workflow.add_node("ticket_generation", run_ticket_gen)

    # Set entry point
    workflow.set_entry_point("cve_context")

    # Add conditional edges
    workflow.add_conditional_edges(
        "cve_context",
        route_after_cve_context,
        {
            "dependency_usage": "dependency_usage",
            END: END,
        },
    )

    workflow.add_conditional_edges(
        "dependency_usage",
        route_after_dependency_usage,
        {
            "ownership": "ownership",
            END: END,
        },
    )

    workflow.add_conditional_edges(
        "ownership",
        route_after_ownership,
        {
            "ticket_generation": "ticket_generation",
            END: END,
        },
    )

    # Ticket generation always ends the pipeline
    workflow.add_edge("ticket_generation", END)

    # Compile and return the graph
    return workflow.compile()


class TriagePipelineRunner:
    """Runner for the CVE triage pipeline.

    Provides a high-level interface for executing the pipeline.
    """

    def __init__(self, use_ai: bool = True):
        """Initialize the pipeline runner.

        Args:
            use_ai: Whether to use AI for ticket generation.
        """
        self._pipeline = create_triage_pipeline(use_ai=use_ai)

    async def run(
        self,
        job_id: int,
        job_cve_id: int,
        cve_id: str,
        codebase_path: str,
    ) -> PipelineState:
        """Run the triage pipeline for a single CVE.

        Args:
            job_id: The job ID.
            job_cve_id: The job CVE ID.
            cve_id: The CVE identifier to analyze.
            codebase_path: Path to the codebase.

        Returns:
            Final pipeline state with all results.
        """
        from traceguard.agents.state import create_initial_state

        initial_state = create_initial_state(
            job_id=job_id,
            job_cve_id=job_cve_id,
            cve_id=cve_id,
            codebase_path=codebase_path,
        )

        logger.info(f"Starting triage pipeline for {cve_id}")

        # Run the pipeline
        final_state = await self._pipeline.ainvoke(initial_state)

        logger.info(f"Pipeline completed for {cve_id}: {final_state.get('current_step')}")

        return final_state

    async def run_batch(
        self,
        job_id: int,
        cve_analyses: list[dict],
        codebase_path: str,
    ) -> list[PipelineState]:
        """Run the triage pipeline for multiple CVEs.

        Args:
            job_id: The job ID.
            cve_analyses: List of dicts with job_cve_id and cve_id.
            codebase_path: Path to the codebase.

        Returns:
            List of final pipeline states.
        """
        results = []

        for analysis in cve_analyses:
            result = await self.run(
                job_id=job_id,
                job_cve_id=analysis["job_cve_id"],
                cve_id=analysis["cve_id"],
                codebase_path=codebase_path,
            )
            results.append(result)

        return results
