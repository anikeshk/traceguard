"""
LangGraph workflow definition for TraceGuard.

This module defines the StateGraph that orchestrates agent execution.
The graph determines the order of operations and handles conditional routing.
"""

from langgraph.graph import StateGraph, END

from traceguard.graph.state import TraceGuardState
from traceguard.graph.nodes import (
    security_intake_node,
    ownership_resolution_node,
    cve_summarization_node,
    jira_ticket_creation_node,
)


def should_continue(state: TraceGuardState) -> str:
    """
    Conditional edge function: determine next step based on status.

    If the current step failed, route to END.
    Otherwise, continue to the next step.
    """
    if state["status"] == "failed":
        return "end"
    return "continue"


def create_workflow() -> StateGraph:
    """
    Create the TraceGuard LangGraph workflow.

    Graph structure:
        [start]
            |
            v
        security_intake
            |
            +---(failed)---> [END]
            |
            v (continue)
        ownership_resolution
            |
            +---(failed)---> [END]
            |
            v (continue)
        cve_summarization
            |
            +---(failed)---> [END]
            |
            v (continue)
        jira_ticket_creation
            |
            v
        [END]
    """
    workflow = StateGraph(TraceGuardState)

    # Add nodes
    workflow.add_node("security_intake", security_intake_node)
    workflow.add_node("ownership_resolution", ownership_resolution_node)
    workflow.add_node("cve_summarization", cve_summarization_node)
    workflow.add_node("jira_ticket_creation", jira_ticket_creation_node)

    # Set entry point
    workflow.set_entry_point("security_intake")

    # Add conditional edges from security_intake
    workflow.add_conditional_edges(
        "security_intake",
        should_continue,
        {
            "continue": "ownership_resolution",
            "end": END,
        },
    )

    # Add conditional edges from ownership_resolution
    workflow.add_conditional_edges(
        "ownership_resolution",
        should_continue,
        {
            "continue": "cve_summarization",
            "end": END,
        },
    )

    # Add conditional edges from cve_summarization
    workflow.add_conditional_edges(
        "cve_summarization",
        should_continue,
        {
            "continue": "jira_ticket_creation",
            "end": END,
        },
    )

    # jira_ticket_creation always ends the workflow
    workflow.add_edge("jira_ticket_creation", END)

    return workflow


def compile_workflow():
    """
    Compile the workflow for execution.

    Returns a compiled graph that can be invoked with state.
    """
    workflow = create_workflow()
    return workflow.compile()
