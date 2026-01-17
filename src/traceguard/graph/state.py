"""
State schema for the TraceGuard LangGraph workflow.

This module defines the typed state that flows through all nodes in the graph.
Each node receives the full state and returns updates to be merged.
"""

from typing import TypedDict, Literal


class AlertData(TypedDict):
    """Normalized alert data from GitHub Dependabot."""

    alert_number: int
    state: str
    cve_id: str | None
    severity: str
    summary: str | None
    description: str | None
    package_name: str
    package_ecosystem: str
    vulnerable_version_range: str | None
    patched_version: str | None
    html_url: str


class OwnerData(TypedDict):
    """Resolved owner information from GitHub."""

    username: str
    email: str | None
    name: str | None


class CVESummaryData(TypedDict):
    """Developer-friendly CVE summary from OpenAI."""

    alert_number: int
    title: str
    what_is_vulnerable: str
    why_it_matters: str
    repo_impact: str
    recommended_action: str
    urgency_signal: str


class JiraTicketData(TypedDict):
    """Jira ticket creation result."""

    alert_number: int
    ticket_key: str
    ticket_url: str
    summary: str
    priority: str
    assignee: str | None
    dry_run: bool
    preview_payload: dict | None


class AuditEntry(TypedDict):
    """
    Single audit trail entry recorded by each node.

    Every agent step records its inputs, outputs, decisions, and any errors
    for full transparency and auditability.
    """

    step_name: str
    timestamp: str  # ISO format
    inputs: dict
    outputs: dict
    decisions: list[str]
    errors: list[str] | None


class TraceGuardState(TypedDict):
    """
    LangGraph state for the TraceGuard workflow.

    This is the single source of truth passed through all nodes.
    The state is immutable - nodes return updates that get merged.
    """

    # Job identification (immutable throughout execution)
    job_id: int
    repo_owner: str
    repo_name: str
    repo_full_name: str
    repo_url: str

    # Status tracking (mutable, tracks progress)
    status: Literal[
        "pending",
        "fetching_alerts",
        "resolving_owner",
        "summarizing_cves",
        "creating_tickets",
        "completed",
        "failed",
    ]
    error_message: str | None

    # Agent outputs (populated as graph executes)
    alerts: list[AlertData]
    owner: OwnerData | None
    cve_summaries: list[CVESummaryData] | None
    jira_tickets: list[JiraTicketData] | None

    # Configuration
    dry_run: bool

    # Audit trail (appended by each node)
    audit_trail: list[AuditEntry]
