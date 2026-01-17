"""
LangGraph node functions for the TraceGuard workflow.

Each node is a pure async function that:
1. Receives the full TraceGuardState
2. Performs its operation (calling external APIs)
3. Returns state updates (including audit entry)

Nodes do NOT access the database - they operate on pure data structures.
The runner handles persistence after graph execution.
"""

import logging
from datetime import datetime
from typing import Any

from traceguard.github.client import GitHubClient
from traceguard.openai.client import OpenAIClient
from traceguard.jira.client import JiraClient
from traceguard.graph.state import (
    TraceGuardState,
    AlertData,
    OwnerData,
    CVESummaryData,
    JiraTicketData,
    AuditEntry,
)

logger = logging.getLogger(__name__)


def create_audit_entry(
    step_name: str,
    inputs: dict,
    outputs: dict,
    decisions: list[str],
    errors: list[str] | None = None,
) -> AuditEntry:
    """Create a standardized audit entry for transparency."""
    return AuditEntry(
        step_name=step_name,
        timestamp=datetime.utcnow().isoformat(),
        inputs=inputs,
        outputs=outputs,
        decisions=decisions,
        errors=errors,
    )


async def security_intake_node(state: TraceGuardState) -> dict[str, Any]:
    """
    Fetch Dependabot alerts from GitHub.

    This node queries the GitHub API for open Dependabot security alerts
    on the target repository and normalizes them into AlertData structures.

    Inputs: repo_owner, repo_name from state
    Outputs: alerts list, updated status
    Decisions: Logs whether alerts were found
    """
    client = GitHubClient()
    decisions: list[str] = []
    errors: list[str] = []

    repo_identifier = f"{state['repo_owner']}/{state['repo_name']}"
    logger.info(f"Security intake starting for {repo_identifier}")

    try:
        raw_alerts = await client.get_dependabot_alerts(
            owner=state["repo_owner"],
            repo=state["repo_name"],
        )

        # Transform to AlertData
        alerts: list[AlertData] = [
            AlertData(
                alert_number=a.number,
                state=a.state,
                cve_id=a.cve_id,
                severity=a.severity,
                summary=a.summary,
                description=a.description,
                package_name=a.package_name,
                package_ecosystem=a.package_ecosystem,
                vulnerable_version_range=a.vulnerable_version_range,
                patched_version=a.patched_version,
                html_url=a.html_url,
            )
            for a in raw_alerts
        ]

        if len(alerts) == 0:
            decisions.append(
                "No open Dependabot alerts found - repository appears secure"
            )
        else:
            # Group by severity for the decision log
            severity_counts: dict[str, int] = {}
            for alert in alerts:
                sev = alert["severity"]
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            severity_summary = ", ".join(
                f"{count} {sev}" for sev, count in severity_counts.items()
            )
            decisions.append(
                f"Found {len(alerts)} open alerts: {severity_summary}"
            )

        audit_entry = create_audit_entry(
            step_name="security_intake",
            inputs={"repository": repo_identifier},
            outputs={"alert_count": len(alerts)},
            decisions=decisions,
        )

        logger.info(
            f"Security intake completed for {repo_identifier}: "
            f"{len(alerts)} alerts found"
        )

        return {
            "alerts": alerts,
            "status": "resolving_owner",
            "audit_trail": state["audit_trail"] + [audit_entry],
        }

    except Exception as e:
        logger.error(f"Security intake failed for {repo_identifier}: {e}")
        errors.append(str(e))

        audit_entry = create_audit_entry(
            step_name="security_intake",
            inputs={"repository": repo_identifier},
            outputs={},
            decisions=["Failed to fetch Dependabot alerts from GitHub"],
            errors=errors,
        )

        return {
            "status": "failed",
            "error_message": str(e),
            "audit_trail": state["audit_trail"] + [audit_entry],
        }


async def ownership_resolution_node(state: TraceGuardState) -> dict[str, Any]:
    """
    Resolve repository owner information from GitHub.

    This node queries the GitHub API for user information about the
    repository owner, extracting contact details for ticket assignment.

    Inputs: repo_owner from state
    Outputs: owner data, updated status
    Decisions: Logs resolution details and contact availability
    """
    client = GitHubClient()
    decisions: list[str] = []
    errors: list[str] = []

    logger.info(f"Ownership resolution starting for user: {state['repo_owner']}")

    try:
        user = await client.get_user(state["repo_owner"])

        owner = OwnerData(
            username=user.login,
            email=user.email,
            name=user.name,
        )

        if user.email:
            decisions.append(
                f"Resolved owner '{user.login}' with public email: {user.email}"
            )
        else:
            decisions.append(
                f"Resolved owner '{user.login}' - no public email available, "
                "will need alternative contact method for ticket assignment"
            )

        if user.name:
            decisions.append(f"Owner display name: {user.name}")

        audit_entry = create_audit_entry(
            step_name="ownership_resolution",
            inputs={"repo_owner": state["repo_owner"]},
            outputs={
                "username": user.login,
                "has_email": user.email is not None,
                "has_name": user.name is not None,
            },
            decisions=decisions,
        )

        logger.info(
            f"Ownership resolution completed: {user.login} "
            f"(email: {user.email or 'none'})"
        )

        return {
            "owner": owner,
            "status": "completed",
            "audit_trail": state["audit_trail"] + [audit_entry],
        }

    except Exception as e:
        logger.error(f"Ownership resolution failed for {state['repo_owner']}: {e}")
        errors.append(str(e))

        audit_entry = create_audit_entry(
            step_name="ownership_resolution",
            inputs={"repo_owner": state["repo_owner"]},
            outputs={},
            decisions=["Failed to resolve owner information from GitHub"],
            errors=errors,
        )

        return {
            "status": "failed",
            "error_message": str(e),
            "audit_trail": state["audit_trail"] + [audit_entry],
        }


async def cve_summarization_node(state: TraceGuardState) -> dict[str, Any]:
    """
    Summarize CVEs into developer-friendly content using OpenAI.

    This node takes raw alert data and transforms it into clear,
    actionable summaries that can be used in Jira tickets.

    Inputs: alerts list from state
    Outputs: cve_summaries list, updated status
    Decisions: Logs summarization results per alert
    """
    client = OpenAIClient()
    decisions: list[str] = []
    errors: list[str] = []
    summaries: list[CVESummaryData] = []

    alerts = state.get("alerts", [])
    repo_name = state["repo_full_name"]

    logger.info(f"CVE summarization starting for {len(alerts)} alerts")

    if not alerts:
        decisions.append("No alerts to summarize - skipping CVE summarization")

        audit_entry = create_audit_entry(
            step_name="cve_summarization",
            inputs={"alert_count": 0},
            outputs={"summary_count": 0},
            decisions=decisions,
        )

        return {
            "cve_summaries": [],
            "status": "creating_tickets",
            "audit_trail": state["audit_trail"] + [audit_entry],
        }

    try:
        for alert in alerts:
            logger.info(
                f"Summarizing alert {alert['alert_number']}: {alert['cve_id']}"
            )

            summary = await client.summarize_cve(
                cve_id=alert["cve_id"],
                severity=alert["severity"],
                summary=alert["summary"],
                description=alert["description"],
                package_name=alert["package_name"],
                package_ecosystem=alert["package_ecosystem"],
                vulnerable_version_range=alert["vulnerable_version_range"],
                patched_version=alert["patched_version"],
                repo_name=repo_name,
            )

            summaries.append(
                CVESummaryData(
                    alert_number=alert["alert_number"],
                    title=summary.title,
                    what_is_vulnerable=summary.what_is_vulnerable,
                    why_it_matters=summary.why_it_matters,
                    repo_impact=summary.repo_impact,
                    recommended_action=summary.recommended_action,
                    urgency_signal=summary.urgency_signal,
                )
            )

            decisions.append(
                f"Alert {alert['alert_number']} ({alert['cve_id'] or 'no CVE'}): "
                f"urgency={summary.urgency_signal}"
            )

        audit_entry = create_audit_entry(
            step_name="cve_summarization",
            inputs={"alert_count": len(alerts)},
            outputs={"summary_count": len(summaries)},
            decisions=decisions,
        )

        logger.info(f"CVE summarization completed: {len(summaries)} summaries created")

        return {
            "cve_summaries": summaries,
            "status": "creating_tickets",
            "audit_trail": state["audit_trail"] + [audit_entry],
        }

    except Exception as e:
        logger.error(f"CVE summarization failed: {e}")
        errors.append(str(e))

        audit_entry = create_audit_entry(
            step_name="cve_summarization",
            inputs={"alert_count": len(alerts)},
            outputs={},
            decisions=["Failed to summarize CVEs using OpenAI"],
            errors=errors,
        )

        return {
            "status": "failed",
            "error_message": str(e),
            "audit_trail": state["audit_trail"] + [audit_entry],
        }


async def jira_ticket_creation_node(state: TraceGuardState) -> dict[str, Any]:
    """
    Create Jira tickets for each CVE summary.

    This node takes CVE summaries and owner information to create
    well-formatted, assigned Jira tickets. Supports dry-run mode
    for previewing tickets without creation.

    Inputs: cve_summaries, alerts, owner, dry_run from state
    Outputs: jira_tickets list, updated status
    Decisions: Logs ticket creation results, assignment status
    """
    client = JiraClient()
    decisions: list[str] = []
    errors: list[str] = []
    tickets: list[JiraTicketData] = []

    summaries = state.get("cve_summaries") or []
    alerts = state.get("alerts", [])
    owner = state.get("owner")
    dry_run = state.get("dry_run", False)
    repo_full_name = state["repo_full_name"]

    logger.info(
        f"Jira ticket creation starting: {len(summaries)} tickets, "
        f"dry_run={dry_run}"
    )

    if not summaries:
        decisions.append("No CVE summaries to create tickets for - skipping")

        audit_entry = create_audit_entry(
            step_name="jira_ticket_creation",
            inputs={"summary_count": 0, "dry_run": dry_run},
            outputs={"ticket_count": 0},
            decisions=decisions,
        )

        return {
            "jira_tickets": [],
            "status": "completed",
            "audit_trail": state["audit_trail"] + [audit_entry],
        }

    alerts_by_number = {a["alert_number"]: a for a in alerts}

    assignee_id: str | None = None
    if owner and owner.get("email"):
        try:
            jira_user = await client.find_user_by_email(owner["email"])
            if jira_user:
                assignee_id = jira_user.account_id
                decisions.append(
                    f"Resolved Jira user for assignment: {jira_user.display_name}"
                )
            else:
                decisions.append(
                    f"No Jira user found for email {owner['email']} - "
                    "tickets will be unassigned"
                )
        except Exception as e:
            decisions.append(f"Failed to lookup Jira user: {e}")
            errors.append(f"Jira user lookup failed: {e}")
    else:
        decisions.append("No owner email available - tickets will be unassigned")

    try:
        for summary in summaries:
            alert = alerts_by_number.get(summary["alert_number"])
            if not alert:
                logger.warning(f"Alert {summary['alert_number']} not found")
                continue

            priority = client.get_priority_name(alert["severity"])

            description = client.build_ticket_description(
                cve_id=alert["cve_id"],
                severity=alert["severity"],
                what_is_vulnerable=summary["what_is_vulnerable"],
                why_it_matters=summary["why_it_matters"],
                repo_impact=summary["repo_impact"],
                recommended_action=summary["recommended_action"],
                package_name=alert["package_name"],
                package_ecosystem=alert["package_ecosystem"],
                vulnerable_version_range=alert["vulnerable_version_range"],
                patched_version=alert["patched_version"],
                html_url=alert["html_url"],
                repo_full_name=repo_full_name,
            )

            labels = ["security", "vulnerability", "traceguard"]
            if alert["cve_id"]:
                labels.append(alert["cve_id"].replace("-", "_"))

            if dry_run:
                preview_payload = {
                    "summary": summary["title"],
                    "description": description,
                    "priority": priority,
                    "labels": labels,
                    "assignee_account_id": assignee_id,
                }

                tickets.append(
                    JiraTicketData(
                        alert_number=summary["alert_number"],
                        ticket_key="DRY-RUN",
                        ticket_url="",
                        summary=summary["title"],
                        priority=priority,
                        assignee=owner["username"] if owner else None,
                        dry_run=True,
                        preview_payload=preview_payload,
                    )
                )

                decisions.append(
                    f"[DRY RUN] Would create ticket for alert "
                    f"{summary['alert_number']}: {summary['title']}"
                )
            else:
                issue = await client.create_issue(
                    summary=summary["title"],
                    description=description,
                    priority=priority,
                    labels=labels,
                    assignee_account_id=assignee_id,
                )

                tickets.append(
                    JiraTicketData(
                        alert_number=summary["alert_number"],
                        ticket_key=issue.key,
                        ticket_url=issue.browse_url,
                        summary=summary["title"],
                        priority=priority,
                        assignee=owner["username"] if owner else None,
                        dry_run=False,
                        preview_payload=None,
                    )
                )

                decisions.append(
                    f"Created ticket {issue.key} for alert "
                    f"{summary['alert_number']}: {issue.browse_url}"
                )

                logger.info(f"Created Jira ticket: {issue.key}")

        audit_entry = create_audit_entry(
            step_name="jira_ticket_creation",
            inputs={
                "summary_count": len(summaries),
                "dry_run": dry_run,
                "has_assignee": assignee_id is not None,
            },
            outputs={
                "ticket_count": len(tickets),
                "tickets": [t["ticket_key"] for t in tickets],
            },
            decisions=decisions,
            errors=errors if errors else None,
        )

        mode = "DRY RUN" if dry_run else "LIVE"
        logger.info(f"Jira ticket creation completed [{mode}]: {len(tickets)} tickets")

        return {
            "jira_tickets": tickets,
            "status": "completed",
            "audit_trail": state["audit_trail"] + [audit_entry],
        }

    except Exception as e:
        logger.error(f"Jira ticket creation failed: {e}")
        errors.append(str(e))

        audit_entry = create_audit_entry(
            step_name="jira_ticket_creation",
            inputs={"summary_count": len(summaries), "dry_run": dry_run},
            outputs={"tickets_created_before_failure": len(tickets)},
            decisions=decisions,
            errors=errors,
        )

        return {
            "jira_tickets": tickets,
            "status": "failed",
            "error_message": str(e),
            "audit_trail": state["audit_trail"] + [audit_entry],
        }
