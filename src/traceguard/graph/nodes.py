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
from traceguard.graph.state import TraceGuardState, AlertData, OwnerData, AuditEntry

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
