"""
Workflow runner that coordinates graph execution with database persistence.

This module bridges the pure LangGraph workflow with SQLAlchemy persistence.
The runner:
1. Loads job data from the database
2. Initializes graph state
3. Executes the compiled workflow
4. Persists results back to the database
5. Saves audit trail artifacts
"""

import json
import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from traceguard.db.models import Job, Alert, Owner, JobStatus, AuditArtifact, JiraTicket
from traceguard.graph.state import TraceGuardState
from traceguard.graph.workflow import compile_workflow

logger = logging.getLogger(__name__)


async def run_traceguard_workflow(
    job_id: int,
    session: AsyncSession,
    dry_run: bool = False,
) -> TraceGuardState:
    """
    Execute the TraceGuard workflow for a job.

    This function:
    1. Loads job data from DB
    2. Initializes graph state
    3. Runs the LangGraph workflow
    4. Persists results back to DB
    5. Saves audit trail

    Args:
        job_id: The database ID of the job to process
        session: Async SQLAlchemy session for database operations
        dry_run: If True, Jira tickets will be previewed but not created

    Returns:
        The final state after workflow execution
    """
    # 1. Load job from database
    result = await session.execute(select(Job).where(Job.id == job_id))
    job = result.scalar_one_or_none()

    if not job:
        raise ValueError(f"Job {job_id} not found")

    logger.info(f"Starting workflow for job {job_id} ({job.repo_full_name})")

    # 2. Initialize state from job
    initial_state: TraceGuardState = {
        "job_id": job.id,
        "repo_owner": job.repo_owner,
        "repo_name": job.repo_name,
        "repo_full_name": job.repo_full_name,
        "repo_url": job.repo_url,
        "status": "fetching_alerts",
        "error_message": None,
        "alerts": [],
        "owner": None,
        "cve_summaries": None,
        "jira_tickets": None,
        "dry_run": dry_run,
        "audit_trail": [],
    }

    # Update job status to indicate workflow started
    job.status = JobStatus.FETCHING_ALERTS
    await session.flush()

    # 3. Execute workflow
    app = compile_workflow()
    final_state = await app.ainvoke(initial_state)

    logger.info(
        f"Workflow completed for job {job_id} with status: {final_state['status']}"
    )

    # 4. Persist results to database
    await persist_workflow_results(session, job, final_state)

    # 5. Save audit trail
    await save_audit_trail(session, job_id, final_state["audit_trail"])

    return final_state


async def persist_workflow_results(
    session: AsyncSession,
    job: Job,
    state: TraceGuardState,
) -> None:
    """
    Persist workflow results to the database.

    Updates the job status and creates Alert/Owner records based on
    the final state from the workflow.
    """
    # Update job status
    status_map = {
        "pending": JobStatus.PENDING,
        "fetching_alerts": JobStatus.FETCHING_ALERTS,
        "resolving_owner": JobStatus.RESOLVING_OWNER,
        "summarizing_cves": JobStatus.SUMMARIZING_CVES,
        "creating_tickets": JobStatus.CREATING_TICKETS,
        "completed": JobStatus.COMPLETED,
        "failed": JobStatus.FAILED,
    }
    job.status = status_map.get(state["status"], JobStatus.FAILED)
    job.error_message = state.get("error_message")

    # Save alerts
    for alert_data in state.get("alerts", []):
        alert = Alert(
            job_id=job.id,
            alert_number=alert_data["alert_number"],
            state=alert_data["state"],
            cve_id=alert_data["cve_id"],
            severity=alert_data["severity"],
            summary=alert_data["summary"],
            description=alert_data["description"],
            package_name=alert_data["package_name"],
            package_ecosystem=alert_data["package_ecosystem"],
            vulnerable_version_range=alert_data["vulnerable_version_range"],
            patched_version=alert_data["patched_version"],
            html_url=alert_data["html_url"],
        )
        session.add(alert)

    # Save owner
    if state.get("owner"):
        owner_data = state["owner"]
        owner = Owner(
            job_id=job.id,
            username=owner_data["username"],
            email=owner_data["email"],
            name=owner_data["name"],
        )
        session.add(owner)

    await session.flush()

    # Save Jira tickets (need to do this after flush to get alert IDs)
    jira_tickets = state.get("jira_tickets") or []
    if jira_tickets:
        # Build alert lookup by number
        alert_lookup: dict[int, int] = {}
        result = await session.execute(
            select(Alert).where(Alert.job_id == job.id)
        )
        for alert in result.scalars().all():
            alert_lookup[alert.alert_number] = alert.id

        for ticket_data in jira_tickets:
            alert_id = alert_lookup.get(ticket_data["alert_number"])
            if alert_id:
                ticket = JiraTicket(
                    job_id=job.id,
                    alert_id=alert_id,
                    ticket_key=ticket_data["ticket_key"],
                    ticket_url=ticket_data["ticket_url"],
                    summary=ticket_data["summary"],
                    priority=ticket_data["priority"],
                    assignee=ticket_data["assignee"],
                    dry_run=ticket_data["dry_run"],
                )
                session.add(ticket)

        await session.flush()

    logger.info(
        f"Persisted results for job {job.id}: "
        f"{len(state.get('alerts', []))} alerts, "
        f"owner={'yes' if state.get('owner') else 'no'}, "
        f"{len(jira_tickets)} jira tickets"
    )


async def save_audit_trail(
    session: AsyncSession,
    job_id: int,
    audit_trail: list,
) -> None:
    """
    Save audit trail entries to the database.

    Each audit entry from the workflow is persisted as an AuditArtifact
    record for transparency and debugging.
    """
    for entry in audit_trail:
        artifact = AuditArtifact(
            job_id=job_id,
            step_name=entry["step_name"],
            timestamp=entry["timestamp"],
            inputs_json=json.dumps(entry["inputs"]),
            outputs_json=json.dumps(entry["outputs"]),
            decisions_json=json.dumps(entry["decisions"]),
            errors_json=json.dumps(entry.get("errors") or []),
        )
        session.add(artifact)

    await session.flush()
    logger.info(f"Saved {len(audit_trail)} audit artifacts for job {job_id}")
