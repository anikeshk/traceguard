"""Job orchestration service.

Handles job creation, execution, and status management.
"""

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from traceguard.agents import TriagePipelineRunner
from traceguard.core.exceptions import JobNotFoundError, CodebaseNotFoundError
from traceguard.models.job import (
    Job,
    JobCVE,
    AgentStep,
    JobStatus,
    ApplicabilityStatus,
    AgentStepStatus,
)
from traceguard.models.cve import GeneratedIssue, UsageEvidence, ResolvedOwner

logger = logging.getLogger(__name__)


class JobService:
    """Service for managing scan jobs and orchestrating the triage pipeline."""

    def __init__(self, session: AsyncSession, use_ai: bool = True):
        """Initialize the job service.

        Args:
            session: Async database session.
            use_ai: Whether to use AI for ticket generation.
        """
        self._session = session
        self._pipeline_runner = TriagePipelineRunner(use_ai=use_ai)

    async def create_job(
        self,
        codebase_path: str,
        cve_ids: list[str],
    ) -> Job:
        """Create a new scan job.

        Args:
            codebase_path: Path to the codebase to analyze.
            cve_ids: List of CVE IDs to analyze.

        Returns:
            Created Job instance.

        Raises:
            CodebaseNotFoundError: If codebase path doesn't exist.
        """
        # Validate codebase path
        path = Path(codebase_path)
        if not path.exists():
            raise CodebaseNotFoundError(codebase_path)

        # Create job
        job = Job(
            codebase_path=str(path.resolve()),
            status=JobStatus.PENDING,
        )
        self._session.add(job)
        await self._session.flush()

        # Create JobCVE entries
        for cve_id in cve_ids:
            job_cve = JobCVE(
                job_id=job.id,
                cve_id=cve_id,
            )
            self._session.add(job_cve)

        await self._session.commit()
        await self._session.refresh(job)

        logger.info(f"Created job {job.id} with {len(cve_ids)} CVEs")
        return job

    async def get_job(self, job_id: int) -> Job:
        """Get a job by ID with all related data.

        Args:
            job_id: The job ID.

        Returns:
            Job instance with loaded relationships.

        Raises:
            JobNotFoundError: If job doesn't exist.
        """
        query = (
            select(Job)
            .where(Job.id == job_id)
            .options(
                selectinload(Job.cve_analyses).selectinload(JobCVE.steps).selectinload(AgentStep.artifacts),
                selectinload(Job.cve_analyses).selectinload(JobCVE.steps).selectinload(AgentStep.usage_evidence),
                selectinload(Job.cve_analyses).selectinload(JobCVE.steps).selectinload(AgentStep.resolved_owners),
                selectinload(Job.cve_analyses).selectinload(JobCVE.generated_issue),
            )
        )
        result = await self._session.execute(query)
        job = result.scalar_one_or_none()

        if not job:
            raise JobNotFoundError(job_id)

        return job

    async def list_jobs(
        self,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[Job], int]:
        """List jobs with pagination.

        Args:
            page: Page number (1-indexed).
            page_size: Number of items per page.

        Returns:
            Tuple of (jobs list, total count).
        """
        # Get total count
        count_query = select(func.count(Job.id))
        result = await self._session.execute(count_query)
        total = result.scalar_one()

        # Get paginated jobs
        offset = (page - 1) * page_size
        query = (
            select(Job)
            .options(selectinload(Job.cve_analyses))
            .order_by(Job.created_at.desc())
            .offset(offset)
            .limit(page_size)
        )
        result = await self._session.execute(query)
        jobs = list(result.scalars().all())

        return jobs, total

    async def run_job(self, job_id: int) -> Job:
        """Run the triage pipeline for a job.

        Args:
            job_id: The job ID to run.

        Returns:
            Updated Job instance.

        Raises:
            JobNotFoundError: If job doesn't exist.
        """
        job = await self.get_job(job_id)

        # Update job status
        job.status = JobStatus.RUNNING
        job.started_at = datetime.now(timezone.utc)
        await self._session.commit()

        logger.info(f"Starting job {job_id}")

        try:
            # Run pipeline for each CVE
            for job_cve in job.cve_analyses:
                await self._run_cve_analysis(job, job_cve)

            # Mark job as completed
            job.status = JobStatus.COMPLETED
            job.completed_at = datetime.now(timezone.utc)

        except Exception as e:
            logger.error(f"Job {job_id} failed: {e}")
            job.status = JobStatus.FAILED
            job.error_message = str(e)
            job.completed_at = datetime.now(timezone.utc)

        await self._session.commit()
        await self._session.refresh(job)

        logger.info(f"Job {job_id} completed with status: {job.status}")
        return job

    async def _run_cve_analysis(self, job: Job, job_cve: JobCVE) -> None:
        """Run analysis for a single CVE.

        Args:
            job: The parent job.
            job_cve: The CVE analysis to run.
        """
        logger.info(f"Analyzing CVE {job_cve.cve_id}")

        # Create agent steps
        agent_names = ["cve_context", "dependency_usage", "ownership", "ticket_generation"]
        steps = {}

        for i, agent_name in enumerate(agent_names):
            step = AgentStep(
                job_cve_id=job_cve.id,
                agent_name=agent_name,
                step_order=i + 1,
                status=AgentStepStatus.PENDING,
            )
            self._session.add(step)
            steps[agent_name] = step

        await self._session.flush()

        try:
            # Run the pipeline
            final_state = await self._pipeline_runner.run(
                job_id=job.id,
                job_cve_id=job_cve.id,
                cve_id=job_cve.cve_id,
                codebase_path=job.codebase_path,
            )

            # Update CVE applicability
            job_cve.applicability = (
                ApplicabilityStatus.APPLICABLE
                if final_state.get("is_applicable")
                else ApplicabilityStatus.NOT_APPLICABLE
                if final_state.get("is_applicable") is False
                else ApplicabilityStatus.UNKNOWN
            )
            job_cve.applicability_reason = final_state.get("applicability_reason")

            # Update agent steps based on state
            await self._update_agent_steps(steps, final_state)

            # Save usage evidence
            usage_evidence = final_state.get("usage_evidence", [])
            if usage_evidence:
                dep_step = steps.get("dependency_usage")
                for evidence in usage_evidence:
                    ue = UsageEvidence(
                        agent_step_id=dep_step.id,
                        file_path=evidence.get("file_path", ""),
                        line_number=evidence.get("line_number", 0),
                        usage_type=evidence.get("usage_type", ""),
                        code_snippet=evidence.get("code_snippet"),
                        package_name=evidence.get("package_name", ""),
                    )
                    self._session.add(ue)

            # Save resolved owners
            owners = final_state.get("owners", [])
            if owners:
                owner_step = steps.get("ownership")
                for owner in owners:
                    ro = ResolvedOwner(
                        agent_step_id=owner_step.id,
                        file_path=owner.get("file_path", ""),
                        owner=owner.get("owner", ""),
                        owner_type=owner.get("owner_type", "user"),
                        reasoning=owner.get("reasoning"),
                    )
                    self._session.add(ro)

            # Save generated issue
            if final_state.get("generated_issue_title"):
                issue = GeneratedIssue(
                    job_cve_id=job_cve.id,
                    title=final_state.get("generated_issue_title", ""),
                    body=final_state.get("generated_issue_body", ""),
                    github_issue_url=final_state.get("github_issue_url"),
                )
                self._session.add(issue)

            await self._session.flush()

        except Exception as e:
            logger.error(f"Error analyzing CVE {job_cve.cve_id}: {e}")
            job_cve.applicability = ApplicabilityStatus.UNKNOWN
            job_cve.applicability_reason = f"Analysis failed: {str(e)}"
            raise

    async def _update_agent_steps(
        self,
        steps: dict[str, AgentStep],
        final_state: dict,
    ) -> None:
        """Update agent step statuses based on pipeline state.

        Args:
            steps: Dictionary of agent name to AgentStep.
            final_state: Final pipeline state.
        """
        current_step = final_state.get("current_step", "")

        # Determine which steps completed
        step_completion = {
            "cve_context": "cve_context_complete" in current_step or "cve_context_failed" not in current_step,
            "dependency_usage": "dependency_usage_complete" in current_step,
            "ownership": "ownership_complete" in current_step or "ownership_failed" in current_step,
            "ticket_generation": "ticket_generation_complete" in current_step,
        }

        # Check for errors
        step_errors = {
            "cve_context": final_state.get("cve_context_error"),
            "dependency_usage": None,  # No separate error field
            "ownership": final_state.get("ownership_error"),
            "ticket_generation": None,
        }

        now = datetime.now(timezone.utc)

        for agent_name, step in steps.items():
            error = step_errors.get(agent_name)

            if error:
                step.status = AgentStepStatus.FAILED
                step.error_message = error
                step.completed_at = now
            elif step_completion.get(agent_name):
                step.status = AgentStepStatus.COMPLETED
                step.completed_at = now
            elif final_state.get("is_applicable") is False and agent_name in ("ownership", "ticket_generation"):
                step.status = AgentStepStatus.SKIPPED
            else:
                step.status = AgentStepStatus.PENDING

            # Store relevant state data
            if agent_name == "cve_context":
                step.output_data = {"cve_context": final_state.get("cve_context")}
            elif agent_name == "dependency_usage":
                step.output_data = {
                    "is_applicable": final_state.get("is_applicable"),
                    "evidence_count": len(final_state.get("usage_evidence", [])),
                }
            elif agent_name == "ownership":
                step.output_data = {
                    "owner_count": len(final_state.get("owners", [])),
                }
            elif agent_name == "ticket_generation":
                step.output_data = {
                    "title": final_state.get("generated_issue_title"),
                    "has_url": bool(final_state.get("github_issue_url")),
                }

    async def delete_job(self, job_id: int) -> bool:
        """Delete a job and all related data.

        Args:
            job_id: The job ID to delete.

        Returns:
            True if deleted, False if not found.
        """
        job = await self._session.get(Job, job_id)
        if not job:
            return False

        await self._session.delete(job)
        await self._session.commit()

        logger.info(f"Deleted job {job_id}")
        return True
