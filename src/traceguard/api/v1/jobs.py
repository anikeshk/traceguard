"""Job management API endpoints."""

import logging

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy.ext.asyncio import AsyncSession

from traceguard.core.database import get_db_session
from traceguard.core.exceptions import JobNotFoundError, CodebaseNotFoundError
from traceguard.services.job_service import JobService
from traceguard.schemas.job import (
    CreateJobRequest,
    CreateJobResponse,
    JobDetailSchema,
    JobListResponse,
    JobListItemSchema,
    JobCVEDetailSchema,
    AgentStepSchema,
    GeneratedIssueSchema,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/jobs", tags=["jobs"])


def get_job_service(session: AsyncSession = Depends(get_db_session)) -> JobService:
    """Dependency to get JobService instance."""
    return JobService(session)


@router.post("/", response_model=CreateJobResponse, status_code=status.HTTP_201_CREATED)
async def create_job(
    request: CreateJobRequest,
    background_tasks: BackgroundTasks,
    job_service: JobService = Depends(get_job_service),
) -> CreateJobResponse:
    """Create a new scan job.

    The job will be created in PENDING status and executed in the background.
    """
    try:
        job = await job_service.create_job(
            codebase_path=request.codebase_path,
            cve_ids=request.cve_ids,
        )

        # Schedule job execution in background
        background_tasks.add_task(run_job_background, job.id)

        return CreateJobResponse(
            job_id=job.id,
            status=job.status,
            cve_count=len(request.cve_ids),
            created_at=job.created_at,
        )

    except CodebaseNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


async def run_job_background(job_id: int) -> None:
    """Run a job in the background.

    This function is called by FastAPI's BackgroundTasks.
    """
    from traceguard.core.database import get_session

    logger.info(f"Starting background execution of job {job_id}")

    async with get_session() as session:
        job_service = JobService(session)
        try:
            await job_service.run_job(job_id)
        except Exception as e:
            logger.error(f"Background job {job_id} failed: {e}")


@router.get("/", response_model=JobListResponse)
async def list_jobs(
    page: int = 1,
    page_size: int = 20,
    job_service: JobService = Depends(get_job_service),
) -> JobListResponse:
    """List all jobs with pagination."""
    jobs, total = await job_service.list_jobs(page=page, page_size=page_size)

    job_items = [
        JobListItemSchema(
            id=job.id,
            codebase_path=job.codebase_path,
            status=job.status,
            cve_count=len(job.cve_analyses),
            started_at=job.started_at,
            completed_at=job.completed_at,
            created_at=job.created_at,
        )
        for job in jobs
    ]

    return JobListResponse(
        jobs=job_items,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{job_id}", response_model=JobDetailSchema)
async def get_job(
    job_id: int,
    job_service: JobService = Depends(get_job_service),
) -> JobDetailSchema:
    """Get detailed information about a specific job."""
    try:
        job = await job_service.get_job(job_id)
    except JobNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job {job_id} not found",
        )

    # Convert to schema
    cve_analyses = []
    for cve in job.cve_analyses:
        steps = [
            AgentStepSchema(
                id=step.id,
                agent_name=step.agent_name,
                step_order=step.step_order,
                status=step.status,
                started_at=step.started_at,
                completed_at=step.completed_at,
                input_data=step.input_data,
                output_data=step.output_data,
                error_message=step.error_message,
            )
            for step in sorted(cve.steps, key=lambda s: s.step_order)
        ]

        generated_issue = None
        if cve.generated_issue:
            generated_issue = GeneratedIssueSchema(
                id=cve.generated_issue.id,
                title=cve.generated_issue.title,
                body=cve.generated_issue.body,
                github_issue_url=cve.generated_issue.github_issue_url,
                created_issue_number=cve.generated_issue.created_issue_number,
                created_at=cve.generated_issue.created_at,
            )

        cve_analyses.append(
            JobCVEDetailSchema(
                id=cve.id,
                cve_id=cve.cve_id,
                applicability=cve.applicability,
                applicability_reason=cve.applicability_reason,
                steps=steps,
                generated_issue=generated_issue,
            )
        )

    return JobDetailSchema(
        id=job.id,
        codebase_path=job.codebase_path,
        status=job.status,
        started_at=job.started_at,
        completed_at=job.completed_at,
        error_message=job.error_message,
        created_at=job.created_at,
        updated_at=job.updated_at,
        cve_analyses=cve_analyses,
    )


@router.delete("/{job_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_job(
    job_id: int,
    job_service: JobService = Depends(get_job_service),
) -> None:
    """Delete a job and all related data."""
    deleted = await job_service.delete_job(job_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job {job_id} not found",
        )
