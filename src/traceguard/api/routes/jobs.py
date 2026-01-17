import json
import logging
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from traceguard.db import get_session, Job, JobStatus, AuditArtifact

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/jobs", tags=["jobs"])


class CreateJobRequest(BaseModel):
    repo_name: str
    repo_full_name: str
    repo_owner: str
    repo_url: str


class AlertResponse(BaseModel):
    id: int
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
    created_at: datetime


class OwnerResponse(BaseModel):
    id: int
    username: str
    email: str | None
    name: str | None
    created_at: datetime


class JobResponse(BaseModel):
    id: int
    repo_name: str
    repo_full_name: str
    repo_owner: str
    repo_url: str
    status: str
    error_message: str | None
    created_at: datetime
    updated_at: datetime
    alerts: list[AlertResponse] = []
    owner: OwnerResponse | None = None


class JobListResponse(BaseModel):
    id: int
    repo_name: str
    repo_full_name: str
    repo_owner: str
    repo_url: str
    status: str
    error_message: str | None
    created_at: datetime
    updated_at: datetime
    alert_count: int = 0


async def run_job_pipeline(job_id: int) -> None:
    """Background task to run the LangGraph workflow."""
    from traceguard.db import get_session_factory
    from traceguard.graph import run_traceguard_workflow

    factory = get_session_factory()
    async with factory() as session:
        try:
            # Run the LangGraph workflow
            final_state = await run_traceguard_workflow(job_id, session)
            await session.commit()
            logger.info(
                f"Job {job_id} workflow completed with status: {final_state['status']}"
            )

        except Exception as e:
            logger.error(f"Job {job_id} workflow failed: {e}")
            await session.rollback()

            # Update job status on failure
            async with factory() as error_session:
                result = await error_session.execute(
                    select(Job).where(Job.id == job_id)
                )
                job = result.scalar_one_or_none()
                if job:
                    job.status = JobStatus.FAILED
                    job.error_message = str(e)
                    await error_session.commit()


@router.post("", response_model=JobResponse)
async def create_job(
    request: CreateJobRequest,
    background_tasks: BackgroundTasks,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> JobResponse:
    """Create a new scan job for a repository."""
    try:
        # Create the job
        job = Job(
            repo_name=request.repo_name,
            repo_full_name=request.repo_full_name,
            repo_owner=request.repo_owner,
            repo_url=request.repo_url,
            status=JobStatus.PENDING,
        )
        session.add(job)
        await session.commit()

        logger.info(f"Created job {job.id} for {request.repo_full_name}")

        # Schedule background processing
        background_tasks.add_task(run_job_pipeline, job.id)

        return JobResponse(
            id=job.id,
            repo_name=job.repo_name,
            repo_full_name=job.repo_full_name,
            repo_owner=job.repo_owner,
            repo_url=job.repo_url,
            status=job.status.value,
            error_message=job.error_message,
            created_at=job.created_at,
            updated_at=job.updated_at,
            alerts=[],
            owner=None,
        )

    except Exception as e:
        logger.error(f"Failed to create job: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("", response_model=list[JobListResponse])
async def list_jobs(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[JobListResponse]:
    """List all jobs."""
    try:
        result = await session.execute(
            select(Job)
            .options(selectinload(Job.alerts))
            .order_by(Job.created_at.desc())
        )
        jobs = result.scalars().all()

        return [
            JobListResponse(
                id=job.id,
                repo_name=job.repo_name,
                repo_full_name=job.repo_full_name,
                repo_owner=job.repo_owner,
                repo_url=job.repo_url,
                status=job.status.value,
                error_message=job.error_message,
                created_at=job.created_at,
                updated_at=job.updated_at,
                alert_count=len(job.alerts),
            )
            for job in jobs
        ]

    except Exception as e:
        logger.error(f"Failed to list jobs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{job_id}", response_model=JobResponse)
async def get_job(
    job_id: int,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> JobResponse:
    """Get a specific job with all its details."""
    try:
        result = await session.execute(
            select(Job)
            .options(selectinload(Job.alerts), selectinload(Job.owner))
            .where(Job.id == job_id)
        )
        job = result.scalar_one_or_none()

        if not job:
            raise HTTPException(status_code=404, detail=f"Job {job_id} not found")

        return JobResponse(
            id=job.id,
            repo_name=job.repo_name,
            repo_full_name=job.repo_full_name,
            repo_owner=job.repo_owner,
            repo_url=job.repo_url,
            status=job.status.value,
            error_message=job.error_message,
            created_at=job.created_at,
            updated_at=job.updated_at,
            alerts=[
                AlertResponse(
                    id=alert.id,
                    alert_number=alert.alert_number,
                    state=alert.state,
                    cve_id=alert.cve_id,
                    severity=alert.severity,
                    summary=alert.summary,
                    description=alert.description,
                    package_name=alert.package_name,
                    package_ecosystem=alert.package_ecosystem,
                    vulnerable_version_range=alert.vulnerable_version_range,
                    patched_version=alert.patched_version,
                    html_url=alert.html_url,
                    created_at=alert.created_at,
                )
                for alert in job.alerts
            ],
            owner=OwnerResponse(
                id=job.owner.id,
                username=job.owner.username,
                email=job.owner.email,
                name=job.owner.name,
                created_at=job.owner.created_at,
            )
            if job.owner
            else None,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get job {job_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


class AuditEntryResponse(BaseModel):
    id: int
    step_name: str
    timestamp: str
    inputs: dict
    outputs: dict
    decisions: list[str]
    errors: list[str]
    created_at: datetime


@router.get("/{job_id}/audit", response_model=list[AuditEntryResponse])
async def get_job_audit_trail(
    job_id: int,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[AuditEntryResponse]:
    """Get the audit trail for a specific job."""
    try:
        # Verify job exists
        job_result = await session.execute(select(Job).where(Job.id == job_id))
        job = job_result.scalar_one_or_none()

        if not job:
            raise HTTPException(status_code=404, detail=f"Job {job_id} not found")

        # Fetch audit artifacts
        result = await session.execute(
            select(AuditArtifact)
            .where(AuditArtifact.job_id == job_id)
            .order_by(AuditArtifact.created_at)
        )
        artifacts = result.scalars().all()

        return [
            AuditEntryResponse(
                id=artifact.id,
                step_name=artifact.step_name,
                timestamp=artifact.timestamp,
                inputs=json.loads(artifact.inputs_json),
                outputs=json.loads(artifact.outputs_json),
                decisions=json.loads(artifact.decisions_json),
                errors=json.loads(artifact.errors_json) if artifact.errors_json else [],
                created_at=artifact.created_at,
            )
            for artifact in artifacts
        ]

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get audit trail for job {job_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
