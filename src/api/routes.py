"""FastAPI routes for TraceGuard API."""

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, WebSocket
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.analysis.agent import TriageOrchestrator
from src.cve_sources.aggregator import CVEAggregator
from src.database.connection import get_db
from src.database.models import CVE, Ownership, ScanJob, TriageResult, TriageStatus

logger = logging.getLogger(__name__)

router = APIRouter()


# Pydantic models for API
class ScanRequest(BaseModel):
    """Request to start a CVE scan."""

    codebase_path: str = Field(..., description="Path to the codebase to scan")
    ecosystem: str = Field("pypi", description="Package ecosystem (pypi, npm, go, etc.)")
    package_filter: str | None = Field(None, description="Filter CVEs by package name")


class ScanResponse(BaseModel):
    """Response from starting a scan."""

    job_id: int
    status: str
    message: str


class CVEResponse(BaseModel):
    """CVE information response."""

    id: str
    title: str | None
    description: str
    severity: str
    cvss_score: float | None
    source: str
    source_url: str | None
    published_at: datetime | None
    affected_packages: list[str]


class TriageResultResponse(BaseModel):
    """Triage result response."""

    id: int
    cve_id: str
    status: str
    is_affected: bool | None
    confidence: float | None
    reasoning: str | None
    priority_score: float | None
    remediation: str | None
    affected_files: list[str]
    owners: list[dict]


class TriageOverride(BaseModel):
    """Request to override a triage decision."""

    is_affected: bool
    reason: str


class DashboardStats(BaseModel):
    """Dashboard statistics."""

    total_cves: int
    triaged_count: int
    affected_count: int
    pending_count: int
    critical_count: int
    high_count: int


# WebSocket connections for progress updates
active_connections: dict[int, list[WebSocket]] = {}


async def notify_progress(job_id: int, message: dict) -> None:
    """Send progress update to connected WebSocket clients."""
    if job_id in active_connections:
        for ws in active_connections[job_id]:
            try:
                await ws.send_json(message)
            except Exception:
                pass


@router.websocket("/ws/scan/{job_id}")
async def scan_progress_websocket(websocket: WebSocket, job_id: int):
    """WebSocket endpoint for real-time scan progress."""
    await websocket.accept()

    if job_id not in active_connections:
        active_connections[job_id] = []
    active_connections[job_id].append(websocket)

    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except Exception:
        pass
    finally:
        if job_id in active_connections:
            active_connections[job_id].remove(websocket)


async def run_scan_job(
    job_id: int,
    codebase_path: str,
    ecosystem: str,
    package_filter: str | None,
) -> None:
    """Background task to run a CVE scan."""
    from src.database.connection import get_db_context

    async with get_db_context() as db:
        # Update job status
        job = await db.get(ScanJob, job_id)
        if not job:
            return

        job.status = "running"
        job.started_at = datetime.utcnow()
        await db.commit()

        try:
            # Fetch CVEs
            aggregator = CVEAggregator()

            await notify_progress(job_id, {"stage": "fetching", "message": "Fetching CVEs..."})

            cves = await aggregator.fetch_cves(
                package_name=package_filter,
                ecosystem=ecosystem,
                limit=100,
            )

            job.total_cves = len(cves)
            await db.commit()

            await notify_progress(
                job_id,
                {"stage": "fetching", "message": f"Found {len(cves)} CVEs"},
            )

            # Store CVEs in database
            for cve_data in cves:
                existing = await db.get(CVE, cve_data.id)
                if not existing:
                    cve = CVE(
                        id=cve_data.id,
                        title=cve_data.title,
                        description=cve_data.description,
                        severity=cve_data.severity,
                        cvss_score=cve_data.cvss_score,
                        cvss_vector=cve_data.cvss_vector,
                        source=cve_data.source,
                        source_url=cve_data.source_url,
                        published_at=cve_data.published_at,
                        modified_at=cve_data.modified_at,
                        affected_packages=json.dumps(cve_data.affected_packages),
                        affected_versions=json.dumps(cve_data.affected_versions),
                        references=json.dumps(cve_data.references),
                    )
                    db.add(cve)

            await db.commit()

            # Run triage
            await notify_progress(
                job_id,
                {"stage": "triaging", "message": "Starting triage analysis..."},
            )

            orchestrator = TriageOrchestrator()

            async def progress_callback(current: int, total: int, cve_id: str) -> None:
                job.processed_cves = current + 1
                await db.commit()
                await notify_progress(
                    job_id,
                    {
                        "stage": "triaging",
                        "current": current + 1,
                        "total": total,
                        "cve_id": cve_id,
                        "message": f"Analyzing {cve_id} ({current + 1}/{total})",
                    },
                )

            decisions = await orchestrator.run_triage(
                codebase_path=codebase_path,
                cves=cves,
                ecosystem=ecosystem,
                progress_callback=progress_callback,
            )

            # Store triage results
            affected_count = 0
            for decision in decisions:
                status = (
                    TriageStatus.AFFECTED.value
                    if decision.is_affected
                    else TriageStatus.NOT_AFFECTED.value
                )

                triage = TriageResult(
                    cve_id=decision.cve_id,
                    codebase_path=codebase_path,
                    status=status,
                    is_affected=decision.is_affected,
                    confidence=decision.confidence,
                    reasoning=decision.reasoning,
                    affected_files=json.dumps(decision.affected_files),
                    affected_dependencies=json.dumps(decision.affected_dependencies),
                    remediation=decision.remediation,
                    priority_score=decision.priority_score,
                )
                db.add(triage)

                if decision.is_affected:
                    affected_count += 1

            job.affected_count = affected_count
            job.status = "completed"
            job.completed_at = datetime.utcnow()
            await db.commit()

            await notify_progress(
                job_id,
                {
                    "stage": "completed",
                    "message": f"Scan complete. {affected_count} affected CVEs found.",
                    "affected_count": affected_count,
                },
            )

        except Exception as e:
            logger.error(f"Scan job {job_id} failed: {e}")
            job.status = "failed"
            job.error_message = str(e)
            await db.commit()

            await notify_progress(
                job_id,
                {"stage": "error", "message": f"Scan failed: {e}"},
            )


@router.post("/scan", response_model=ScanResponse)
async def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Start a new CVE scan for a codebase."""
    # Validate codebase path
    path = Path(request.codebase_path)
    if not path.exists():
        raise HTTPException(status_code=400, detail=f"Path does not exist: {request.codebase_path}")

    # Create scan job
    job = ScanJob(
        codebase_path=request.codebase_path,
        status="pending",
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    # Start background scan
    background_tasks.add_task(
        run_scan_job,
        job.id,
        request.codebase_path,
        request.ecosystem,
        request.package_filter,
    )

    return ScanResponse(
        job_id=job.id,
        status="pending",
        message="Scan started. Connect to WebSocket for progress updates.",
    )


@router.get("/scan/{job_id}")
async def get_scan_status(
    job_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get the status of a scan job."""
    job = await db.get(ScanJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")

    return {
        "id": job.id,
        "status": job.status,
        "codebase_path": job.codebase_path,
        "total_cves": job.total_cves,
        "processed_cves": job.processed_cves,
        "affected_count": job.affected_count,
        "error_message": job.error_message,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
    }


@router.get("/cves", response_model=list[CVEResponse])
async def list_cves(
    db: Annotated[AsyncSession, Depends(get_db)],
    severity: str | None = Query(None, description="Filter by severity"),
    limit: int = Query(50, le=200),
    offset: int = Query(0),
):
    """List CVEs with optional filtering."""
    query = select(CVE).offset(offset).limit(limit)

    if severity:
        query = query.where(CVE.severity == severity.lower())

    query = query.order_by(CVE.created_at.desc())

    result = await db.execute(query)
    cves = result.scalars().all()

    return [
        CVEResponse(
            id=cve.id,
            title=cve.title,
            description=cve.description,
            severity=cve.severity,
            cvss_score=cve.cvss_score,
            source=cve.source,
            source_url=cve.source_url,
            published_at=cve.published_at,
            affected_packages=json.loads(cve.affected_packages) if cve.affected_packages else [],
        )
        for cve in cves
    ]


@router.get("/cves/{cve_id}")
async def get_cve(
    cve_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get detailed information about a specific CVE."""
    cve = await db.get(CVE, cve_id)
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")

    # Get triage results
    result = await db.execute(
        select(TriageResult).where(TriageResult.cve_id == cve_id)
    )
    triage_results = result.scalars().all()

    return {
        "cve": {
            "id": cve.id,
            "title": cve.title,
            "description": cve.description,
            "severity": cve.severity,
            "cvss_score": cve.cvss_score,
            "cvss_vector": cve.cvss_vector,
            "source": cve.source,
            "source_url": cve.source_url,
            "published_at": cve.published_at,
            "affected_packages": json.loads(cve.affected_packages) if cve.affected_packages else [],
            "affected_versions": json.loads(cve.affected_versions) if cve.affected_versions else {},
            "references": json.loads(cve.references) if cve.references else [],
        },
        "triage_results": [
            {
                "id": tr.id,
                "codebase_path": tr.codebase_path,
                "status": tr.status,
                "is_affected": tr.is_affected,
                "confidence": tr.confidence,
                "reasoning": tr.reasoning,
                "remediation": tr.remediation,
                "priority_score": tr.priority_score,
            }
            for tr in triage_results
        ],
    }


@router.get("/triage", response_model=list[TriageResultResponse])
async def list_triage_results(
    db: Annotated[AsyncSession, Depends(get_db)],
    status: str | None = Query(None, description="Filter by status"),
    affected_only: bool = Query(False, description="Show only affected CVEs"),
    limit: int = Query(50, le=200),
    offset: int = Query(0),
):
    """List triage results with filtering."""
    query = select(TriageResult).offset(offset).limit(limit)

    if status:
        query = query.where(TriageResult.status == status)

    if affected_only:
        query = query.where(TriageResult.is_affected == True)

    query = query.order_by(TriageResult.priority_score.desc().nulls_last())

    result = await db.execute(query)
    triage_results = result.scalars().all()

    # Get owners for each result
    responses = []
    for tr in triage_results:
        owners_result = await db.execute(
            select(Ownership).where(Ownership.triage_result_id == tr.id)
        )
        owners = owners_result.scalars().all()

        responses.append(
            TriageResultResponse(
                id=tr.id,
                cve_id=tr.cve_id,
                status=tr.status,
                is_affected=tr.is_affected,
                confidence=tr.confidence,
                reasoning=tr.reasoning,
                priority_score=tr.priority_score,
                remediation=tr.remediation,
                affected_files=json.loads(tr.affected_files) if tr.affected_files else [],
                owners=[
                    {"identifier": o.owner, "source": o.source, "confidence": o.confidence}
                    for o in owners
                ],
            )
        )

    return responses


@router.post("/triage/{triage_id}/override")
async def override_triage(
    triage_id: int,
    override: TriageOverride,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Manually override a triage decision."""
    triage = await db.get(TriageResult, triage_id)
    if not triage:
        raise HTTPException(status_code=404, detail="Triage result not found")

    triage.is_affected = override.is_affected
    triage.status = (
        TriageStatus.AFFECTED.value if override.is_affected else TriageStatus.NOT_AFFECTED.value
    )
    triage.manual_override = True
    triage.override_reason = override.reason

    await db.commit()

    return {"message": "Triage decision overridden", "id": triage_id}


@router.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get dashboard statistics."""
    # Total CVEs
    total_result = await db.execute(select(CVE))
    total_cves = len(total_result.scalars().all())

    # Triage stats
    triage_result = await db.execute(select(TriageResult))
    all_triage = triage_result.scalars().all()

    triaged_count = len([t for t in all_triage if t.status != TriageStatus.PENDING.value])
    affected_count = len([t for t in all_triage if t.is_affected])
    pending_count = len([t for t in all_triage if t.status == TriageStatus.PENDING.value])

    # Severity counts
    cve_result = await db.execute(select(CVE))
    all_cves = cve_result.scalars().all()

    critical_count = len([c for c in all_cves if c.severity == "critical"])
    high_count = len([c for c in all_cves if c.severity == "high"])

    return DashboardStats(
        total_cves=total_cves,
        triaged_count=triaged_count,
        affected_count=affected_count,
        pending_count=pending_count,
        critical_count=critical_count,
        high_count=high_count,
    )
