"""Statistics service for dashboard metrics."""

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from traceguard.models.job import Job, JobCVE, ApplicabilityStatus
from traceguard.models.cve import GeneratedIssue, CVEContext
from traceguard.schemas.stats import DashboardStats, SeverityBreakdown

logger = logging.getLogger(__name__)


class StatsService:
    """Service for calculating dashboard statistics."""

    def __init__(self, session: AsyncSession):
        """Initialize the stats service.

        Args:
            session: Async database session.
        """
        self._session = session

    async def get_dashboard_stats(self) -> DashboardStats:
        """Get dashboard statistics.

        Returns:
            DashboardStats with all metrics.
        """
        # Total jobs
        total_jobs_query = select(func.count(Job.id))
        result = await self._session.execute(total_jobs_query)
        total_jobs = result.scalar_one()

        # Jobs in last 7 days
        seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
        recent_jobs_query = select(func.count(Job.id)).where(
            Job.created_at >= seven_days_ago
        )
        result = await self._session.execute(recent_jobs_query)
        jobs_last_7_days = result.scalar_one()

        # Total CVEs analyzed
        cves_analyzed_query = select(func.count(JobCVE.id))
        result = await self._session.execute(cves_analyzed_query)
        cves_analyzed = result.scalar_one()

        # Applicable CVEs
        applicable_query = select(func.count(JobCVE.id)).where(
            JobCVE.applicability == ApplicabilityStatus.APPLICABLE
        )
        result = await self._session.execute(applicable_query)
        applicable_cves = result.scalar_one()

        # Not applicable CVEs
        not_applicable_query = select(func.count(JobCVE.id)).where(
            JobCVE.applicability == ApplicabilityStatus.NOT_APPLICABLE
        )
        result = await self._session.execute(not_applicable_query)
        not_applicable_cves = result.scalar_one()

        # Issues generated
        issues_query = select(func.count(GeneratedIssue.id))
        result = await self._session.execute(issues_query)
        issues_generated = result.scalar_one()

        # Severity breakdown from CVE context cache
        severity_breakdown = await self._get_severity_breakdown()

        return DashboardStats(
            total_jobs=total_jobs,
            jobs_last_7_days=jobs_last_7_days,
            cves_analyzed=cves_analyzed,
            applicable_cves=applicable_cves,
            not_applicable_cves=not_applicable_cves,
            issues_generated=issues_generated,
            by_severity=severity_breakdown,
        )

    async def _get_severity_breakdown(self) -> SeverityBreakdown:
        """Get breakdown of applicable CVEs by severity.

        Returns:
            SeverityBreakdown with counts per severity level.
        """
        breakdown = SeverityBreakdown()

        # Get applicable CVE IDs
        applicable_query = select(JobCVE.cve_id).where(
            JobCVE.applicability == ApplicabilityStatus.APPLICABLE
        ).distinct()
        result = await self._session.execute(applicable_query)
        applicable_cve_ids = [row[0] for row in result.fetchall()]

        if not applicable_cve_ids:
            return breakdown

        # Get severity from cached CVE contexts
        for cve_id in applicable_cve_ids:
            context_query = select(CVEContext.severity).where(
                CVEContext.cve_id == cve_id
            )
            result = await self._session.execute(context_query)
            row = result.first()

            if row and row[0]:
                severity = row[0].upper()
                if severity == "CRITICAL":
                    breakdown.critical += 1
                elif severity == "HIGH":
                    breakdown.high += 1
                elif severity == "MEDIUM":
                    breakdown.medium += 1
                elif severity == "LOW":
                    breakdown.low += 1
                else:
                    breakdown.unknown += 1
            else:
                breakdown.unknown += 1

        return breakdown
