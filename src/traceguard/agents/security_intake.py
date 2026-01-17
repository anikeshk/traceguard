import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from traceguard.db.models import Job, Alert, JobStatus
from traceguard.github.client import GitHubClient

logger = logging.getLogger(__name__)


class SecurityIntakeAgent:
    """Agent that fetches Dependabot security alerts and saves CVE info."""

    def __init__(self, session: AsyncSession, github_client: GitHubClient | None = None):
        self.session = session
        self.github_client = github_client or GitHubClient()

    async def run(self, job_id: int) -> list[Alert]:
        """
        Fetch Dependabot alerts for the job's repository and save them.

        Returns the list of created Alert records.
        """
        # Get the job
        result = await self.session.execute(select(Job).where(Job.id == job_id))
        job = result.scalar_one_or_none()

        if not job:
            raise ValueError(f"Job {job_id} not found")

        logger.info(f"Starting security intake for job {job_id} ({job.repo_full_name})")

        # Update job status
        job.status = JobStatus.FETCHING_ALERTS
        await self.session.flush()

        try:
            # Fetch alerts from GitHub
            dependabot_alerts = await self.github_client.get_dependabot_alerts(
                owner=job.repo_owner,
                repo=job.repo_name,
            )

            logger.info(
                f"Found {len(dependabot_alerts)} open Dependabot alerts "
                f"for {job.repo_full_name}"
            )

            # Create Alert records
            alerts: list[Alert] = []
            for alert_data in dependabot_alerts:
                alert = Alert(
                    job_id=job.id,
                    alert_number=alert_data.number,
                    state=alert_data.state,
                    cve_id=alert_data.cve_id,
                    severity=alert_data.severity,
                    summary=alert_data.summary,
                    description=alert_data.description,
                    package_name=alert_data.package_name,
                    package_ecosystem=alert_data.package_ecosystem,
                    vulnerable_version_range=alert_data.vulnerable_version_range,
                    patched_version=alert_data.patched_version,
                    html_url=alert_data.html_url,
                )
                self.session.add(alert)
                alerts.append(alert)

            await self.session.flush()
            logger.info(f"Saved {len(alerts)} alerts for job {job_id}")

            return alerts

        except Exception as e:
            logger.error(f"Security intake failed for job {job_id}: {e}")
            job.status = JobStatus.FAILED
            job.error_message = str(e)
            await self.session.flush()
            raise
