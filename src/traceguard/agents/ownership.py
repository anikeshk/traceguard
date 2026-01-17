import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from traceguard.db.models import Job, Owner, JobStatus
from traceguard.github.client import GitHubClient

logger = logging.getLogger(__name__)


class OwnershipResolutionAgent:
    """Agent that resolves repository ownership and saves owner info."""

    def __init__(self, session: AsyncSession, github_client: GitHubClient | None = None):
        self.session = session
        self.github_client = github_client or GitHubClient()

    async def run(self, job_id: int) -> Owner:
        """
        Resolve the owner for the job's repository and save owner info.

        Returns the created Owner record.
        """
        # Get the job
        result = await self.session.execute(select(Job).where(Job.id == job_id))
        job = result.scalar_one_or_none()

        if not job:
            raise ValueError(f"Job {job_id} not found")

        logger.info(
            f"Starting ownership resolution for job {job_id} ({job.repo_full_name})"
        )

        # Update job status
        job.status = JobStatus.RESOLVING_OWNER
        await self.session.flush()

        try:
            # Fetch user info from GitHub
            user = await self.github_client.get_user(job.repo_owner)

            logger.info(
                f"Resolved owner for {job.repo_full_name}: "
                f"{user.login} ({user.email or 'no public email'})"
            )

            # Create Owner record
            owner = Owner(
                job_id=job.id,
                username=user.login,
                email=user.email,
                name=user.name,
            )
            self.session.add(owner)

            # Mark job as completed
            job.status = JobStatus.COMPLETED
            await self.session.flush()

            logger.info(f"Ownership resolution completed for job {job_id}")
            return owner

        except Exception as e:
            logger.error(f"Ownership resolution failed for job {job_id}: {e}")
            job.status = JobStatus.FAILED
            job.error_message = str(e)
            await self.session.flush()
            raise
