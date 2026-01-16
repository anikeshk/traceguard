"""HTTP client for TraceGuard API."""

import httpx
from typing import Optional


class TraceGuardAPIClient:
    """Client for interacting with the TraceGuard FastAPI backend."""

    def __init__(self, base_url: str = "http://localhost:8000"):
        """Initialize the API client.

        Args:
            base_url: Base URL of the TraceGuard API.
        """
        self._base_url = base_url.rstrip("/")
        self._client = httpx.Client(timeout=30.0, follow_redirects=True)

    def health_check(self) -> dict:
        """Check if the API is healthy."""
        response = self._client.get(f"{self._base_url}/api/v1/health")
        response.raise_for_status()
        return response.json()

    def get_stats(self) -> dict:
        """Get dashboard statistics."""
        response = self._client.get(f"{self._base_url}/api/v1/stats")
        response.raise_for_status()
        return response.json()

    def list_jobs(self, page: int = 1, page_size: int = 20) -> dict:
        """List jobs with pagination."""
        response = self._client.get(
            f"{self._base_url}/api/v1/jobs",
            params={"page": page, "page_size": page_size},
        )
        response.raise_for_status()
        return response.json()

    def get_job(self, job_id: int) -> dict:
        """Get detailed job information."""
        response = self._client.get(f"{self._base_url}/api/v1/jobs/{job_id}")
        response.raise_for_status()
        return response.json()

    def create_job(self, codebase_path: str, cve_ids: list[str]) -> dict:
        """Create a new scan job."""
        response = self._client.post(
            f"{self._base_url}/api/v1/jobs",
            json={
                "codebase_path": codebase_path,
                "cve_ids": cve_ids,
            },
        )
        response.raise_for_status()
        return response.json()

    def delete_job(self, job_id: int) -> bool:
        """Delete a job."""
        response = self._client.delete(f"{self._base_url}/api/v1/jobs/{job_id}")
        return response.status_code == 204

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()


def get_api_client(base_url: Optional[str] = None) -> TraceGuardAPIClient:
    """Get an API client instance.

    Args:
        base_url: Optional base URL override.

    Returns:
        TraceGuardAPIClient instance.
    """
    import os

    url = base_url or os.getenv("STREAMLIT_API_URL", "http://localhost:8000")
    return TraceGuardAPIClient(url)
