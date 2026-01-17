"""
Async client for Jira REST API.

Provides ticket creation and management capabilities for security
vulnerability tracking.
"""

import base64
import logging
from dataclasses import dataclass

import httpx

from traceguard.config import (
    get_jira_host,
    get_jira_token,
    get_jira_user_email,
    get_jira_project_key,
)

logger = logging.getLogger(__name__)


@dataclass
class JiraIssue:
    """Represents a created Jira issue."""

    key: str
    id: str
    self_url: str
    browse_url: str


@dataclass
class JiraUser:
    """Represents a Jira user for assignment."""

    account_id: str
    display_name: str
    email_address: str | None


class JiraClient:
    """Async client for Jira REST API."""

    SEVERITY_TO_PRIORITY = {
        "critical": "Highest",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "unknown": "Medium",
    }

    def __init__(
        self,
        host: str | None = None,
        token: str | None = None,
        user_email: str | None = None,
        project_key: str | None = None,
    ) -> None:
        self._host = host or get_jira_host()
        self._token = token or get_jira_token()
        self._user_email = user_email or get_jira_user_email()
        self._project_key = project_key or get_jira_project_key()

    def _get_headers(self) -> dict[str, str]:
        """Generate auth headers for Jira Cloud API (Basic Auth with API token)."""
        credentials = f"{self._user_email}:{self._token}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return {
            "Authorization": f"Basic {encoded}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def get_priority_name(self, severity: str) -> str:
        """Map CVE severity to Jira priority name."""
        return self.SEVERITY_TO_PRIORITY.get(severity.lower(), "Medium")

    async def get_issue_types(self, project_key: str | None = None) -> list[dict]:
        """
        Get available issue types for a project.

        Returns list of issue type dicts with 'id', 'name', 'description'.
        """
        project = project_key or self._project_key
        url = f"{self._host}/rest/api/3/issue/createmeta/{project}/issuetypes"

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                url,
                headers=self._get_headers(),
            )

            if response.status_code != 200:
                logger.warning(
                    f"Failed to get issue types: {response.status_code} - {response.text}"
                )
                return []

            data = response.json()
            return data.get("issueTypes", data.get("values", []))

    async def find_user_by_email(self, email: str) -> JiraUser | None:
        """
        Find a Jira user by email address for ticket assignment.

        Returns None if user not found.
        """
        url = f"{self._host}/rest/api/3/user/search"
        params = {"query": email}

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                url,
                headers=self._get_headers(),
                params=params,
            )

            if response.status_code != 200:
                logger.warning(f"User search failed: {response.status_code}")
                return None

            users = response.json()
            if not users:
                return None

            user = users[0]
            return JiraUser(
                account_id=user["accountId"],
                display_name=user.get("displayName", ""),
                email_address=user.get("emailAddress"),
            )

    async def create_issue(
        self,
        summary: str,
        description: str,
        priority: str,
        labels: list[str] | None = None,
        assignee_account_id: str | None = None,
        project_key: str | None = None,
        issue_type: str = "Bug",
    ) -> JiraIssue:
        """
        Create a new Jira issue.

        Args:
            summary: Issue title
            description: Full description (plain text)
            priority: Priority name (Highest, High, Medium, Low, Lowest)
            labels: Optional list of labels
            assignee_account_id: Jira account ID for assignment
            project_key: Override default project key
            issue_type: Issue type name (default: Bug, falls back to Task)

        Returns:
            Created JiraIssue with key and URLs
        """
        project = project_key or self._project_key
        url = f"{self._host}/rest/api/3/issue"

        # Fetch available issue types and find the right one
        issue_types = await self.get_issue_types(project)
        issue_type_id = None

        # Try to find the requested issue type
        for it in issue_types:
            if it.get("name", "").lower() == issue_type.lower():
                issue_type_id = it["id"]
                break

        # Fall back to Task if requested type not found
        if not issue_type_id:
            for it in issue_types:
                if it.get("name", "").lower() == "task":
                    issue_type_id = it["id"]
                    issue_type = "Task"
                    logger.info(f"Issue type 'Bug' not found, using 'Task' instead")
                    break

        # If still not found, use the first available issue type
        if not issue_type_id and issue_types:
            issue_type_id = issue_types[0]["id"]
            issue_type = issue_types[0].get("name", "Unknown")
            logger.info(f"Using first available issue type: {issue_type}")

        if not issue_type_id:
            raise ValueError(f"No issue types available for project {project}")

        fields: dict = {
            "project": {"key": project},
            "summary": summary,
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": description}],
                    }
                ],
            },
            "issuetype": {"id": issue_type_id},
            "priority": {"name": priority},
        }

        if labels:
            fields["labels"] = labels

        if assignee_account_id:
            fields["assignee"] = {"accountId": assignee_account_id}

        payload = {"fields": fields}

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                url,
                headers=self._get_headers(),
                json=payload,
            )

            if response.status_code not in (200, 201):
                logger.error(
                    f"Jira create issue failed {response.status_code}: {response.text}"
                )

            response.raise_for_status()
            data = response.json()

            logger.info(f"Created Jira issue: {data['key']}")

            return JiraIssue(
                key=data["key"],
                id=data["id"],
                self_url=data["self"],
                browse_url=f"{self._host}/browse/{data['key']}",
            )

    def build_ticket_description(
        self,
        cve_id: str | None,
        severity: str,
        what_is_vulnerable: str,
        why_it_matters: str,
        repo_impact: str,
        recommended_action: str,
        package_name: str,
        package_ecosystem: str,
        vulnerable_version_range: str | None,
        patched_version: str | None,
        html_url: str,
        repo_full_name: str,
    ) -> str:
        """
        Build a formatted Jira ticket description from CVE summary data.

        Returns plain text formatted for Jira's description field.
        """
        sections = [
            f"Repository: {repo_full_name}",
            f"CVE: {cve_id or 'Not assigned'}",
            f"Severity: {severity.upper()}",
            "",
            "== What is Vulnerable ==",
            what_is_vulnerable,
            "",
            "== Why This Matters ==",
            why_it_matters,
            "",
            "== Impact on This Repository ==",
            repo_impact,
            "",
            "== Recommended Action ==",
            recommended_action,
            "",
            "== Technical Details ==",
            f"Package: {package_name} ({package_ecosystem})",
            f"Vulnerable versions: {vulnerable_version_range or 'Unknown'}",
            f"Patched version: {patched_version or 'No patch available'}",
            "",
            "== References ==",
            f"GitHub Alert: {html_url}",
        ]

        if cve_id:
            sections.append(f"NVD: https://nvd.nist.gov/vuln/detail/{cve_id}")

        return "\n".join(sections)
