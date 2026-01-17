"""
Async client for OpenAI API.

Provides CVE summarization capabilities for creating developer-friendly
security alert descriptions.
"""

import json
import logging
from dataclasses import dataclass

import httpx

from traceguard.config import get_openai_api_key

logger = logging.getLogger(__name__)


@dataclass
class CVESummary:
    """Developer-friendly CVE summary."""

    title: str
    what_is_vulnerable: str
    why_it_matters: str
    repo_impact: str
    recommended_action: str
    urgency_signal: str


class OpenAIClient:
    """Async client for OpenAI API - CVE summarization."""

    BASE_URL = "https://api.openai.com/v1"
    MODEL = "gpt-4o-mini"

    def __init__(self, api_key: str | None = None) -> None:
        self._api_key = api_key or get_openai_api_key()

    def _get_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

    async def summarize_cve(
        self,
        cve_id: str | None,
        severity: str,
        summary: str | None,
        description: str | None,
        package_name: str,
        package_ecosystem: str,
        vulnerable_version_range: str | None,
        patched_version: str | None,
        repo_name: str,
    ) -> CVESummary:
        """
        Transform raw CVE data into a developer-friendly summary.

        Uses GPT to convert technical CVE information into actionable,
        jargon-free guidance that developers can understand and act on.
        """
        system_prompt = """You are a security engineer translating CVE data into clear,
developer-friendly summaries. Avoid security jargon. Be concise but complete.
Your output must be actionable - developers should know exactly what to do."""

        user_prompt = f"""Summarize this security vulnerability for a developer:

CVE ID: {cve_id or 'Not assigned'}
Severity: {severity}
Package: {package_name} ({package_ecosystem})
Vulnerable versions: {vulnerable_version_range or 'Unknown'}
Patched version: {patched_version or 'No patch available'}
Repository: {repo_name}

Original summary: {summary or 'None provided'}
Description: {description or 'None provided'}

Provide a JSON response with these exact fields:
{{
    "title": "Brief ticket title (max 80 chars)",
    "what_is_vulnerable": "Plain language: what component is vulnerable and how",
    "why_it_matters": "Potential impact if not fixed (be specific)",
    "repo_impact": "How this specifically affects the {repo_name} repository",
    "recommended_action": "Clear step-by-step remediation (include version to upgrade to if known)",
    "urgency_signal": "One of: immediate, soon, when_convenient"
}}"""

        url = f"{self.BASE_URL}/chat/completions"
        payload = {
            "model": self.MODEL,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.3,
        }

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                url,
                headers=self._get_headers(),
                json=payload,
            )

            if response.status_code != 200:
                logger.error(
                    f"OpenAI API error {response.status_code}: {response.text}"
                )

            response.raise_for_status()
            data = response.json()

            content = data["choices"][0]["message"]["content"]
            parsed = json.loads(content)

            logger.info(f"Summarized CVE {cve_id or 'unknown'}: {parsed['title']}")

            return CVESummary(
                title=parsed["title"],
                what_is_vulnerable=parsed["what_is_vulnerable"],
                why_it_matters=parsed["why_it_matters"],
                repo_impact=parsed["repo_impact"],
                recommended_action=parsed["recommended_action"],
                urgency_signal=parsed["urgency_signal"],
            )
