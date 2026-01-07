"""NVD (National Vulnerability Database) API client."""

import asyncio
import logging
from datetime import datetime

import httpx

from src.config import get_settings
from src.cve_sources.base import CVEData, CVESource

logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDSource(CVESource):
    """CVE source using the NVD API."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self._rate_limit_delay = 0.6 if self.settings.nvd_api_key else 6.0  # Requests per second

    @property
    def name(self) -> str:
        return "nvd"

    async def fetch_cves(
        self,
        keywords: list[str] | None = None,
        package_name: str | None = None,
        ecosystem: str | None = None,
        since: datetime | None = None,
        limit: int = 100,
    ) -> list[CVEData]:
        """Fetch CVEs from NVD API."""
        params: dict[str, str | int] = {
            "resultsPerPage": min(limit, 2000),
        }

        if keywords:
            params["keywordSearch"] = " ".join(keywords)

        if since:
            params["lastModStartDate"] = since.strftime("%Y-%m-%dT%H:%M:%S.000")
            params["lastModEndDate"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000")

        if package_name:
            params["virtualMatchString"] = f"cpe:2.3:*:*:{package_name}:*:*:*:*:*:*:*"

        headers = {}
        if self.settings.nvd_api_key:
            headers["apiKey"] = self.settings.nvd_api_key

        cves: list[CVEData] = []
        start_index = 0

        async with httpx.AsyncClient(timeout=30.0) as client:
            while len(cves) < limit:
                params["startIndex"] = start_index

                try:
                    response = await client.get(NVD_API_BASE, params=params, headers=headers)
                    response.raise_for_status()
                    data = response.json()
                except httpx.HTTPError as e:
                    logger.error(f"NVD API error: {e}")
                    break

                vulnerabilities = data.get("vulnerabilities", [])
                if not vulnerabilities:
                    break

                for vuln in vulnerabilities:
                    cve = self._parse_cve(vuln.get("cve", {}))
                    if cve:
                        cves.append(cve)
                        if len(cves) >= limit:
                            break

                total_results = data.get("totalResults", 0)
                start_index += len(vulnerabilities)

                if start_index >= total_results:
                    break

                # Rate limiting
                await asyncio.sleep(self._rate_limit_delay)

        return cves

    async def get_cve(self, cve_id: str) -> CVEData | None:
        """Get a specific CVE from NVD."""
        headers = {}
        if self.settings.nvd_api_key:
            headers["apiKey"] = self.settings.nvd_api_key

        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.get(
                    NVD_API_BASE,
                    params={"cveId": cve_id},
                    headers=headers,
                )
                response.raise_for_status()
                data = response.json()
            except httpx.HTTPError as e:
                logger.error(f"NVD API error fetching {cve_id}: {e}")
                return None

        vulnerabilities = data.get("vulnerabilities", [])
        if vulnerabilities:
            return self._parse_cve(vulnerabilities[0].get("cve", {}))
        return None

    def _parse_cve(self, cve_data: dict) -> CVEData | None:
        """Parse NVD CVE data into CVEData."""
        cve_id = cve_data.get("id")
        if not cve_id:
            return None

        # Get description (prefer English)
        descriptions = cve_data.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")

        # Get CVSS score (prefer v3.1, then v3.0, then v2.0)
        cvss_score = None
        cvss_vector = None
        metrics = cve_data.get("metrics", {})

        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics and metrics[version]:
                cvss_data = metrics[version][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString")
                break

        # Get affected configurations
        affected_packages: list[str] = []
        affected_versions: dict[str, list[str]] = {}

        configurations = cve_data.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable"):
                        cpe = cpe_match.get("criteria", "")
                        # Parse CPE: cpe:2.3:a:vendor:product:version:...
                        parts = cpe.split(":")
                        if len(parts) >= 5:
                            product = parts[4]
                            if product not in affected_packages:
                                affected_packages.append(product)

                            version_start = cpe_match.get("versionStartIncluding")
                            version_end = cpe_match.get("versionEndExcluding")
                            if version_start or version_end:
                                version_range = []
                                if version_start:
                                    version_range.append(f">={version_start}")
                                if version_end:
                                    version_range.append(f"<{version_end}")
                                affected_versions.setdefault(product, []).extend(version_range)

        # Get references
        references = [ref.get("url") for ref in cve_data.get("references", []) if ref.get("url")]

        # Parse dates
        published_at = None
        modified_at = None
        if cve_data.get("published"):
            try:
                published_at = datetime.fromisoformat(cve_data["published"].replace("Z", "+00:00"))
            except ValueError:
                pass
        if cve_data.get("lastModified"):
            try:
                modified_at = datetime.fromisoformat(cve_data["lastModified"].replace("Z", "+00:00"))
            except ValueError:
                pass

        return CVEData(
            id=cve_id,
            title=cve_id,  # NVD doesn't have separate titles
            description=description,
            severity=self._normalize_severity(cvss_score),
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            source="nvd",
            source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            published_at=published_at,
            modified_at=modified_at,
            affected_packages=affected_packages,
            affected_versions=affected_versions,
            references=references,
        )
