"""OSV (Open Source Vulnerabilities) Database client."""

import logging
from datetime import datetime

import httpx
from packageurl import PackageURL

from src.cve_sources.base import CVEData, CVESource

logger = logging.getLogger(__name__)

OSV_API_BASE = "https://api.osv.dev/v1"


def _ecosystem_to_purl_type(ecosystem: str) -> str:
    """Convert ecosystem name to PURL type.

    Args:
        ecosystem: Ecosystem name (e.g., "PyPI", "npm", "Maven")

    Returns:
        PURL type string (e.g., "pypi", "npm", "maven")
    """
    ecosystem_map = {
        "PyPI": "pypi",
        "npm": "npm",
        "Maven": "maven",
        "Go": "golang",
        "RubyGems": "gem",
        "NuGet": "nuget",
        "Cargo": "cargo",
        "Composer": "composer",
    }
    return ecosystem_map.get(ecosystem, ecosystem.lower())


class OSVSource(CVESource):
    """CVE source using the OSV Database API."""

    @property
    def name(self) -> str:
        return "osv"

    async def fetch_cves(
        self,
        keywords: list[str] | None = None,
        package_name: str | None = None,
        ecosystem: str | None = None,
        since: datetime | None = None,
        limit: int = 100,
    ) -> list[CVEData]:
        """Fetch vulnerabilities from OSV API."""
        if not package_name and not ecosystem:
            logger.warning("OSV requires package_name or ecosystem for efficient queries")
            return []

        query: dict = {}

        if package_name:
            # Use PURL format for better standardization
            purl_type = _ecosystem_to_purl_type(ecosystem) if ecosystem else "pypi"
            purl = PackageURL(type=purl_type, name=package_name)
            query["package"] = {"purl": str(purl)}
            logger.debug(f"OSV query with PURL: {query}")

        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.post(
                    f"{OSV_API_BASE}/query",
                    json=query,
                )
                response.raise_for_status()
                data = response.json()
            except httpx.HTTPError as e:
                logger.error(f"OSV API error: {e}")
                return []

        cves: list[CVEData] = []
        for vuln in data.get("vulns", [])[:limit]:
            cve = self._parse_vulnerability(vuln)
            if cve:
                # Filter by modification date if specified
                if since and cve.modified_at and cve.modified_at < since:
                    continue
                cves.append(cve)

        return cves

    async def get_cve(self, cve_id: str) -> CVEData | None:
        """Get a specific vulnerability from OSV."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.get(f"{OSV_API_BASE}/vulns/{cve_id}")
                if response.status_code == 404:
                    return None
                response.raise_for_status()
                data = response.json()
            except httpx.HTTPError as e:
                logger.error(f"OSV API error fetching {cve_id}: {e}")
                return None

        return self._parse_vulnerability(data)

    async def query_by_package(
        self,
        package_name: str,
        version: str | None = None,
        ecosystem: str = "PyPI",
    ) -> list[CVEData]:
        """Query OSV for vulnerabilities affecting a specific package."""
        # Convert ecosystem to PURL type
        purl_type = _ecosystem_to_purl_type(ecosystem)

        # Handle npm scoped packages (e.g., @angular/core)
        if purl_type == "npm" and "/" in package_name:
            namespace, name = package_name.split("/", 1)
            namespace = namespace.lstrip("@")
            if version:
                purl = PackageURL(
                    type=purl_type, namespace=namespace, name=name, version=version
                )
            else:
                purl = PackageURL(type=purl_type, namespace=namespace, name=name)
        else:
            # Create PURL with or without version
            if version:
                purl = PackageURL(type=purl_type, name=package_name, version=version)
            else:
                purl = PackageURL(type=purl_type, name=package_name)

        query: dict = {"package": {"purl": str(purl)}}
        logger.debug(f"OSV query_by_package with PURL: {query}")

        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.post(
                    f"{OSV_API_BASE}/query",
                    json=query,
                )
                response.raise_for_status()
                data = response.json()
            except httpx.HTTPError as e:
                logger.error(f"OSV API error querying {package_name}: {e}")
                return []

        return [
            cve for vuln in data.get("vulns", [])
            if (cve := self._parse_vulnerability(vuln))
        ]

    def _parse_vulnerability(self, vuln_data: dict) -> CVEData | None:
        """Parse OSV vulnerability data into CVEData."""
        vuln_id = vuln_data.get("id")
        if not vuln_id:
            return None

        # Get CVE alias if available
        aliases = vuln_data.get("aliases", [])
        cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln_id)

        # Get severity
        cvss_score = None
        cvss_vector = None
        severity_list = vuln_data.get("severity", [])
        for sev in severity_list:
            if sev.get("type") == "CVSS_V3":
                cvss_vector = sev.get("score")
                # Extract base score from vector if present
                if cvss_vector and "/" in cvss_vector:
                    try:
                        # CVSS vector format includes score sometimes
                        score_part = cvss_vector.split("/")[0]
                        if ":" in score_part:
                            cvss_score = float(score_part.split(":")[-1])
                    except (ValueError, IndexError):
                        pass
                break

        # Get affected packages
        affected_packages: list[str] = []
        affected_versions: dict[str, list[str]] = {}

        for affected in vuln_data.get("affected", []):
            pkg = affected.get("package", {})
            pkg_name = pkg.get("name")
            if pkg_name and pkg_name not in affected_packages:
                affected_packages.append(pkg_name)

            # Get version ranges
            for version_range in affected.get("ranges", []):
                events = version_range.get("events", [])
                for event in events:
                    if "introduced" in event:
                        affected_versions.setdefault(pkg_name, []).append(
                            f">={event['introduced']}"
                        )
                    if "fixed" in event:
                        affected_versions.setdefault(pkg_name, []).append(
                            f"<{event['fixed']}"
                        )

        # Get references
        references = [
            ref.get("url") for ref in vuln_data.get("references", [])
            if ref.get("url")
        ]

        # Parse dates
        published_at = None
        modified_at = None
        if vuln_data.get("published"):
            try:
                published_at = datetime.fromisoformat(
                    vuln_data["published"].replace("Z", "+00:00")
                )
            except ValueError:
                pass
        if vuln_data.get("modified"):
            try:
                modified_at = datetime.fromisoformat(
                    vuln_data["modified"].replace("Z", "+00:00")
                )
            except ValueError:
                pass

        return CVEData(
            id=cve_id,
            title=vuln_data.get("summary"),
            description=vuln_data.get("details", vuln_data.get("summary", "")),
            severity=self._normalize_severity(cvss_score),
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            source="osv",
            source_url=f"https://osv.dev/vulnerability/{vuln_id}",
            published_at=published_at,
            modified_at=modified_at,
            affected_packages=affected_packages,
            affected_versions=affected_versions,
            references=references,
        )
