"""OSV (Open Source Vulnerabilities) API client."""

import logging
from datetime import datetime, timezone
from typing import Optional

import httpx

from traceguard.cve_sources.base import CVESource
from traceguard.schemas.cve import AffectedPackage, CVEContextSchema

logger = logging.getLogger(__name__)

OSV_API_URL = "https://api.osv.dev/v1"


class OSVClient(CVESource):
    """Client for the OSV (Open Source Vulnerabilities) API.

    OSV is a distributed vulnerability database for open source software.
    API docs: https://osv.dev/docs/
    """

    def __init__(self, timeout: float = 30.0):
        """Initialize the OSV client.

        Args:
            timeout: HTTP request timeout in seconds.
        """
        self._client = httpx.AsyncClient(timeout=timeout)

    @property
    def source_name(self) -> str:
        return "osv"

    async def fetch_by_cve_id(self, cve_id: str) -> Optional[CVEContextSchema]:
        """Fetch CVE context by CVE identifier.

        OSV doesn't support direct CVE lookup, so we query by the CVE alias.
        """
        try:
            # OSV uses the vulnerability ID endpoint for direct lookups
            # CVE IDs can be found via the query endpoint with aliases
            response = await self._client.post(
                f"{OSV_API_URL}/query",
                json={"aliases": [cve_id]},
            )
            response.raise_for_status()
            data = response.json()

            vulns = data.get("vulns", [])
            if not vulns:
                logger.debug(f"No OSV entry found for CVE {cve_id}")
                return None

            # Return the first matching vulnerability
            return self._parse_osv_vulnerability(vulns[0])

        except httpx.HTTPStatusError as e:
            logger.error(f"OSV API error for {cve_id}: {e.response.status_code}")
            return None
        except Exception as e:
            logger.error(f"Error fetching CVE {cve_id} from OSV: {e}")
            return None

    async def fetch_by_ghsa_id(self, ghsa_id: str) -> Optional[CVEContextSchema]:
        """Fetch CVE context by GitHub Security Advisory ID."""
        try:
            # GHSA IDs are also aliases in OSV
            response = await self._client.post(
                f"{OSV_API_URL}/query",
                json={"aliases": [ghsa_id]},
            )
            response.raise_for_status()
            data = response.json()

            vulns = data.get("vulns", [])
            if not vulns:
                logger.debug(f"No OSV entry found for GHSA {ghsa_id}")
                return None

            return self._parse_osv_vulnerability(vulns[0])

        except httpx.HTTPStatusError as e:
            logger.error(f"OSV API error for {ghsa_id}: {e.response.status_code}")
            return None
        except Exception as e:
            logger.error(f"Error fetching GHSA {ghsa_id} from OSV: {e}")
            return None

    async def fetch_by_package(
        self,
        package_name: str,
        ecosystem: str,
        version: Optional[str] = None,
    ) -> list[CVEContextSchema]:
        """Fetch all CVEs affecting a specific package."""
        try:
            # Build the query payload using PURL format
            purl = self._build_purl(package_name, ecosystem, version)
            query_payload = {"package": {"purl": purl}}

            if version:
                query_payload["version"] = version

            response = await self._client.post(
                f"{OSV_API_URL}/query",
                json=query_payload,
            )
            response.raise_for_status()
            data = response.json()

            vulns = data.get("vulns", [])
            results = []
            for vuln in vulns:
                parsed = self._parse_osv_vulnerability(vuln)
                if parsed:
                    results.append(parsed)

            return results

        except httpx.HTTPStatusError as e:
            logger.error(f"OSV API error for package {package_name}: {e.response.status_code}")
            return []
        except Exception as e:
            logger.error(f"Error fetching vulnerabilities for {package_name}: {e}")
            return []

    async def fetch_by_osv_id(self, osv_id: str) -> Optional[CVEContextSchema]:
        """Fetch vulnerability by OSV ID directly."""
        try:
            response = await self._client.get(f"{OSV_API_URL}/vulns/{osv_id}")
            response.raise_for_status()
            data = response.json()
            return self._parse_osv_vulnerability(data)

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                logger.debug(f"OSV ID {osv_id} not found")
                return None
            logger.error(f"OSV API error for {osv_id}: {e.response.status_code}")
            return None
        except Exception as e:
            logger.error(f"Error fetching OSV ID {osv_id}: {e}")
            return None

    def _build_purl(
        self, package_name: str, ecosystem: str, version: Optional[str] = None
    ) -> str:
        """Build a Package URL (PURL) for the given package.

        PURL spec: https://github.com/package-url/purl-spec
        """
        # Map ecosystem names to PURL types
        ecosystem_to_purl_type = {
            "npm": "npm",
            "pypi": "pypi",
            "pip": "pypi",
            "maven": "maven",
            "go": "golang",
            "cargo": "cargo",
            "nuget": "nuget",
            "rubygems": "gem",
            "packagist": "composer",
        }

        purl_type = ecosystem_to_purl_type.get(ecosystem.lower(), ecosystem.lower())

        # Handle scoped npm packages (e.g., @types/node)
        if purl_type == "npm" and package_name.startswith("@"):
            # @scope/name -> pkg:npm/%40scope/name
            package_name = package_name.replace("@", "%40", 1)

        purl = f"pkg:{purl_type}/{package_name}"
        if version:
            purl += f"@{version}"

        return purl

    def _parse_osv_vulnerability(self, vuln: dict) -> Optional[CVEContextSchema]:
        """Parse an OSV vulnerability response into our schema."""
        try:
            osv_id = vuln.get("id", "")

            # Extract CVE and GHSA IDs from aliases
            cve_id = None
            ghsa_id = None
            aliases = vuln.get("aliases", [])
            for alias in aliases:
                if alias.startswith("CVE-"):
                    cve_id = alias
                elif alias.startswith("GHSA-"):
                    ghsa_id = alias

            # If no CVE ID found, use OSV ID as the identifier
            if not cve_id:
                cve_id = osv_id

            # Parse affected packages
            affected_packages = []
            fixed_versions_all = []

            for affected in vuln.get("affected", []):
                pkg = affected.get("package", {})
                pkg_name = pkg.get("name", "")
                ecosystem = pkg.get("ecosystem", "")

                # Extract version ranges
                ranges = affected.get("ranges", [])
                version_range = None
                fixed_versions = []

                for range_info in ranges:
                    events = range_info.get("events", [])
                    for event in events:
                        if "fixed" in event:
                            fixed_versions.append(event["fixed"])

                # Also check versions list
                versions = affected.get("versions", [])
                if versions:
                    version_range = f"affected versions: {', '.join(versions[:5])}"
                    if len(versions) > 5:
                        version_range += f" (+{len(versions) - 5} more)"

                if pkg_name:
                    affected_packages.append(
                        AffectedPackage(
                            name=pkg_name,
                            ecosystem=ecosystem,
                            version_range=version_range,
                            fixed_versions=fixed_versions,
                        )
                    )
                    fixed_versions_all.extend(fixed_versions)

            # Extract severity
            severity = None
            cvss_score = None
            severity_list = vuln.get("severity", [])
            for sev in severity_list:
                if sev.get("type") == "CVSS_V3":
                    score_str = sev.get("score", "")
                    # Try to extract numeric score from CVSS vector
                    try:
                        # CVSS vectors often have format like "CVSS:3.1/AV:N/..."
                        # The score might be in the database field
                        if "score" in vuln.get("database_specific", {}):
                            cvss_score = float(vuln["database_specific"]["score"])
                    except (ValueError, KeyError):
                        pass

            # Determine severity from CVSS score or database_specific
            db_specific = vuln.get("database_specific", {})
            if "severity" in db_specific:
                severity = db_specific["severity"].upper()
            elif cvss_score:
                if cvss_score >= 9.0:
                    severity = "CRITICAL"
                elif cvss_score >= 7.0:
                    severity = "HIGH"
                elif cvss_score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

            # Extract references
            references = [ref.get("url", "") for ref in vuln.get("references", []) if ref.get("url")]

            return CVEContextSchema(
                cve_id=cve_id,
                ghsa_id=ghsa_id,
                osv_id=osv_id,
                summary=vuln.get("summary"),
                description=vuln.get("details"),
                severity=severity,
                cvss_score=cvss_score,
                affected_packages=affected_packages,
                fixed_versions=list(set(fixed_versions_all)),
                references=references,
                remediation_notes=None,
                source=self.source_name,
                fetched_at=datetime.now(timezone.utc),
                raw_data=vuln,
            )

        except Exception as e:
            logger.error(f"Error parsing OSV vulnerability: {e}")
            return None

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()
