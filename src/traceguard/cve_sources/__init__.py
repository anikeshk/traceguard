"""CVE data source implementations."""

from traceguard.cve_sources.base import CVESource
from traceguard.cve_sources.osv import OSVClient
from traceguard.cve_sources.github_advisory import GitHubAdvisoryClient
from traceguard.cve_sources.aggregator import CVESourceAggregator

__all__ = [
    "CVESource",
    "OSVClient",
    "GitHubAdvisoryClient",
    "CVESourceAggregator",
]
