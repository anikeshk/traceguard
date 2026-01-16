"""Pydantic schemas for statistics."""

from pydantic import BaseModel, Field


class SeverityBreakdown(BaseModel):
    """Breakdown of CVEs by severity."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unknown: int = 0


class DashboardStats(BaseModel):
    """Dashboard statistics."""

    total_jobs: int = Field(description="Total number of scan jobs")
    jobs_last_7_days: int = Field(description="Jobs created in the last 7 days")
    cves_analyzed: int = Field(description="Total CVEs analyzed")
    applicable_cves: int = Field(description="CVEs found to be applicable")
    not_applicable_cves: int = Field(description="CVEs found to be not applicable")
    issues_generated: int = Field(description="Issues generated")
    by_severity: SeverityBreakdown = Field(
        default_factory=SeverityBreakdown,
        description="Breakdown by severity",
    )
