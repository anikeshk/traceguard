"""Pydantic schemas for CVE data."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class AffectedPackage(BaseModel):
    """An affected package in a CVE."""

    name: str
    ecosystem: str
    version_range: Optional[str] = None
    fixed_versions: list[str] = Field(default_factory=list)


class CVEContextSchema(BaseModel):
    """CVE context data from external sources."""

    cve_id: str
    ghsa_id: Optional[str] = None
    osv_id: Optional[str] = None
    summary: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    affected_packages: list[AffectedPackage] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    remediation_notes: Optional[str] = None
    source: str
    fetched_at: datetime
    raw_data: Optional[dict] = None

    class Config:
        from_attributes = True


class CVELookupRequest(BaseModel):
    """Request to look up a CVE."""

    cve_id: str


class CVELookupResponse(BaseModel):
    """Response from CVE lookup."""

    found: bool
    context: Optional[CVEContextSchema] = None
    error: Optional[str] = None
