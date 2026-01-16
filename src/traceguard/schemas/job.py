"""Pydantic schemas for job-related API operations."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from traceguard.models.job import JobStatus, ApplicabilityStatus, AgentStepStatus


class CreateJobRequest(BaseModel):
    """Request to create a new scan job."""

    codebase_path: str = Field(..., description="Path to the local codebase")
    cve_ids: list[str] = Field(..., min_length=1, description="List of CVE IDs to analyze")
    auto_create_issues: bool = Field(
        default=False, description="Automatically create GitHub issues"
    )


class CreateJobResponse(BaseModel):
    """Response after creating a job."""

    job_id: int
    status: JobStatus
    cve_count: int
    created_at: datetime


class AgentStepSchema(BaseModel):
    """Schema for an agent step."""

    id: int
    agent_name: str
    step_order: int
    status: AgentStepStatus
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    input_data: Optional[dict] = None
    output_data: Optional[dict] = None
    error_message: Optional[str] = None

    class Config:
        from_attributes = True


class ArtifactSchema(BaseModel):
    """Schema for an artifact."""

    id: int
    artifact_type: str
    artifact_name: str
    content: dict
    created_at: datetime

    class Config:
        from_attributes = True


class UsageEvidenceSchema(BaseModel):
    """Schema for usage evidence."""

    id: int
    file_path: str
    line_number: int
    usage_type: str
    code_snippet: Optional[str] = None
    package_name: str

    class Config:
        from_attributes = True


class ResolvedOwnerSchema(BaseModel):
    """Schema for resolved owner."""

    id: int
    file_path: str
    owner: str
    owner_type: str
    reasoning: Optional[str] = None

    class Config:
        from_attributes = True


class GeneratedIssueSchema(BaseModel):
    """Schema for generated issue."""

    id: int
    title: str
    body: str
    github_issue_url: Optional[str] = None
    created_issue_number: Optional[int] = None
    created_at: datetime

    class Config:
        from_attributes = True


class JobCVEDetailSchema(BaseModel):
    """Detailed schema for a CVE analysis within a job."""

    id: int
    cve_id: str
    applicability: Optional[ApplicabilityStatus] = None
    applicability_reason: Optional[str] = None
    steps: list[AgentStepSchema] = Field(default_factory=list)
    generated_issue: Optional[GeneratedIssueSchema] = None

    class Config:
        from_attributes = True


class JobDetailSchema(BaseModel):
    """Detailed schema for a job."""

    id: int
    codebase_path: str
    status: JobStatus
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    cve_analyses: list[JobCVEDetailSchema] = Field(default_factory=list)

    class Config:
        from_attributes = True


class JobListItemSchema(BaseModel):
    """Schema for a job in a list view."""

    id: int
    codebase_path: str
    status: JobStatus
    cve_count: int
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True


class JobListResponse(BaseModel):
    """Response for listing jobs."""

    jobs: list[JobListItemSchema]
    total: int
    page: int
    page_size: int
