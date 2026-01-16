"""Pydantic schemas for static analysis."""

from typing import Optional

from pydantic import BaseModel, Field


class UsageEvidenceSchema(BaseModel):
    """Evidence of package usage found in the codebase."""

    file_path: str
    line_number: int
    usage_type: str  # 'import', 'require', 'dynamic_import'
    code_snippet: Optional[str] = None
    package_name: str

    class Config:
        from_attributes = True


class ResolvedOwnerSchema(BaseModel):
    """Ownership resolution from CODEOWNERS."""

    file_path: str
    owner: str
    owner_type: str  # 'user', 'team'
    reasoning: Optional[str] = None

    class Config:
        from_attributes = True


class DependencyAnalysisResult(BaseModel):
    """Result of dependency usage analysis."""

    package_name: str
    ecosystem: str
    is_used: bool
    usage_evidence: list[UsageEvidenceSchema] = Field(default_factory=list)
    installed_version: Optional[str] = None
    error: Optional[str] = None


class OwnershipAnalysisResult(BaseModel):
    """Result of ownership resolution analysis."""

    resolved_owners: list[ResolvedOwnerSchema] = Field(default_factory=list)
    codeowners_found: bool
    error: Optional[str] = None
