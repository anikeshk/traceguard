"""LangGraph pipeline state definitions."""

from typing import Annotated, Optional, TypedDict
from operator import add

from traceguard.schemas.cve import CVEContextSchema
from traceguard.schemas.analysis import UsageEvidenceSchema, ResolvedOwnerSchema


class PipelineState(TypedDict, total=False):
    """State shared across all agents in the pipeline.

    This state is passed through each agent node and updated with results.
    """

    # Input parameters
    job_id: int
    job_cve_id: int
    cve_id: str
    codebase_path: str

    # CVE Context Agent outputs
    cve_context: Optional[dict]  # Serialized CVEContextSchema
    cve_context_error: Optional[str]

    # Dependency Usage Agent outputs
    usage_evidence: Annotated[list[dict], add]  # Serialized UsageEvidenceSchema
    is_applicable: Optional[bool]
    applicability_reason: Optional[str]
    installed_version: Optional[str]

    # Ownership Agent outputs
    owners: Annotated[list[dict], add]  # Serialized ResolvedOwnerSchema
    ownership_error: Optional[str]

    # Ticket Generation Agent outputs
    generated_issue_title: Optional[str]
    generated_issue_body: Optional[str]
    github_issue_url: Optional[str]

    # Pipeline metadata
    current_step: str
    errors: Annotated[list[str], add]


def create_initial_state(
    job_id: int,
    job_cve_id: int,
    cve_id: str,
    codebase_path: str,
) -> PipelineState:
    """Create an initial pipeline state.

    Args:
        job_id: The job ID.
        job_cve_id: The job CVE ID.
        cve_id: The CVE identifier to analyze.
        codebase_path: Path to the codebase.

    Returns:
        Initial PipelineState.
    """
    return PipelineState(
        job_id=job_id,
        job_cve_id=job_cve_id,
        cve_id=cve_id,
        codebase_path=codebase_path,
        cve_context=None,
        cve_context_error=None,
        usage_evidence=[],
        is_applicable=None,
        applicability_reason=None,
        installed_version=None,
        owners=[],
        ownership_error=None,
        generated_issue_title=None,
        generated_issue_body=None,
        github_issue_url=None,
        current_step="initialized",
        errors=[],
    )
