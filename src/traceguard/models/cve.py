"""CVE-related SQLAlchemy models."""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from traceguard.models.base import Base


class CVEContext(Base):
    """Cached CVE context data from external sources."""

    __tablename__ = "cve_contexts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    ghsa_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True, index=True)
    osv_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    affected_packages: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    fixed_versions: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    references: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    remediation_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(50), nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    raw_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)


class UsageEvidence(Base):
    """Evidence of package usage found in the codebase."""

    __tablename__ = "usage_evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_step_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("agent_steps.id"), nullable=False
    )
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    line_number: Mapped[int] = mapped_column(Integer, nullable=False)
    usage_type: Mapped[str] = mapped_column(String(50), nullable=False)
    code_snippet: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    package_name: Mapped[str] = mapped_column(String(200), nullable=False)

    # Relationships
    agent_step: Mapped["AgentStep"] = relationship("AgentStep", back_populates="usage_evidence")


class ResolvedOwner(Base):
    """Ownership resolution from CODEOWNERS."""

    __tablename__ = "resolved_owners"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_step_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("agent_steps.id"), nullable=False
    )
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    owner: Mapped[str] = mapped_column(String(200), nullable=False)
    owner_type: Mapped[str] = mapped_column(String(20), nullable=False)
    reasoning: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    agent_step: Mapped["AgentStep"] = relationship("AgentStep", back_populates="resolved_owners")


class GeneratedIssue(Base):
    """Generated GitHub issue content."""

    __tablename__ = "generated_issues"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    job_cve_id: Mapped[int] = mapped_column(Integer, ForeignKey("job_cves.id"), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    github_issue_url: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    created_issue_number: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default="CURRENT_TIMESTAMP",
        nullable=False,
    )

    # Relationships
    job_cve: Mapped["JobCVE"] = relationship("JobCVE", back_populates="generated_issue")


# Forward reference imports
from traceguard.models.job import AgentStep, JobCVE  # noqa: E402, F811
