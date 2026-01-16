"""Job-related SQLAlchemy models."""

import enum
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from traceguard.models.base import Base, TimestampMixin


class JobStatus(str, enum.Enum):
    """Status of a scan job."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ApplicabilityStatus(str, enum.Enum):
    """CVE applicability determination."""

    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


class AgentStepStatus(str, enum.Enum):
    """Status of an agent step."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class Job(Base, TimestampMixin):
    """A scan job that analyzes one or more CVEs against a codebase."""

    __tablename__ = "jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    codebase_path: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[JobStatus] = mapped_column(
        Enum(JobStatus), nullable=False, default=JobStatus.PENDING
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    cve_analyses: Mapped[list["JobCVE"]] = relationship(
        "JobCVE", back_populates="job", cascade="all, delete-orphan"
    )


class JobCVE(Base, TimestampMixin):
    """Analysis of a single CVE within a job."""

    __tablename__ = "job_cves"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    job_id: Mapped[int] = mapped_column(Integer, ForeignKey("jobs.id"), nullable=False)
    cve_id: Mapped[str] = mapped_column(String(50), nullable=False)
    applicability: Mapped[Optional[ApplicabilityStatus]] = mapped_column(
        Enum(ApplicabilityStatus), nullable=True
    )
    applicability_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    job: Mapped["Job"] = relationship("Job", back_populates="cve_analyses")
    steps: Mapped[list["AgentStep"]] = relationship(
        "AgentStep", back_populates="job_cve", cascade="all, delete-orphan"
    )
    generated_issue: Mapped[Optional["GeneratedIssue"]] = relationship(
        "GeneratedIssue", back_populates="job_cve", uselist=False, cascade="all, delete-orphan"
    )


class AgentStep(Base):
    """A single agent step in the analysis pipeline."""

    __tablename__ = "agent_steps"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    job_cve_id: Mapped[int] = mapped_column(Integer, ForeignKey("job_cves.id"), nullable=False)
    agent_name: Mapped[str] = mapped_column(String(100), nullable=False)
    step_order: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[AgentStepStatus] = mapped_column(
        Enum(AgentStepStatus), nullable=False, default=AgentStepStatus.PENDING
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    input_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    output_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default="CURRENT_TIMESTAMP",
        nullable=False,
    )

    # Relationships
    job_cve: Mapped["JobCVE"] = relationship("JobCVE", back_populates="steps")
    artifacts: Mapped[list["Artifact"]] = relationship(
        "Artifact", back_populates="agent_step", cascade="all, delete-orphan"
    )
    usage_evidence: Mapped[list["UsageEvidence"]] = relationship(
        "UsageEvidence", back_populates="agent_step", cascade="all, delete-orphan"
    )
    resolved_owners: Mapped[list["ResolvedOwner"]] = relationship(
        "ResolvedOwner", back_populates="agent_step", cascade="all, delete-orphan"
    )


class Artifact(Base):
    """An artifact produced by an agent step."""

    __tablename__ = "artifacts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_step_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("agent_steps.id"), nullable=False
    )
    artifact_type: Mapped[str] = mapped_column(String(50), nullable=False)
    artifact_name: Mapped[str] = mapped_column(String(200), nullable=False)
    content: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default="CURRENT_TIMESTAMP",
        nullable=False,
    )

    # Relationships
    agent_step: Mapped["AgentStep"] = relationship("AgentStep", back_populates="artifacts")


# Forward reference imports
from traceguard.models.cve import UsageEvidence, ResolvedOwner, GeneratedIssue  # noqa: E402
