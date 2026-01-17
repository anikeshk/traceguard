from datetime import datetime
from enum import Enum
from typing import Optional

from sqlalchemy import ForeignKey, String, Text, DateTime, Enum as SQLEnum
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class JobStatus(str, Enum):
    PENDING = "pending"
    FETCHING_ALERTS = "fetching_alerts"
    RESOLVING_OWNER = "resolving_owner"
    COMPLETED = "completed"
    FAILED = "failed"


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[int] = mapped_column(primary_key=True)
    repo_name: Mapped[str] = mapped_column(String(255))
    repo_full_name: Mapped[str] = mapped_column(String(255))
    repo_owner: Mapped[str] = mapped_column(String(255))
    repo_url: Mapped[str] = mapped_column(String(500))
    status: Mapped[JobStatus] = mapped_column(
        SQLEnum(JobStatus), default=JobStatus.PENDING
    )
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    alerts: Mapped[list["Alert"]] = relationship(
        back_populates="job", cascade="all, delete-orphan"
    )
    owner: Mapped[Optional["Owner"]] = relationship(
        back_populates="job", cascade="all, delete-orphan", uselist=False
    )
    audit_artifacts: Mapped[list["AuditArtifact"]] = relationship(
        back_populates="job", cascade="all, delete-orphan"
    )


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id"))

    # Alert identification
    alert_number: Mapped[int] = mapped_column()
    state: Mapped[str] = mapped_column(String(50))

    # CVE information
    cve_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    severity: Mapped[str] = mapped_column(String(50))
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Package information
    package_name: Mapped[str] = mapped_column(String(255))
    package_ecosystem: Mapped[str] = mapped_column(String(100))
    vulnerable_version_range: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    patched_version: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )

    # Metadata
    html_url: Mapped[str] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )

    job: Mapped["Job"] = relationship(back_populates="alerts")


class Owner(Base):
    __tablename__ = "owners"

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id"), unique=True)

    username: Mapped[str] = mapped_column(String(255))
    email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )

    job: Mapped["Job"] = relationship(back_populates="owner")


class AuditArtifact(Base):
    """
    Audit trail entry for agent transparency.

    Records inputs, outputs, decisions, and errors for each step
    in the workflow execution.
    """

    __tablename__ = "audit_artifacts"

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id"))

    step_name: Mapped[str] = mapped_column(String(100))
    timestamp: Mapped[str] = mapped_column(String(50))  # ISO format

    # JSON-serialized fields for flexibility
    inputs_json: Mapped[str] = mapped_column(Text)
    outputs_json: Mapped[str] = mapped_column(Text)
    decisions_json: Mapped[str] = mapped_column(Text)
    errors_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )

    job: Mapped["Job"] = relationship(back_populates="audit_artifacts")
