"""SQLAlchemy database models."""

from datetime import datetime
from enum import Enum
from typing import Optional

from sqlalchemy import DateTime, Float, ForeignKey, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all models."""

    pass


class Severity(str, Enum):
    """CVE severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class TriageStatus(str, Enum):
    """Triage status for a CVE."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    NEEDS_REVIEW = "needs_review"


class OwnershipSource(str, Enum):
    """Source of ownership assignment."""

    CODEOWNERS = "codeowners"
    GIT_BLAME = "git_blame"
    MANUAL = "manual"


class CVE(Base):
    """CVE metadata from various sources."""

    __tablename__ = "cves"

    id: Mapped[str] = mapped_column(String(50), primary_key=True)  # e.g., CVE-2024-1234
    title: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20), default=Severity.UNKNOWN.value)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    source: Mapped[str] = mapped_column(String(50))  # nvd, osv, github
    source_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    published_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    modified_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    affected_packages: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON list
    affected_versions: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON dict
    references: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON list of URLs
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Relationships
    triage_results: Mapped[list["TriageResult"]] = relationship(back_populates="cve")

    def __repr__(self) -> str:
        return f"<CVE {self.id}: {self.severity}>"


class TriageResult(Base):
    """Result of CVE triage analysis for a specific codebase."""

    __tablename__ = "triage_results"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(String(50), ForeignKey("cves.id"))
    codebase_path: Mapped[str] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(20), default=TriageStatus.PENDING.value)
    is_affected: Mapped[Optional[bool]] = mapped_column(nullable=True)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)  # 0.0 to 1.0
    reasoning: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    affected_files: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON list
    affected_dependencies: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON list
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    priority_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)  # Computed
    manual_override: Mapped[bool] = mapped_column(default=False)
    override_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Relationships
    cve: Mapped["CVE"] = relationship(back_populates="triage_results")
    owners: Mapped[list["Ownership"]] = relationship(back_populates="triage_result")

    def __repr__(self) -> str:
        return f"<TriageResult {self.id}: {self.cve_id} - {self.status}>"


class Ownership(Base):
    """Owner assignment for a triage result."""

    __tablename__ = "ownership"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    triage_result_id: Mapped[int] = mapped_column(ForeignKey("triage_results.id"))
    owner: Mapped[str] = mapped_column(String(200))  # Email, username, or team name
    source: Mapped[str] = mapped_column(String(20))  # codeowners, git_blame, manual
    file_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    triage_result: Mapped["TriageResult"] = relationship(back_populates="owners")

    def __repr__(self) -> str:
        return f"<Ownership {self.id}: {self.owner} ({self.source})>"


class ScanJob(Base):
    """Track scanning jobs."""

    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    codebase_path: Mapped[str] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending, running, completed, failed
    total_cves: Mapped[int] = mapped_column(default=0)
    processed_cves: Mapped[int] = mapped_column(default=0)
    affected_count: Mapped[int] = mapped_column(default=0)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"<ScanJob {self.id}: {self.status}>"
