"""Custom exception classes for TraceGuard."""


class TraceGuardError(Exception):
    """Base exception for TraceGuard errors."""

    pass


class CVENotFoundError(TraceGuardError):
    """Raised when a CVE cannot be found in any source."""

    def __init__(self, cve_id: str):
        self.cve_id = cve_id
        super().__init__(f"CVE not found: {cve_id}")


class CVESourceError(TraceGuardError):
    """Raised when a CVE source API fails."""

    def __init__(self, source: str, message: str):
        self.source = source
        super().__init__(f"CVE source '{source}' error: {message}")


class CodebaseNotFoundError(TraceGuardError):
    """Raised when the specified codebase path does not exist."""

    def __init__(self, path: str):
        self.path = path
        super().__init__(f"Codebase path not found: {path}")


class CodeOwnersNotFoundError(TraceGuardError):
    """Raised when CODEOWNERS file is missing."""

    def __init__(self, path: str):
        self.path = path
        super().__init__(f"CODEOWNERS file not found in: {path}")


class OwnerResolutionError(TraceGuardError):
    """Raised when no owner can be resolved for affected files."""

    def __init__(self, files: list[str]):
        self.files = files
        super().__init__(f"Could not resolve owners for files: {files}")


class AgentExecutionError(TraceGuardError):
    """Raised when an agent fails during execution."""

    def __init__(self, agent_name: str, message: str):
        self.agent_name = agent_name
        super().__init__(f"Agent '{agent_name}' failed: {message}")


class JobNotFoundError(TraceGuardError):
    """Raised when a job cannot be found."""

    def __init__(self, job_id: int):
        self.job_id = job_id
        super().__init__(f"Job not found: {job_id}")
