"""Base agent interface for the CVE triage pipeline."""

from abc import ABC, abstractmethod
from typing import Any

from traceguard.agents.state import PipelineState


class BaseAgent(ABC):
    """Abstract base class for pipeline agents.

    Each agent is responsible for a specific step in the CVE triage process.
    Agents should be stateless and operate on the shared PipelineState.
    """

    @property
    @abstractmethod
    def agent_name(self) -> str:
        """Get the unique identifier for this agent."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Get a human-readable description of what this agent does."""
        pass

    @property
    def step_order(self) -> int:
        """Get the order of this step in the pipeline.

        Override this in subclasses to define execution order.
        """
        return 0

    @abstractmethod
    async def execute(self, state: PipelineState) -> dict[str, Any]:
        """Execute the agent's task and return state updates.

        Args:
            state: The current pipeline state.

        Returns:
            Dictionary of state updates to merge into the pipeline state.
        """
        pass

    def validate_inputs(self, state: PipelineState) -> list[str]:
        """Validate that required inputs are present in state.

        Override this in subclasses to add input validation.

        Args:
            state: The current pipeline state.

        Returns:
            List of error messages (empty if valid).
        """
        return []

    def should_skip(self, state: PipelineState) -> bool:
        """Check if this agent should be skipped based on current state.

        Override this in subclasses to add skip logic.

        Args:
            state: The current pipeline state.

        Returns:
            True if agent should be skipped, False otherwise.
        """
        return False
