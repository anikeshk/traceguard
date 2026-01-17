import logging
import os
from pathlib import Path

from dotenv import load_dotenv

logger = logging.getLogger(__name__)


def _find_dotenv() -> Path | None:
    """Find .env file by traversing up from cwd."""
    current = Path.cwd()
    while current != current.parent:
        env_file = current / ".env"
        if env_file.exists():
            return env_file
        current = current.parent
    return None


def load_config() -> None:
    """Load environment variables from .env file."""
    env_path = _find_dotenv()
    if env_path:
        load_dotenv(env_path)


def get_github_token() -> str:
    """Get GitHub token from environment.

    Raises:
        ValueError: If GITHUB_TOKEN is not set.
    """
    load_config()
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        raise ValueError("GITHUB_TOKEN not set. Create a .env file with your token.")
    return token
