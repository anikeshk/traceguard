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


def get_openai_api_key() -> str:
    """Get OpenAI API key from environment.

    Raises:
        ValueError: If OPENAI_API_KEY is not set.
    """
    load_config()
    key = os.getenv("OPENAI_API_KEY")
    if not key:
        raise ValueError("OPENAI_API_KEY not set. Add it to your .env file.")
    return key


def get_jira_host() -> str:
    """Get Jira host URL from environment.

    Returns the base URL for Jira (e.g., https://your-domain.atlassian.net)

    Raises:
        ValueError: If JIRA_HOST is not set.
    """
    load_config()
    host = os.getenv("JIRA_HOST")
    if not host:
        raise ValueError("JIRA_HOST not set. Add it to your .env file.")
    return host.rstrip("/")


def get_jira_token() -> str:
    """Get Jira API token from environment.

    Raises:
        ValueError: If JIRA_TOKEN is not set.
    """
    load_config()
    token = os.getenv("JIRA_TOKEN")
    if not token:
        raise ValueError("JIRA_TOKEN not set. Add it to your .env file.")
    return token


def get_jira_user_email() -> str:
    """Get Jira user email for API authentication.

    Raises:
        ValueError: If JIRA_USER_EMAIL is not set.
    """
    load_config()
    email = os.getenv("JIRA_USER_EMAIL")
    if not email:
        raise ValueError("JIRA_USER_EMAIL not set. Add it to your .env file.")
    return email


def get_jira_project_key() -> str:
    """Get the default Jira project key from environment.

    Raises:
        ValueError: If JIRA_PROJECT_KEY is not set.
    """
    load_config()
    key = os.getenv("JIRA_PROJECT_KEY")
    if not key:
        raise ValueError("JIRA_PROJECT_KEY not set. Add it to your .env file.")
    return key
