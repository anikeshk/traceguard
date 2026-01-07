"""Configuration management using Pydantic Settings."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Database
    database_url: str = "sqlite+aiosqlite:///./traceguard.db"

    # OpenAI
    openai_api_key: str = ""
    openai_model: str = "gpt-4o"

    # CVE Sources
    nvd_api_key: str = ""  # Optional, but increases rate limits
    github_token: str = ""  # For GitHub Advisory API

    # Application
    debug: bool = False
    log_level: str = "INFO"

    # API Server
    api_host: str = "127.0.0.1"
    api_port: int = 8000

    # Streamlit
    streamlit_port: int = 8501

    @property
    def data_dir(self) -> Path:
        """Get the data directory path."""
        path = Path("./data")
        path.mkdir(exist_ok=True)
        return path


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
