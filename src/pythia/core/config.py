"""Pythia runtime configuration loaded from environment / .env."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_ENV_FILE = _PROJECT_ROOT / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(_ENV_FILE),
        env_file_encoding="utf-8",
        env_prefix="PYTHIA_",
        extra="ignore",
    )

    env: Literal["development", "staging", "production"] = "development"
    host: str = "127.0.0.1"
    port: int = 8000
    log_level: str = "INFO"

    api_key: str = Field(default="changeme", description="API key for write endpoints")

    database_url: str = "sqlite:///./pythia.db"

    claude_model: str = "claude-sonnet-4-6"
    anthropic_api_key: str | None = Field(default=None, alias="ANTHROPIC_API_KEY")

    scrape_user_agent: str = "Pythia/0.1"
    scrape_rate_limit_per_min: int = 20

    # Optional API keys for external intel feeds
    otx_api_key: str | None = Field(default=None, alias="OTX_API_KEY")
    phishtank_api_key: str | None = Field(default=None, alias="PHISHTANK_API_KEY")

    enable_scheduler: bool = Field(default=False, description="Start APScheduler background sync on API startup")

    # Intel feed aggregator
    feed_auto_ingest: bool = Field(default=False, description="Auto-run Claude on new feed articles")
    feed_max_articles_per_run: int = Field(default=10, description="Max Claude calls per scheduler tick")

    @model_validator(mode="after")
    def resolve_sqlite_path(self) -> Settings:
        if self.database_url.startswith("sqlite:///./"):
            relative_part = self.database_url.replace("sqlite:///./", "")
            absolute_path = _PROJECT_ROOT / relative_part
            self.database_url = f"sqlite:///{absolute_path}"
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
