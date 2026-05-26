"""Base interface every source scraper implements."""

from __future__ import annotations

from abc import ABC, abstractmethod


class BaseScraper(ABC):
    name: str

    @abstractmethod
    async def fetch_urls(self) -> list[str]:
        """Return URLs of new intel articles since the last run."""

    @abstractmethod
    async def fetch_article(self, url: str) -> str:
        """Return cleaned article text for `url`."""
