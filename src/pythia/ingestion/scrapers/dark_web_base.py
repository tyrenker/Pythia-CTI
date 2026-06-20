"""Base class for all dark web forum scrapers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pythia.models.dark_web import DarkWebForumSource


class DarkWebScraper(ABC):
    """Sends requests via Tor SOCKS5. Subclass per forum category."""

    def __init__(
        self,
        source: DarkWebForumSource,
        tor_proxy: str = "socks5://127.0.0.1:9050",
        timeout: float = 30.0,
    ) -> None:
        self._source = source
        self._tor_proxy = tor_proxy
        self._timeout = timeout

    def _get_client(self) -> Any:
        import httpx

        return httpx.Client(proxy=self._tor_proxy, timeout=self._timeout)

    @abstractmethod
    def fetch_listing(self) -> list[dict[str, Any]]:
        """Return new post stubs: list of {title, post_url, published_at}."""
        ...

    @abstractmethod
    def fetch_post_content(self, post_url: str) -> str:
        """Fetch and return full text for a single post URL."""
        ...
