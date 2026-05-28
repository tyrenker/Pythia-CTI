"""RSS/Atom feed scraper backed by feedparser."""

from __future__ import annotations

import html
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from pythia.ingestion.scrapers.base import BaseScraper

if TYPE_CHECKING:
    from pythia.models.intel_feed import IntelFeedSource

try:
    import feedparser

    _HAS_FEEDPARSER = True
except ImportError:
    _HAS_FEEDPARSER = False


def _to_utc(time_struct: object) -> datetime | None:
    """Convert feedparser's time_struct (calendar.struct_time) to a UTC datetime."""
    import calendar

    if time_struct is None:
        return None
    try:
        ts = calendar.timegm(time_struct)  # type: ignore[arg-type]
        return datetime.fromtimestamp(ts, tz=UTC).replace(tzinfo=None)
    except Exception:
        return None


def _strip_html(text: str | None) -> str | None:
    if not text:
        return None
    clean = re.sub(r"<[^>]+>", " ", text)
    return html.unescape(clean).strip() or None


class RssScraper(BaseScraper):
    """Poll one RSS/Atom feed URL and return new article URLs."""

    name: str = "rss"

    def __init__(self, source: IntelFeedSource) -> None:
        self._source = source

    async def fetch_urls(self) -> list[str]:
        """Return article URLs published after `source.last_polled_at`."""
        if not _HAS_FEEDPARSER:
            raise RuntimeError("feedparser is not installed — add it to the ingestion extras")

        ua = "Pythia/0.1 threat-intel-aggregator (https://github.com/tyrenker/pythia)"
        try:
            feed = feedparser.parse(
                self._source.url,
                agent=ua,
                request_headers={"User-Agent": ua},
            )
        except Exception as exc:
            raise RuntimeError(f"feedparser failed: {exc}") from exc

        if feed.get("bozo") and not feed.get("entries"):
            bozo_exc = feed.get("bozo_exception")
            raise RuntimeError(f"Feed parse error: {bozo_exc}")

        cutoff = self._source.last_polled_at  # UTC naive; None → accept all
        urls: list[str] = []
        for entry in feed.get("entries", []):
            link: str = entry.get("link", "")
            if not link:
                continue
            pub = _to_utc(entry.get("published_parsed") or entry.get("updated_parsed"))
            if cutoff and pub and pub <= cutoff:
                continue
            urls.append(link)

        return urls

    def fetch_entries(self) -> list[dict[str, str | datetime | None]]:
        """Return full entry metadata (title, url, published_at, summary) for new articles."""
        if not _HAS_FEEDPARSER:
            raise RuntimeError("feedparser is not installed — add it to the ingestion extras")

        ua = "Pythia/0.1 threat-intel-aggregator (https://github.com/tyrenker/pythia)"
        try:
            feed = feedparser.parse(
                self._source.url,
                agent=ua,
                request_headers={"User-Agent": ua},
            )
        except Exception as exc:
            raise RuntimeError(f"feedparser failed: {exc}") from exc

        if feed.get("bozo") and not feed.get("entries"):
            bozo_exc = feed.get("bozo_exception")
            raise RuntimeError(f"Feed parse error: {bozo_exc}")

        cutoff = self._source.last_polled_at
        results: list[dict[str, str | datetime | None]] = []
        for entry in feed.get("entries", []):
            link: str = entry.get("link", "")
            if not link:
                continue
            pub = _to_utc(entry.get("published_parsed") or entry.get("updated_parsed"))
            if cutoff and pub and pub <= cutoff:
                continue

            raw_summary = (
                entry.get("summary")
                or entry.get("description")
                or (entry.get("content") or [{}])[0].get("value", "")
            )
            results.append(
                {
                    "url": link,
                    "title": _strip_html(entry.get("title")),
                    "published_at": pub,
                    "summary": _strip_html(raw_summary),
                }
            )

        return results

    async def fetch_article(self, url: str) -> str:
        """Fetch and extract clean text from an article URL via trafilatura."""
        try:
            import trafilatura
        except ImportError as exc:
            raise RuntimeError(
                "trafilatura is not installed — add it to the ingestion extras"
            ) from exc

        downloaded = trafilatura.fetch_url(url)
        if not downloaded:
            raise RuntimeError(f"Could not download {url}")
        text: str = trafilatura.extract(downloaded) or ""
        if not text.strip():
            raise RuntimeError(f"No text extracted from {url}")
        return text
