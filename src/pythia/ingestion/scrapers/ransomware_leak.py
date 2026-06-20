"""Scraper for ransomware leak sites (static HTML victim tables).

Covers: LockBit, ALPHV, Cl0p, RansomHub, Akira, Play, Hunters, BianLian,
Medusa, DragonForce — all share a similar structure (victim name + date).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from pythia.ingestion.scrapers.dark_web_base import DarkWebScraper

if TYPE_CHECKING:
    pass  # DarkWebForumSource accessed via self._source (typed in base)


class RansomwareLeakScraper(DarkWebScraper):
    """Generic scraper for ransomware leak sites.

    Extracts victim entries from common HTML patterns:
    - Tables with victim name + date columns
    - Card/div layouts with victim name headings
    Falls back to regex extraction when BeautifulSoup is unavailable.
    """

    def fetch_listing(self) -> list[dict[str, Any]]:
        onion_url = self._source.onion_url
        base_url = f"http://{onion_url}"
        try:
            with self._get_client() as client:
                resp = client.get(base_url)
                resp.raise_for_status()
                html = resp.text
        except Exception as exc:
            raise RuntimeError(f"Failed to fetch {base_url}: {exc}") from exc

        return self._parse_victims(html, base_url)

    def _parse_victims(self, html: str, base_url: str) -> list[dict[str, Any]]:
        try:
            import bs4  # noqa: F401

            return self._bs4_parse(html, base_url)
        except ImportError:
            return self._regex_parse(html, base_url)

    def _bs4_parse(self, html: str, base_url: str) -> list[dict[str, Any]]:
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html, "html.parser")
        results: list[dict[str, Any]] = []

        # Pattern 1: table rows
        for row in soup.find_all("tr"):
            cells = row.find_all(["td", "th"])
            if len(cells) < 2:
                continue
            title = cells[0].get_text(strip=True)
            if not title or len(title) < 2:
                continue
            date_text = cells[-1].get_text(strip=True)
            link_tag = row.find("a", href=True)
            post_url = str(link_tag["href"]) if link_tag else f"{base_url}#{_slug(title)}"
            if post_url.startswith("/"):
                post_url = base_url.rstrip("/") + post_url
            results.append(
                {
                    "title": title,
                    "post_url": post_url,
                    "published_at": _parse_date(date_text),
                }
            )

        if results:
            return results

        # Pattern 2: heading/div cards
        for tag in soup.find_all(["h2", "h3", "h4", ".victim", ".company"]):
            title = tag.get_text(strip=True)
            if not title or len(title) < 2:
                continue
            link_tag = tag.find("a", href=True) or tag.find_parent("a")
            post_url = str(link_tag["href"]) if link_tag else f"{base_url}#{_slug(title)}"
            if post_url.startswith("/"):
                post_url = base_url.rstrip("/") + post_url
            results.append(
                {
                    "title": title,
                    "post_url": post_url,
                    "published_at": None,
                }
            )

        return results

    def _regex_parse(self, html: str, base_url: str) -> list[dict[str, Any]]:
        # Simple fallback: extract anything that looks like a victim entry
        results: list[dict[str, Any]] = []
        # Match href + text in anchor tags
        for m in re.finditer(r'href="(/[^"]+)"[^>]*>\s*([A-Z][^<]{2,80}?)\s*<', html):
            path, title = m.group(1), m.group(2)
            post_url = base_url.rstrip("/") + path
            results.append({"title": title, "post_url": post_url, "published_at": None})
        return results

    def fetch_post_content(self, post_url: str) -> str:
        try:
            with self._get_client() as client:
                resp = client.get(post_url)
                resp.raise_for_status()
                html = resp.text
        except Exception as exc:
            raise RuntimeError(f"Failed to fetch post {post_url}: {exc}") from exc

        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all(["script", "style", "nav", "footer"]):
                tag.decompose()
            return str(soup.get_text(separator="\n", strip=True))
        except ImportError:
            return str(re.sub(r"<[^>]+>", " ", html))


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def _parse_date(text: str) -> datetime | None:
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%B %d, %Y", "%d %B %Y"):
        try:
            return datetime.strptime(text.strip(), fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None
