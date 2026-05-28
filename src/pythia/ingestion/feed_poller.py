"""Background jobs for the live intel feed aggregator.

Two entry points:
  poll_all_feeds(session)        — fetch new article metadata from all active RSS sources
  process_article_queue(session) — run Claude on queued articles where auto_ingest=True
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime
from typing import Any


def poll_all_feeds(session: Any, *, dry_run: bool = False) -> int:
    """Fetch new articles from all active IntelFeedSources.

    Inserts IntelFeedArticle rows for new URLs (deduplicated by URL).
    Returns the total number of new articles inserted.
    """
    from pythia.ingestion.scrapers.rss import RssScraper
    from pythia.models.intel_feed import IntelFeedArticle, IntelFeedSource

    sources: list[IntelFeedSource] = session.query(IntelFeedSource).filter_by(active=True).all()

    total_new = 0
    for source in sources:
        print(f"  Polling {source.name} ({source.url})...", end=" ", flush=True)
        scraper = RssScraper(source)
        try:
            entries = scraper.fetch_entries()
        except Exception as exc:
            source.last_error = str(exc)[:500]
            session.flush()
            print(f"failed ({exc})")
            continue

        source.last_error = None
        new_count = 0
        for entry in entries:
            url = str(entry["url"])
            existing = session.query(IntelFeedArticle).filter_by(url=url).first()
            if existing:
                continue
            if not dry_run:
                article = IntelFeedArticle(
                    id=str(uuid.uuid4()),
                    source_id=source.id,
                    source_name=source.name,
                    title=str(entry["title"]) if entry["title"] else None,
                    url=url,
                    published_at=entry["published_at"],
                    summary=str(entry["summary"]) if entry["summary"] else None,
                    status="queued",
                )
                session.add(article)
            new_count += 1

        if not dry_run:
            source.last_polled_at = datetime.now(UTC).replace(tzinfo=None)
            source.article_count = source.article_count + new_count
            session.flush()

        total_new += new_count
        print(f"{new_count} new articles")
        # polite delay between sources
        time.sleep(0.5)

    if not dry_run:
        session.commit()
    return total_new


def process_article_queue(
    session: Any,
    *,
    limit: int = 10,
    dry_run: bool = False,
) -> int:
    """Run Claude on queued articles whose source has auto_ingest=True.

    Returns the number of articles successfully ingested.
    """
    from pythia.ingestion.scrapers.rss import RssScraper
    from pythia.models.intel_feed import IntelFeedArticle, IntelFeedSource
    from pythia.models.report import SourceReport

    auto_source_ids = {
        s.id for s in session.query(IntelFeedSource).filter_by(active=True, auto_ingest=True).all()
    }
    if not auto_source_ids:
        return 0

    articles: list[IntelFeedArticle] = (
        session.query(IntelFeedArticle)
        .filter(
            IntelFeedArticle.status == "queued",
            IntelFeedArticle.source_id.in_(list(auto_source_ids)),
        )
        .order_by(IntelFeedArticle.published_at.desc())
        .limit(limit)
        .all()
    )

    if not articles:
        return 0

    from pythia.ingestion.claude_parser import parse_article

    succeeded = 0
    for article in articles:
        if dry_run:
            succeeded += 1
            continue

        article.status = "ingesting"
        session.flush()

        try:
            # Fetch full article text
            source = session.get(IntelFeedSource, article.source_id)
            scraper = RssScraper(source)
            text = _run_async(scraper.fetch_article(article.url))
            parsed = parse_article(text, source_url=article.url)
        except Exception as exc:
            article.status = "failed"
            article.error = str(exc)[:500]
            session.flush()
            continue

        report = SourceReport(
            id=str(uuid.uuid4()),
            title=parsed.get("title") or article.title,
            url=article.url,
            raw_text=text[:50_000],
            publication_date=parsed.get("publication_date"),
            status="pending_review",
            parsed_data=parsed,
            tlp=str(parsed.get("tlp", "GREEN")),
        )
        session.add(report)
        session.flush()

        article.status = "done"
        article.report_id = report.id
        session.flush()
        succeeded += 1

    if not dry_run:
        session.commit()
    return succeeded


def _run_async(coro: object) -> str:
    """Run a coroutine synchronously for use in non-async scheduler jobs."""
    import asyncio

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)  # type: ignore[arg-type]
    finally:
        loop.close()


def ingest_article(session: Any, article_id: str) -> str:
    """Ingest a single queued article through Claude. Returns the new SourceReport ID.

    Used by the API's on-demand ingest endpoint.
    """
    import uuid as _uuid

    from pythia.ingestion.claude_parser import parse_article
    from pythia.ingestion.scrapers.rss import RssScraper
    from pythia.models.intel_feed import IntelFeedArticle, IntelFeedSource
    from pythia.models.report import SourceReport

    article: IntelFeedArticle | None = session.get(IntelFeedArticle, article_id)
    if article is None:
        raise ValueError(f"Article {article_id} not found")
    if article.status not in ("queued", "failed"):
        raise ValueError(f"Article is already in status '{article.status}'")

    article.status = "ingesting"
    session.flush()

    source: IntelFeedSource | None = session.get(IntelFeedSource, article.source_id)
    if source is None:
        raise ValueError(f"Source {article.source_id} not found")

    try:
        scraper = RssScraper(source)
        text = _run_async(scraper.fetch_article(article.url))
        parsed = parse_article(text, source_url=article.url)
    except Exception as exc:
        article.status = "failed"
        article.error = str(exc)[:500]
        session.commit()
        raise

    report = SourceReport(
        id=str(_uuid.uuid4()),
        title=parsed.get("title") or article.title,
        url=article.url,
        raw_text=text[:50_000],
        publication_date=parsed.get("publication_date"),
        status="pending_review",
        parsed_data=parsed,
        tlp=str(parsed.get("tlp", "GREEN")),
    )
    session.add(report)
    session.flush()

    article.status = "done"
    article.report_id = report.id
    session.commit()
    return report.id
