"""Background jobs for dark web forum monitoring.

Entry points:
  poll_all_dark_web_sources(session)    — fetch new victim listings from all active sources
  fetch_post_content(session, post_id)  — fetch full text for one queued post
  process_dark_web_queue(session)       — run Claude forum parser on fetched posts
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any


def _get_scraper(source: Any) -> Any:
    """Return the appropriate scraper for a DarkWebForumSource."""
    from pythia.core.config import get_settings
    from pythia.ingestion.scrapers.ransomware_leak import RansomwareLeakScraper

    settings = get_settings()
    tor_proxy = f"socks5://{settings.tor_host}:{settings.tor_socks_port}"

    # Currently only ransomware sites are seeded; extend as categories are added.
    return RansomwareLeakScraper(source, tor_proxy=tor_proxy)


def poll_all_dark_web_sources(session: Any) -> int:
    """Fetch new post listings from all active DarkWebForumSources.

    Inserts DarkWebPost rows for new URLs (deduped by post_url).
    Returns total new posts inserted.
    """
    from pythia.core.config import get_settings
    from pythia.core.tor_proxy import TorProxyManager
    from pythia.models.dark_web import DarkWebForumSource, DarkWebPost

    settings = get_settings()
    tor = TorProxyManager(
        control_host=settings.tor_host,
        control_port=settings.tor_control_port,
        password=settings.tor_control_password,
    )

    if not tor.is_available():
        if settings.tor_required:
            raise RuntimeError("Tor is not available and PYTHIA_TOR_REQUIRED=true")
        print("  dark-web poll: Tor not available — skipping")
        return 0

    sources: list[DarkWebForumSource] = (
        session.query(DarkWebForumSource).filter_by(active=True).all()
    )
    total_new = 0

    for source in sources:
        print(f"  Polling dark web source: {source.name}...", end=" ", flush=True)
        try:
            scraper = _get_scraper(source)
            entries = scraper.fetch_listing()
        except Exception as exc:
            source.last_error = str(exc)[:500]
            session.flush()
            print(f"failed ({exc})")
            tor.new_circuit()
            continue

        source.last_error = None
        new_count = 0
        for entry in entries:
            post_url = str(entry.get("post_url", ""))
            if not post_url:
                continue
            existing = session.query(DarkWebPost).filter_by(post_url=post_url).first()
            if existing:
                continue
            session.add(
                DarkWebPost(
                    id=str(uuid.uuid4()),
                    source_id=source.id,
                    title=entry.get("title"),
                    post_url=post_url,
                    published_at=entry.get("published_at"),
                    status="queued",
                )
            )
            new_count += 1

        source.last_polled_at = datetime.now(UTC).replace(tzinfo=None)
        source.post_count = source.post_count + new_count
        session.flush()
        total_new += new_count
        print(f"{new_count} new posts")
        tor.new_circuit()

    session.commit()
    tor.close()
    return total_new


def fetch_post_content(session: Any, post_id: str) -> None:
    """Fetch full text for a single queued post and store in raw_content."""
    from pythia.core.config import get_settings
    from pythia.core.tor_proxy import TorProxyManager
    from pythia.models.dark_web import DarkWebForumSource, DarkWebPost

    post: DarkWebPost | None = session.get(DarkWebPost, post_id)
    if post is None:
        raise ValueError(f"Post {post_id} not found")

    settings = get_settings()
    tor = TorProxyManager(
        control_host=settings.tor_host,
        control_port=settings.tor_control_port,
        password=settings.tor_control_password,
    )
    if not tor.is_available():
        if settings.tor_required:
            raise RuntimeError("Tor not available")
        raise RuntimeError("Tor proxy is not reachable — cannot fetch dark web content")

    source: DarkWebForumSource | None = session.get(DarkWebForumSource, post.source_id)
    if source is None:
        raise ValueError(f"Source {post.source_id} not found")

    post.status = "fetching"
    session.flush()

    try:
        scraper = _get_scraper(source)
        content = scraper.fetch_post_content(post.post_url)
        post.raw_content = content[:100_000]
        post.status = "fetched"
    except Exception as exc:
        post.status = "failed"
        post.error = str(exc)[:500]
        session.commit()
        tor.close()
        raise

    session.commit()
    tor.close()


def process_dark_web_queue(session: Any, *, limit: int = 5) -> int:
    """Run Claude forum parser on fetched posts where source.auto_ingest=True.

    Returns the number of posts successfully ingested.
    """
    from pythia.models.dark_web import DarkWebForumSource, DarkWebPost

    auto_source_ids = {
        s.id
        for s in session.query(DarkWebForumSource).filter_by(active=True, auto_ingest=True).all()
    }
    if not auto_source_ids:
        return 0

    posts: list[DarkWebPost] = (
        session.query(DarkWebPost)
        .filter(
            DarkWebPost.status == "fetched",
            DarkWebPost.source_id.in_(list(auto_source_ids)),
        )
        .order_by(DarkWebPost.published_at.desc())
        .limit(limit)
        .all()
    )
    if not posts:
        return 0

    from pythia.ingestion.forum_intel_parser import parse_dark_web_post

    succeeded = 0
    for post in posts:
        if not post.raw_content:
            post.status = "skipped"
            session.flush()
            continue

        post.status = "ingesting"
        session.flush()

        try:
            report_id = parse_dark_web_post(session, post)
        except Exception as exc:
            post.status = "failed"
            post.error = str(exc)[:500]
            session.flush()
            continue

        post.status = "done"
        post.report_id = report_id
        session.flush()
        succeeded += 1

    session.commit()
    return succeeded


def ingest_post(session: Any, post_id: str) -> str:
    """Ingest a single fetched post through Claude. Returns the new SourceReport ID."""
    from pythia.ingestion.forum_intel_parser import parse_dark_web_post
    from pythia.models.dark_web import DarkWebPost

    post: DarkWebPost | None = session.get(DarkWebPost, post_id)
    if post is None:
        raise ValueError(f"Post {post_id} not found")
    if post.status not in ("fetched", "failed"):
        raise ValueError(f"Post is in status '{post.status}'; must be 'fetched' to ingest")
    if not post.raw_content:
        raise ValueError("Post has no raw_content; fetch it first")

    post.status = "ingesting"
    session.flush()

    try:
        report_id = parse_dark_web_post(session, post)
    except Exception as exc:
        post.status = "failed"
        post.error = str(exc)[:500]
        session.commit()
        raise

    post.status = "done"
    post.report_id = report_id
    session.commit()
    return report_id
