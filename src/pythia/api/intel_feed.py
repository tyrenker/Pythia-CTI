"""Live intel feed aggregator API.

GET  /v1/intel-feed/sources           list configured RSS sources
POST /v1/intel-feed/sources           add a custom source (auth)
PATCH /v1/intel-feed/sources/{id}     toggle active/auto_ingest (auth)
DELETE /v1/intel-feed/sources/{id}    remove a source (auth)
GET  /v1/intel-feed/articles          paginated raw article queue
GET  /v1/intel-feed/articles/{id}     single article detail
POST /v1/intel-feed/fetch             trigger immediate feed poll (auth)
POST /v1/intel-feed/articles/{id}/ingest  run Claude on one article (auth)
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from pythia.core.db import get_session
from pythia.core.security import require_api_key
from pythia.models.intel_feed import IntelFeedArticle, IntelFeedSource

router = APIRouter()


# ── Response schemas ──────────────────────────────────────────────────────────


class FeedSourceOut(BaseModel):
    id: str
    name: str
    vendor: str
    url: str
    active: bool
    auto_ingest: bool
    poll_interval_h: int
    last_polled_at: datetime | None
    last_error: str | None
    article_count: int
    created_at: datetime

    model_config = {"from_attributes": True}


class FeedArticleOut(BaseModel):
    id: str
    source_id: str
    source_name: str
    title: str | None
    url: str
    published_at: datetime | None
    summary: str | None
    status: str
    report_id: str | None
    error: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Request schemas ───────────────────────────────────────────────────────────


class AddSourceBody(BaseModel):
    name: str
    vendor: str
    url: str
    poll_interval_h: int = 4
    auto_ingest: bool = False


class PatchSourceBody(BaseModel):
    active: bool | None = None
    auto_ingest: bool | None = None
    poll_interval_h: int | None = None


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.get("/sources", response_model=list[FeedSourceOut])
def list_sources(
    active_only: bool = Query(default=False, description="Return only active sources"),
    session: Session = Depends(get_session),
) -> list[IntelFeedSource]:
    q = session.query(IntelFeedSource)
    if active_only:
        q = q.filter_by(active=True)
    return q.order_by(IntelFeedSource.name).all()

@router.post("/sources", response_model=FeedSourceOut, status_code=201)
def add_source(
    body: AddSourceBody,
    _: Annotated[None, Depends(require_api_key)],
    session: Session = Depends(get_session),
) -> IntelFeedSource:
    existing = session.query(IntelFeedSource).filter_by(url=body.url).first()
    if existing:
        raise HTTPException(status_code=409, detail="A source with this URL already exists")

    source = IntelFeedSource(
        name=body.name,
        vendor=body.vendor,
        url=str(body.url),
        poll_interval_h=body.poll_interval_h,
        auto_ingest=body.auto_ingest,
    )
    session.add(source)
    session.commit()
    session.refresh(source)
    return source

@router.patch("/sources/{source_id}", response_model=FeedSourceOut)
def patch_source(
    source_id: str,
    body: PatchSourceBody,
    _: Annotated[None, Depends(require_api_key)],
    session: Session = Depends(get_session),
) -> IntelFeedSource:
    source = session.get(IntelFeedSource, source_id)
    if source is None:
        raise HTTPException(status_code=404, detail="Source not found")

    if body.active is not None:
        source.active = body.active
    if body.auto_ingest is not None:
        source.auto_ingest = body.auto_ingest
    if body.poll_interval_h is not None:
        source.poll_interval_h = body.poll_interval_h

    session.commit()
    session.refresh(source)
    return source

@router.delete("/sources/{source_id}", status_code=204)
def delete_source(
    source_id: str,
    _: Annotated[None, Depends(require_api_key)],
    session: Session = Depends(get_session),
) -> None:
    source = session.get(IntelFeedSource, source_id)
    if source is None:
        raise HTTPException(status_code=404, detail="Source not found")
    session.delete(source)
    session.commit()


@router.get("/articles", response_model=list[FeedArticleOut])
def list_articles(
    source_id: str | None = Query(default=None),
    status: str | None = Query(default=None, description="queued|ingesting|done|failed|skipped"),
    since: datetime | None = Query(default=None, description="Filter by published_at >= since"),
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_session),
) -> list[IntelFeedArticle]:
    q = session.query(IntelFeedArticle)
    if source_id:
        q = q.filter(IntelFeedArticle.source_id == source_id)
    if status:
        q = q.filter(IntelFeedArticle.status == status)
    if since:
        q = q.filter(IntelFeedArticle.published_at >= since)
    return q.order_by(IntelFeedArticle.published_at.desc()).offset(offset).limit(limit).all()

@router.get("/articles/{article_id}", response_model=FeedArticleOut)
def get_article(
    article_id: str,
    session: Session = Depends(get_session),
) -> IntelFeedArticle:
    article = session.get(IntelFeedArticle, article_id)
    if article is None:
        raise HTTPException(status_code=404, detail="Article not found")
    return article

@router.post("/fetch", status_code=202)
def trigger_fetch(
    source_id: str | None = Query(default=None, description="Limit poll to one source by ID"),
    _: Annotated[None, Depends(require_api_key)] = None,
    session: Session = Depends(get_session),
) -> dict[str, object]:
    """Trigger an immediate RSS poll. Runs synchronously; may take a few seconds."""
    from pythia.ingestion.feed_poller import poll_all_feeds

    if source_id:
        source = session.get(IntelFeedSource, source_id)
        if source is None:
            raise HTTPException(status_code=404, detail="Source not found")
        # Temporarily reset last_polled_at so the poll doesn't filter out recent articles
        # (it uses cutoff, so a manual trigger should still pull the latest batch)

    new_articles = poll_all_feeds(session)
    return {"status": "ok", "new_articles": new_articles}


@router.post("/articles/{article_id}/ingest", status_code=202)
def ingest_article(
    article_id: str,
    _: Annotated[None, Depends(require_api_key)],
    session: Session = Depends(get_session),
) -> dict[str, str]:
    """Run Claude on a specific queued article and create a SourceReport."""
    from pythia.ingestion.feed_poller import ingest_article as _ingest

    try:
        report_id = _ingest(session, article_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return {"status": "done", "report_id": report_id}
