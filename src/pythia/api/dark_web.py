"""Dark web forum monitoring API.

GET    /v1/dark-web/sources                  list monitored sources
POST   /v1/dark-web/sources                  add custom source (auth)
PATCH  /v1/dark-web/sources/{id}             toggle active/auto_ingest (auth)
DELETE /v1/dark-web/sources/{id}             remove source (auth)
GET    /v1/dark-web/posts                    recent posts with filters
GET    /v1/dark-web/posts/{id}               post detail + linked report
POST   /v1/dark-web/posts/{id}/fetch         manually fetch full text (auth)
POST   /v1/dark-web/posts/{id}/ingest        run Claude on a fetched post (auth)
POST   /v1/dark-web/pull                     trigger immediate pull (auth)
GET    /v1/dark-web/victims                  deduplicated ransomware victim list
GET    /v1/dark-web/stats                    summary counts
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from pythia.core.db import get_session
from pythia.core.security import require_api_key
from pythia.models.dark_web import DarkWebForumSource, DarkWebPost

router = APIRouter()


# ── Response schemas ──────────────────────────────────────────────────────────


class DarkWebSourceOut(BaseModel):
    id: str
    name: str
    category: str
    active: bool
    auto_ingest: bool
    poll_interval_h: int
    last_polled_at: datetime | None
    last_error: str | None
    post_count: int
    description: str | None
    onion_url: str
    created_at: datetime

    model_config = {"from_attributes": True}


class DarkWebPostOut(BaseModel):
    id: str
    source_id: str
    source_name: str | None
    category: str | None
    title: str | None
    published_at: datetime | None
    status: str
    victim_org: str | None
    victim_sector: str | None
    victim_country: str | None
    threat_actor: str | None
    tlp: str
    admiralty_code: str
    report_id: str | None
    created_at: datetime
    error: str | None

    model_config = {"from_attributes": True}


class VictimOut(BaseModel):
    victim_org: str
    victim_sector: str | None
    victim_country: str | None
    threat_actor: str | None
    first_seen: datetime
    post_id: str


# ── Request schemas ───────────────────────────────────────────────────────────


class AddSourceBody(BaseModel):
    name: str
    onion_url: str
    category: str = "ransomware"
    poll_interval_h: int = 4
    auto_ingest: bool = False
    description: str | None = None


class PatchSourceBody(BaseModel):
    active: bool | None = None
    auto_ingest: bool | None = None
    poll_interval_h: int | None = None


# ── Helpers ───────────────────────────────────────────────────────────────────


def _enrich_post(post: DarkWebPost, session: Session) -> dict[str, object]:
    source = session.get(DarkWebForumSource, post.source_id)
    return {
        "id": post.id,
        "source_id": post.source_id,
        "source_name": source.name if source else None,
        "category": source.category if source else None,
        "title": post.title,
        "published_at": post.published_at,
        "status": post.status,
        "victim_org": post.victim_org,
        "victim_sector": post.victim_sector,
        "victim_country": post.victim_country,
        "threat_actor": post.threat_actor,
        "tlp": post.tlp,
        "admiralty_code": post.admiralty_code,
        "report_id": post.report_id,
        "created_at": post.created_at,
        "error": post.error,
    }


# ── Endpoints — sources ───────────────────────────────────────────────────────


@router.get("/sources", response_model=list[DarkWebSourceOut])
def list_sources(
    category: str | None = Query(default=None),
    active_only: bool = Query(default=False),
    session: Session = Depends(get_session),
) -> list[DarkWebForumSource]:
    q = session.query(DarkWebForumSource)
    if active_only:
        q = q.filter_by(active=True)
    if category:
        q = q.filter(DarkWebForumSource.category == category)
    return q.order_by(DarkWebForumSource.name).all()


@router.post("/sources", response_model=DarkWebSourceOut, status_code=201)
def add_source(
    body: AddSourceBody,
    _: Annotated[None, Depends(require_api_key)],
    session: Session = Depends(get_session),
) -> DarkWebForumSource:
    existing = session.query(DarkWebForumSource).filter_by(onion_url=body.onion_url).first()
    if existing:
        raise HTTPException(status_code=409, detail="A source with this onion URL already exists")
    source = DarkWebForumSource(
        name=body.name,
        onion_url=body.onion_url,
        category=body.category,
        poll_interval_h=body.poll_interval_h,
        auto_ingest=body.auto_ingest,
        description=body.description,
    )
    session.add(source)
    session.commit()
    session.refresh(source)
    return source


@router.patch("/sources/{source_id}", response_model=DarkWebSourceOut)
def patch_source(
    source_id: str,
    body: PatchSourceBody,
    _: Annotated[None, Depends(require_api_key)],
    session: Session = Depends(get_session),
) -> DarkWebForumSource:
    source = session.get(DarkWebForumSource, source_id)
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
    source = session.get(DarkWebForumSource, source_id)
    if source is None:
        raise HTTPException(status_code=404, detail="Source not found")
    session.delete(source)
    session.commit()


# ── Endpoints — posts ─────────────────────────────────────────────────────────


@router.get("/posts", response_model=list[DarkWebPostOut])
def list_posts(
    source_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    category: str | None = Query(default=None),
    victim_sector: str | None = Query(default=None),
    threat_actor: str | None = Query(default=None),
    since: datetime | None = Query(default=None),
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_session),
) -> list[dict[str, object]]:
    q = session.query(DarkWebPost)
    if source_id:
        q = q.filter(DarkWebPost.source_id == source_id)
    if status:
        q = q.filter(DarkWebPost.status == status)
    if victim_sector:
        q = q.filter(DarkWebPost.victim_sector.ilike(f"%{victim_sector}%"))
    if threat_actor:
        q = q.filter(DarkWebPost.threat_actor.ilike(f"%{threat_actor}%"))
    if since:
        q = q.filter(DarkWebPost.created_at >= since)
    if category:
        source_ids = [
            s.id for s in session.query(DarkWebForumSource).filter_by(category=category).all()
        ]
        q = q.filter(DarkWebPost.source_id.in_(source_ids))
    posts = q.order_by(DarkWebPost.created_at.desc()).offset(offset).limit(limit).all()
    return [_enrich_post(p, session) for p in posts]


@router.get("/posts/{post_id}", response_model=DarkWebPostOut)
def get_post(
    post_id: str,
    session: Session = Depends(get_session),
) -> dict[str, object]:
    post = session.get(DarkWebPost, post_id)
    if post is None:
        raise HTTPException(status_code=404, detail="Post not found")
    return _enrich_post(post, session)


@router.post("/posts/{post_id}/fetch", status_code=202)
def fetch_post(
    post_id: str,
    _: Annotated[None, Depends(require_api_key)],
    session: Session = Depends(get_session),
) -> dict[str, str]:
    """Manually fetch full text for a queued dark web post via Tor."""
    from pythia.ingestion.dark_web_poller import fetch_post_content

    post = session.get(DarkWebPost, post_id)
    if post is None:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.status not in ("queued", "failed"):
        raise HTTPException(status_code=422, detail=f"Post is in status '{post.status}'")
    try:
        fetch_post_content(session, post_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {"status": "fetched", "post_id": post_id}


@router.post("/posts/{post_id}/ingest", status_code=202)
def ingest_post(
    post_id: str,
    _: Annotated[None, Depends(require_api_key)],
    session: Session = Depends(get_session),
) -> dict[str, str]:
    """Run Claude forum parser on a fetched post."""
    from pythia.ingestion.dark_web_poller import ingest_post as _ingest

    try:
        report_id = _ingest(session, post_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {"status": "done", "report_id": report_id}


# ── Endpoints — pull ──────────────────────────────────────────────────────────


@router.post("/pull", status_code=202)
def trigger_pull(
    source_id: str | None = Query(default=None, description="Limit to one source by ID"),
    _: Annotated[None, Depends(require_api_key)] = None,
    session: Session = Depends(get_session),
) -> dict[str, object]:
    """Trigger an immediate pull of all (or one) dark web source(s)."""
    from pythia.core.config import get_settings
    from pythia.core.tor_proxy import TorProxyManager
    from pythia.ingestion.dark_web_poller import poll_all_dark_web_sources

    if source_id:
        source = session.get(DarkWebForumSource, source_id)
        if source is None:
            raise HTTPException(status_code=404, detail="Source not found")

    settings = get_settings()
    tor = TorProxyManager(
        control_host=settings.tor_host,
        control_port=settings.tor_control_port,
        password=settings.tor_control_password,
    )
    if not tor.is_available():
        raise HTTPException(
            status_code=503,
            detail="Tor proxy is not reachable — ensure Tor is running on port 9050",
        )

    try:
        new_posts = poll_all_dark_web_sources(session)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return {"status": "ok", "new_posts": new_posts}


# ── Endpoints — victims & stats ───────────────────────────────────────────────


@router.get("/victims", response_model=list[VictimOut])
def list_victims(
    sector: str | None = Query(default=None),
    country: str | None = Query(default=None),
    actor: str | None = Query(default=None),
    since: datetime | None = Query(default=None),
    limit: int = Query(default=100, le=500),
    session: Session = Depends(get_session),
) -> list[VictimOut]:
    """Deduplicated ransomware victim org list."""
    q = (
        session.query(DarkWebPost)
        .filter(DarkWebPost.victim_org.isnot(None))
        .filter(DarkWebPost.status == "done")
    )
    if sector:
        q = q.filter(DarkWebPost.victim_sector.ilike(f"%{sector}%"))
    if country:
        q = q.filter(DarkWebPost.victim_country.ilike(f"%{country}%"))
    if actor:
        q = q.filter(DarkWebPost.threat_actor.ilike(f"%{actor}%"))
    if since:
        q = q.filter(DarkWebPost.created_at >= since)
    posts = q.order_by(DarkWebPost.created_at.desc()).limit(limit).all()

    # Dedup by victim_org (keep first-seen per org)
    seen: set[str] = set()
    results = []
    for p in posts:
        key = (p.victim_org or "").lower()
        if key in seen:
            continue
        seen.add(key)
        results.append(
            VictimOut(
                victim_org=p.victim_org or "",
                victim_sector=p.victim_sector,
                victim_country=p.victim_country,
                threat_actor=p.threat_actor,
                first_seen=p.created_at,
                post_id=p.id,
            )
        )
    return results


@router.get("/stats")
def stats(
    session: Session = Depends(get_session),
) -> dict[str, object]:
    """Summary counts: posts by category/status, victims by sector, top active groups."""
    from collections import Counter
    from datetime import UTC, timedelta

    sources = session.query(DarkWebForumSource).all()
    posts = session.query(DarkWebPost).all()

    now = datetime.now(UTC).replace(tzinfo=None)
    today_cutoff = now - timedelta(days=1)
    month_cutoff = now - timedelta(days=30)

    by_status: Counter[str] = Counter(p.status for p in posts)
    by_category: dict[str, int] = {}
    for s in sources:
        cat = s.category
        count = sum(1 for p in posts if p.source_id == s.id)
        by_category[cat] = by_category.get(cat, 0) + count

    posts_today = len([p for p in posts if p.created_at and p.created_at >= today_cutoff])
    victims_30d = len(
        [p for p in posts if p.victim_org and p.created_at and p.created_at >= month_cutoff]
    )
    pending_ingest = len([p for p in posts if p.status == "fetched"])

    actor_counts: Counter[str] = Counter(p.threat_actor for p in posts if p.threat_actor)
    top_actor = max(actor_counts, key=lambda k: actor_counts[k]) if actor_counts else None
    top_actor_count = actor_counts.get(top_actor, 0) if top_actor else 0

    return {
        "active_sources": len([s for s in sources if s.active]),
        "total_sources": len(sources),
        "posts_today": posts_today,
        "victims_30d": victims_30d,
        "pending_ingest": pending_ingest,
        "top_actor": top_actor,
        "top_actor_count": top_actor_count,
        "by_status": dict(by_status),
        "by_category": by_category,
    }
