"""Honeypot event ingestion and campaign API.

POST   /v1/honeypot/events/bulk       Filebeat batch ingest (API key required)
POST   /v1/honeypot/events            Single event ingest (API key required)
GET    /v1/honeypot/events            List events (?ip=, ?type=, ?campaign=, ?since=, ?limit=)
GET    /v1/honeypot/events/{id}       Event detail with enrichment
GET    /v1/honeypot/campaigns         List campaigns (?status=, ?since=, ?limit=)
GET    /v1/honeypot/campaigns/{id}    Campaign detail + member event summary
POST   /v1/honeypot/campaigns/{id}/generate-report  Trigger campaign CTI report
GET    /v1/honeypot/stats/daily       Last 24h summary
GET    /v1/honeypot/stats/realtime    Last 5 minutes event counts
GET    /v1/honeypot/feeds/blocklist.txt  IP blocklist (no auth)
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Query,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from pythia.core.db import get_session
from pythia.core.security import require_api_key
from pythia.models.honeypot import HoneypotCampaign, HoneypotEvent

router = APIRouter()

# Module-level WebSocket subscriber queues
_honeypot_subscribers: list[asyncio.Queue[dict[str, Any]]] = []


def push_to_stream(event_dict: dict[str, Any]) -> None:
    for q in _honeypot_subscribers:
        with contextlib.suppress(asyncio.QueueFull):
            q.put_nowait(event_dict)


# ── Response schemas ──────────────────────────────────────────────────────────


class HoneypotEventOut(BaseModel):
    id: str
    honeypot_type: str
    attacker_ip: str
    attacker_asn: str | None
    attacker_country_code: str | None
    attacker_org: str | None
    target_port: int | None
    protocol: str | None
    event_timestamp: datetime
    received_at: datetime
    tpot_session_id: str | None
    username_attempted: str | None
    password_attempted: str | None
    commands_run: list[str]
    files_downloaded: list[str]
    payload_hash: str | None
    ttp_ids: list[str]
    campaign_id: str | None
    enriched_at: datetime | None
    abuseipdb_score: int | None
    greynoise_classification: str | None
    vt_detections: int | None

    model_config = {"from_attributes": True}


class HoneypotCampaignOut(BaseModel):
    id: str
    name: str
    status: str
    first_seen: datetime
    last_seen: datetime
    attacker_ips: list[str]
    asns: list[str]
    ttp_ids: list[str]
    payload_hashes: list[str]
    credential_patterns: dict[str, Any]
    target_ports: list[int]
    event_count: int
    sigma_rule_id: str | None
    report_id: str | None
    notes: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ── Ingest helpers ────────────────────────────────────────────────────────────


def _ingest_raw(
    raw: dict[str, Any], session: Session, background_tasks: BackgroundTasks
) -> HoneypotEvent:
    from pythia.ingestion.honeypot_normalizer import normalize

    fields = normalize(raw)
    event = HoneypotEvent(
        id=str(uuid.uuid4()),
        received_at=datetime.utcnow(),
        **fields,
    )
    session.add(event)
    session.commit()
    session.refresh(event)
    background_tasks.add_task(_enrich_in_background, event.id)
    # Push to WebSocket stream
    push_to_stream(
        {
            "id": event.id,
            "honeypot_type": event.honeypot_type,
            "attacker_ip": event.attacker_ip,
            "target_port": event.target_port,
            "protocol": event.protocol,
            "event_timestamp": event.event_timestamp.isoformat(),
            "received_at": event.received_at.isoformat(),
            "ttp_ids": event.ttp_ids,
        }
    )
    return event


def _enrich_in_background(event_id: str) -> None:
    from pythia.ingestion.honeypot_enricher import enrich_event

    enrich_event(event_id)


# ── Endpoints — ingest ────────────────────────────────────────────────────────


@router.post("/events/bulk", status_code=200)
def ingest_bulk(
    events: list[dict[str, Any]],
    background_tasks: BackgroundTasks,
    _: Annotated[None, Depends(require_api_key)],
    session: Session = Depends(get_session),
) -> dict[str, int]:
    count = 0
    for raw in events:
        try:
            _ingest_raw(raw, session, background_tasks)
            count += 1
        except Exception:
            pass
    return {"ingested": count}


@router.post("/events", response_model=HoneypotEventOut, status_code=201)
def ingest_single(
    raw: dict[str, Any],
    background_tasks: BackgroundTasks,
    _: Annotated[None, Depends(require_api_key)],
    session: Session = Depends(get_session),
) -> HoneypotEvent:
    return _ingest_raw(raw, session, background_tasks)


# ── Endpoints — query ─────────────────────────────────────────────────────────


@router.get("/events", response_model=list[HoneypotEventOut])
def list_events(
    ip: str | None = Query(default=None),
    honeypot_type: str | None = Query(default=None),
    campaign: str | None = Query(default=None),
    since: datetime | None = Query(default=None),
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_session),
) -> list[HoneypotEvent]:
    q = session.query(HoneypotEvent)
    if ip:
        q = q.filter(HoneypotEvent.attacker_ip == ip)
    if honeypot_type:
        q = q.filter(HoneypotEvent.honeypot_type == honeypot_type)
    if campaign:
        q = q.filter(HoneypotEvent.campaign_id == campaign)
    if since:
        q = q.filter(HoneypotEvent.event_timestamp >= since)
    return q.order_by(HoneypotEvent.received_at.desc()).offset(offset).limit(limit).all()


@router.get("/events/{event_id}", response_model=HoneypotEventOut)
def get_event(event_id: str, session: Session = Depends(get_session)) -> HoneypotEvent:
    event = session.get(HoneypotEvent, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@router.get("/campaigns", response_model=list[HoneypotCampaignOut])
def list_campaigns(
    status: str | None = Query(default=None),
    since: datetime | None = Query(default=None),
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_session),
) -> list[HoneypotCampaign]:
    q = session.query(HoneypotCampaign)
    if status:
        q = q.filter(HoneypotCampaign.status == status)
    if since:
        q = q.filter(HoneypotCampaign.first_seen >= since)
    return q.order_by(HoneypotCampaign.last_seen.desc()).offset(offset).limit(limit).all()


@router.get("/campaigns/{campaign_id}", response_model=HoneypotCampaignOut)
def get_campaign(campaign_id: str, session: Session = Depends(get_session)) -> HoneypotCampaign:
    campaign = session.get(HoneypotCampaign, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return campaign


@router.post("/campaigns/{campaign_id}/generate-report", status_code=202)
def generate_campaign_report_endpoint(
    campaign_id: str,
    background_tasks: BackgroundTasks,
    _: Annotated[None, Depends(require_api_key)],
    session: Session = Depends(get_session),
) -> dict[str, str]:
    campaign = session.get(HoneypotCampaign, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    background_tasks.add_task(_generate_campaign_report_bg, campaign_id)
    return {"status": "queued", "campaign_id": campaign_id}


def _generate_campaign_report_bg(campaign_id: str) -> None:
    import contextlib

    from pythia.core.db import SessionLocal
    from pythia.reporting.honeypot_report import generate_campaign_report

    with SessionLocal() as s, contextlib.suppress(Exception):
        generate_campaign_report(s, campaign_id)


# ── Stats endpoints ───────────────────────────────────────────────────────────


@router.get("/stats/daily")
def stats_daily(session: Session = Depends(get_session)) -> dict[str, Any]:
    cutoff = datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=24)
    events = session.query(HoneypotEvent).filter(HoneypotEvent.received_at >= cutoff).all()
    ip_counts: Counter[str] = Counter(e.attacker_ip for e in events)
    port_counts: Counter[int] = Counter(e.target_port for e in events if e.target_port)
    type_counts: Counter[str] = Counter(e.honeypot_type for e in events)
    cred_counts: Counter[str] = Counter(
        f"{e.username_attempted}:{e.password_attempted}" for e in events if e.username_attempted
    )
    country_counts: Counter[str] = Counter(
        e.attacker_country_code for e in events if e.attacker_country_code
    )
    return {
        "event_count": len(events),
        "top_ips": ip_counts.most_common(10),
        "top_ports": port_counts.most_common(10),
        "by_honeypot_type": dict(type_counts),
        "top_credentials": cred_counts.most_common(10),
        "top_countries": country_counts.most_common(10),
    }


@router.get("/stats/realtime")
def stats_realtime(session: Session = Depends(get_session)) -> dict[str, Any]:
    cutoff = datetime.now(UTC).replace(tzinfo=None) - timedelta(minutes=5)
    events = session.query(HoneypotEvent).filter(HoneypotEvent.received_at >= cutoff).all()
    by_type: Counter[str] = Counter(e.honeypot_type for e in events)
    return {
        "window_minutes": 5,
        "event_count": len(events),
        "by_honeypot_type": dict(by_type),
    }


# ── Blocklist feed ────────────────────────────────────────────────────────────


@router.get("/feeds/blocklist.txt", response_class=PlainTextResponse)
def blocklist(session: Session = Depends(get_session)) -> PlainTextResponse:
    # High-confidence IPs: score >= 70 or in active campaign
    high_score_ips = (
        session.query(HoneypotEvent.attacker_ip)
        .filter(HoneypotEvent.abuseipdb_score >= 70)
        .distinct()
        .all()
    )
    active_campaign_ips = (
        session.query(HoneypotEvent.attacker_ip)
        .join(HoneypotCampaign, HoneypotEvent.campaign_id == HoneypotCampaign.id)
        .filter(HoneypotCampaign.status == "active")
        .distinct()
        .all()
    )
    all_ips = sorted({ip for (ip,) in high_score_ips} | {ip for (ip,) in active_campaign_ips})
    content = "\n".join(all_ips)
    return PlainTextResponse(
        content,
        headers={"Cache-Control": "max-age=3600"},
    )


# ── STIX/TAXII feed ──────────────────────────────────────────────────────────


@router.get("/taxii/honeypot-iocs")
def taxii_honeypot_iocs(
    status: str = Query(default="active"),
    session: Session = Depends(get_session),
) -> Any:
    """TAXII-style endpoint: STIX 2.1 bundle of honeypot campaign IOCs."""
    from pythia.exporters.stix import export_honeypot_iocs

    campaigns = session.query(HoneypotCampaign).filter(HoneypotCampaign.status == status).all()
    bundle = export_honeypot_iocs(campaigns)
    return JSONResponse(
        content=bundle,
        headers={
            "Content-Type": "application/taxii+json;version=2.1",
            "Cache-Control": "max-age=3600",
        },
    )


# ── Admin / demo helpers ──────────────────────────────────────────────────────


@router.post("/detect-now")
def trigger_detection_now(
    _: Annotated[None, Depends(require_api_key)],
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    """Manually trigger campaign detection — for demos and testing."""
    from pythia.ingestion.campaign_detector import detect_campaigns

    before = session.query(HoneypotCampaign).count()
    detect_campaigns(session)
    session.expire_all()
    after = session.query(HoneypotCampaign).count()
    return {"campaigns_before": before, "campaigns_after": after, "new": after - before}


# ── WebSocket stream ──────────────────────────────────────────────────────────


@router.websocket("/stream")
async def honeypot_stream(websocket: WebSocket) -> None:
    await websocket.accept()
    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
    _honeypot_subscribers.append(queue)
    try:
        while True:
            event_dict = await queue.get()
            await websocket.send_text(json.dumps(event_dict))
    except WebSocketDisconnect:
        pass
    finally:
        with contextlib.suppress(ValueError):
            _honeypot_subscribers.remove(queue)
