"""Indicator of Compromise endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from pythia.core.db import get_session
from pythia.exporters.stix import export_ioc, export_iocs
from pythia.models.actor import ThreatActor
from pythia.models.ioc import IoC

router = APIRouter()


class IoCDetail(BaseModel):
    id: str
    type: str
    value: str
    confidence_source: str
    confidence_info: str
    tlp: str
    pyramid_tier: str
    context: str | None = None
    source_url: str | None = None
    technique_ids: list[str] = Field(default_factory=list)
    actor_id: str | None = None
    actor_name: str | None = None


@router.get("", response_model=list[IoCDetail])
async def list_iocs(
    type: str | None = Query(default=None, description="Filter by IoC type (e.g. cve, ip, domain, hash)"),
    pyramid_tier: str | None = Query(default=None, description="Filter by Pyramid of Pain tier"),
    actor_id: str | None = Query(default=None, description="Filter by linked actor UUID"),
    tlp: str | None = Query(default=None, description="Filter by TLP marking (WHITE, GREEN, AMBER, RED)"),
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_session),
) -> list[IoCDetail]:
    q = session.query(IoC, ThreatActor.name).outerjoin(ThreatActor, IoC.actor_id == ThreatActor.id)
    if type:
        q = q.filter(IoC.type == type.lower())
    if pyramid_tier:
        q = q.filter(IoC.pyramid_tier == pyramid_tier.lower())
    if actor_id:
        q = q.filter(IoC.actor_id == actor_id)
    if tlp:
        q = q.filter(IoC.tlp == tlp.upper())
    results = q.order_by(IoC.created_at.desc()).offset(offset).limit(limit).all()
    return [
        IoCDetail(
            id=i.id,
            type=i.type,
            value=i.value,
            confidence_source=i.confidence_source,
            confidence_info=i.confidence_info,
            tlp=i.tlp,
            pyramid_tier=i.pyramid_tier,
            context=i.context,
            source_url=i.source_url,
            technique_ids=i.technique_ids or [],
            actor_id=i.actor_id,
            actor_name=actor_name,
        )
        for i, actor_name in results
    ]


@router.get("/stix/bundle", include_in_schema=True)
async def get_iocs_stix(
    type: str | None = Query(default=None, description="Filter by IoC type"),
    pyramid_tier: str | None = Query(default=None),
    actor_id: str | None = Query(default=None),
    limit: int = Query(default=100, le=500),
    session: Session = Depends(get_session),
) -> JSONResponse:
    """Export filtered IoCs as a STIX 2.1 indicator bundle."""
    q = session.query(IoC)
    if type:
        q = q.filter(IoC.type == type.lower())
    if pyramid_tier:
        q = q.filter(IoC.pyramid_tier == pyramid_tier.lower())
    if actor_id:
        q = q.filter(IoC.actor_id == actor_id)
    iocs = q.order_by(IoC.created_at.desc()).limit(limit).all()
    bundle = export_iocs(iocs)
    return JSONResponse(content=bundle, media_type="application/stix+json")


@router.get("/{ioc_id}/stix", include_in_schema=True)
async def get_ioc_stix(
    ioc_id: str,
    session: Session = Depends(get_session),
) -> JSONResponse:
    """Export a single IoC as a STIX 2.1 indicator bundle."""
    ioc = session.get(IoC, ioc_id)
    if not ioc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"IoC '{ioc_id}' not found")
    bundle = export_ioc(ioc)
    return JSONResponse(content=bundle, media_type="application/stix+json")


@router.get("/{ioc_id}", response_model=IoCDetail)
async def get_ioc(
    ioc_id: str,
    session: Session = Depends(get_session),
) -> IoCDetail:
    result = (
        session.query(IoC, ThreatActor.name)
        .outerjoin(ThreatActor, IoC.actor_id == ThreatActor.id)
        .filter(IoC.id == ioc_id)
        .first()
    )
    if not result:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"IoC '{ioc_id}' not found")
    ioc, actor_name = result
    return IoCDetail(
        id=ioc.id,
        type=ioc.type,
        value=ioc.value,
        confidence_source=ioc.confidence_source,
        confidence_info=ioc.confidence_info,
        tlp=ioc.tlp,
        pyramid_tier=ioc.pyramid_tier,
        context=ioc.context,
        source_url=ioc.source_url,
        technique_ids=ioc.technique_ids or [],
        actor_id=ioc.actor_id,
        actor_name=actor_name,
    )
