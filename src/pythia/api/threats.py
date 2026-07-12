"""Threat intel feed endpoints — backed by ingested SourceReports."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from pythia.core.db import get_session
from pythia.core.security import require_api_key
from pythia.models.report import SourceReport

router = APIRouter()


class ThreatSummary(BaseModel):
    id: str
    title: str | None = None
    url: str | None = None
    publication_date: str | None = None
    created_at: str | None = None
    tlp: str
    status: str
    actors: list[str] = Field(default_factory=list)
    ttps: list[str] = Field(default_factory=list)
    ioc_count: int = 0


class ThreatDetail(ThreatSummary):
    summary: str | None = None
    sectors_targeted: list[str] = Field(default_factory=list)
    geographies_targeted: list[str] = Field(default_factory=list)
    killchain_phases: list[str] = Field(default_factory=list)
    parsed_data: dict[str, object] = Field(default_factory=dict)


class SuggestedRule(BaseModel):
    title: str
    content: str
    description: str = ""
    severity: str = "medium"
    linked_ttps: list[str] = Field(default_factory=list)
    pyramid_tier: str = "ttp"


class SuggestedQuery(BaseModel):
    title: str
    content: str
    description: str = ""

class SuggestedRulesResponse(BaseModel):
    sigma_rules: list[SuggestedRule] = Field(default_factory=list)
    yara_rules: list[SuggestedRule] = Field(default_factory=list)
    splunk_queries: list[SuggestedQuery] = Field(default_factory=list)
    elastic_queries: list[SuggestedQuery] = Field(default_factory=list)
    playbook: str = ""
    generation_notes: str = ""


def _to_summary(r: SourceReport) -> ThreatSummary:
    pd = r.parsed_data or {}
    actors = [a.get("name", "") for a in (pd.get("actors") or [])]
    ttps = [t.get("technique_id", "") for t in (pd.get("ttps") or [])]
    iocs = len(pd.get("iocs") or []) + len(pd.get("cves") or [])
    return ThreatSummary(
        id=r.id,
        title=r.title,
        url=r.url,
        publication_date=r.publication_date,
        created_at=r.created_at.isoformat() if r.created_at else None,
        tlp=r.tlp,
        status=r.status,
        actors=actors,
        ttps=ttps,
        ioc_count=iocs,
    )


@router.get("", response_model=list[ThreatSummary])
async def list_threats(
    status: str | None = Query(
        default=None, description="Filter by status (pending_review|accepted|rejected)"
    ),
    tlp: str | None = Query(default=None, description="Filter by TLP marking"),
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_session),
) -> list[ThreatSummary]:
    q = session.query(SourceReport)
    if status:
        q = q.filter(SourceReport.status == status)
    if tlp:
        q = q.filter(SourceReport.tlp == tlp.upper())
    reports = q.order_by(SourceReport.created_at.desc()).offset(offset).limit(limit).all()
    return [_to_summary(r) for r in reports]


@router.get("/{threat_id}", response_model=ThreatDetail)
async def get_threat(
    threat_id: str,
    session: Session = Depends(get_session),
) -> ThreatDetail:
    r = session.get(SourceReport, threat_id)
    if not r:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Threat report '{threat_id}' not found"
        )
    pd = r.parsed_data or {}
    actors = [a.get("name", "") for a in (pd.get("actors") or [])]
    ttps = [t.get("technique_id", "") for t in (pd.get("ttps") or [])]
    iocs = len(pd.get("iocs") or []) + len(pd.get("cves") or [])
    return ThreatDetail(
        id=r.id,
        title=r.title,
        url=r.url,
        publication_date=r.publication_date,
        tlp=r.tlp,
        status=r.status,
        actors=actors,
        ttps=ttps,
        ioc_count=iocs,
        summary=pd.get("summary"),  # type: ignore[arg-type]
        sectors_targeted=pd.get("sectors_targeted") or [],  # type: ignore[arg-type]
        geographies_targeted=pd.get("geographies_targeted") or [],  # type: ignore[arg-type]
        killchain_phases=pd.get("killchain_phases") or [],  # type: ignore[arg-type]
        parsed_data=pd,
    )


@router.post("/{threat_id}/suggest-rules", response_model=SuggestedRulesResponse)
def suggest_rules(
    threat_id: str,
    _: Annotated[None, Depends(require_api_key)],
    session: Session = Depends(get_session),
) -> SuggestedRulesResponse:
    """Generate AI-suggested Sigma and YARA rules from a report's extracted TTPs, IoCs, and actors."""
    from pythia.ingestion.rule_generator import generate_suggested_rules

    r = session.get(SourceReport, threat_id)
    if not r:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Threat report '{threat_id}' not found")

    pd = r.parsed_data
    if not pd:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Report has no parsed data to generate rules from",
        )

    try:
        result = generate_suggested_rules(pd)
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Rule generation failed: {exc}",
        ) from exc

    # Persist the generated rules to the report's parsed_data so they survive tab switches
    new_pd = dict(pd)
    new_pd["suggested_rules"] = result
    r.parsed_data = new_pd
    session.commit()

    return SuggestedRulesResponse(
        sigma_rules=[SuggestedRule(**r) for r in result.get("sigma_rules", [])],
        yara_rules=[SuggestedRule(**r) for r in result.get("yara_rules", [])],
        splunk_queries=[SuggestedQuery(**r) for r in result.get("splunk_queries", [])],
        elastic_queries=[SuggestedQuery(**r) for r in result.get("elastic_queries", [])],
        playbook=result.get("playbook", ""),
        generation_notes=result.get("generation_notes", ""),
    )
