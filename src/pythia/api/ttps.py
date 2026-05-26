"""MITRE ATT&CK / ATLAS technique endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from pythia.core.db import get_session
from pythia.detections.converters import convert as sigma_convert
from pythia.models.atlas import AtlasTechnique
from pythia.models.attck import AttckTechnique
from pythia.models.rule import DetectionRule

router = APIRouter()


class TechniqueDetail(BaseModel):
    technique_id: str
    name: str
    description: str | None = None
    tactics: list[str] = Field(default_factory=list)
    is_subtechnique: bool = False
    parent_id: str | None = None
    domain: str
    platforms: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)
    detection_note: str | None = None
    source_url: str | None = None
    framework: str = "attck"


class AtlasTechniqueDetail(BaseModel):
    technique_id: str
    name: str
    description: str | None = None
    tactics: list[str] = Field(default_factory=list)
    subtechniques: list[str] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)
    source_url: str | None = None
    framework: str = "atlas"


@router.get("/{technique_id}", response_model=TechniqueDetail | AtlasTechniqueDetail)
async def get_ttp(
    technique_id: str,
    session: Session = Depends(get_session),
) -> TechniqueDetail | AtlasTechniqueDetail:
    tech_upper = technique_id.upper()

    # MITRE ATLAS (AML.T*)
    if tech_upper.startswith("AML."):
        obj = session.get(AtlasTechnique, technique_id) or session.get(AtlasTechnique, tech_upper)
        if not obj:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"ATLAS technique '{technique_id}' not found")
        return AtlasTechniqueDetail(
            technique_id=obj.technique_id,
            name=obj.name,
            description=obj.description,
            tactics=obj.tactics or [],
            subtechniques=obj.subtechniques or [],
            mitigations=obj.mitigations or [],
            source_url=obj.source_url,
        )

    # MITRE ATT&CK (T*)
    obj = session.get(AttckTechnique, tech_upper)
    if not obj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"ATT&CK technique '{technique_id}' not found")
    return TechniqueDetail(
        technique_id=obj.technique_id,
        name=obj.name,
        description=obj.description,
        tactics=obj.tactics or [],
        is_subtechnique=obj.is_subtechnique,
        parent_id=obj.parent_id,
        domain=obj.domain,
        platforms=obj.platforms or [],
        data_sources=obj.data_sources or [],
        detection_note=obj.detection_note,
        source_url=obj.source_url,
    )


@router.get("/{technique_id}/hunt-queries")
async def get_hunt_queries(
    technique_id: str,
    session: Session = Depends(get_session),
) -> dict[str, object]:
    """Return multi-platform hunt queries for a technique.

    Converts all Sigma rules that cover this technique to Splunk SPL,
    Elastic KQL, and Microsoft Sentinel KQL. Also surfaces ATT&CK data
    sources as search context hints.
    """
    tech_upper = technique_id.upper()
    tech = session.get(AttckTechnique, tech_upper)
    if not tech:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail=f"Technique '{technique_id}' not found")

    # Find rules covering this technique
    rules = session.query(DetectionRule).all()
    matching_rules = [r for r in rules if tech_upper in [t.upper() for t in (r.technique_ids or [])]]

    hunt_queries: list[dict[str, object]] = []
    for rule in matching_rules:
        splunk = sigma_convert(rule.content, "splunk")
        elastic = sigma_convert(rule.content, "elastic")
        sentinel = sigma_convert(rule.content, "sentinel")
        hunt_queries.append({
            "id": rule.id,
            "title": rule.title,
            "technique_ids": rule.technique_ids or [],
            "severity": rule.severity or "medium",
            "tags": [],
            "splunk_spl": splunk or None,
            "elastic_kql": elastic or None,
            "sentinel_kql": sentinel or None,
            "sigma_yaml": rule.content,
            "rule_type": rule.rule_type,
        })

    return {
        "technique_id": tech.technique_id,
        "technique_name": tech.name,
        "rules": hunt_queries,
    }


@router.get("", response_model=list[TechniqueDetail])
async def list_ttps(
    tactic: str | None = Query(default=None, description="Filter by tactic name"),
    domain: str = Query(default="enterprise", description="enterprise | mobile | ics"),
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_session),
) -> list[TechniqueDetail]:
    q = session.query(AttckTechnique).filter(AttckTechnique.domain == domain)
    if tactic:
        q = q.filter(AttckTechnique.tactics.contains(tactic))
    techs = q.order_by(AttckTechnique.technique_id).offset(offset).limit(limit).all()
    return [
        TechniqueDetail(
            technique_id=t.technique_id,
            name=t.name,
            description=t.description,
            tactics=t.tactics or [],
            is_subtechnique=t.is_subtechnique,
            parent_id=t.parent_id,
            domain=t.domain,
            platforms=t.platforms or [],
            data_sources=t.data_sources or [],
            detection_note=t.detection_note,
            source_url=t.source_url,
        )
        for t in techs
    ]
