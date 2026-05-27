"""Threat actor profile endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from pythia.core.db import get_session
from pythia.core.security import require_api_key
from pythia.exporters.stix import export_actor as stix_export_actor
from pythia.ingestion.enrichment import infer_ttps_from_description, rescore_actor
from pythia.models.actor import ActorTTPMapping, ThreatActor
from pythia.models.attck import AttckTechnique

router = APIRouter()


# ── Pydantic response schemas ────────────────────────────────────────────────

class TTPSummary(BaseModel):
    technique_id: str
    name: str | None = None
    tactics: list[str] = Field(default_factory=list)
    use_note: str | None = None


class ActorSummary(BaseModel):
    id: str
    name: str
    aliases: list[str] = Field(default_factory=list)
    country_code: str | None = None
    sponsor_type: str
    motivations: list[str] = Field(default_factory=list)
    sectors_targeted: list[str] = Field(default_factory=list)
    sophistication: int | None = None
    ttp_count: int = 0
    attck_group_id: str | None = None
    tlp: str
    source: str


class ActorDetail(ActorSummary):
    description: str | None = None
    first_observed: str | None = None
    geographies_targeted: list[str] = Field(default_factory=list)
    infrastructure_patterns: str | None = None
    references: list[str] = Field(default_factory=list)
    ttps: list[TTPSummary] = Field(default_factory=list)


class KillChainView(BaseModel):
    actor_id: str
    actor_name: str
    phases: dict[str, list[TTPSummary]]


KILL_CHAIN_PHASES = [
    "reconnaissance",
    "weaponization",
    "delivery",
    "exploitation",
    "installation",
    "command-and-control",
    "actions-on-objectives",
]

ATTCK_TACTIC_TO_KILLCHAIN: dict[str, str] = {
    "reconnaissance": "reconnaissance",
    "resource-development": "weaponization",
    "initial-access": "delivery",
    "execution": "exploitation",
    "persistence": "installation",
    "privilege-escalation": "installation",
    "defense-evasion": "installation",
    "credential-access": "exploitation",
    "discovery": "exploitation",
    "lateral-movement": "actions-on-objectives",
    "collection": "actions-on-objectives",
    "command-and-control": "command-and-control",
    "exfiltration": "actions-on-objectives",
    "impact": "actions-on-objectives",
}


def _resolve_actor(actor_id: str, session: Session) -> ThreatActor | None:
    """Look up an actor by UUID, exact name, slug (hyphens→spaces), or substring."""
    # 1. UUID primary key
    actor = session.get(ThreatActor, actor_id)
    if actor:
        return actor
    # 2. Exact name (case-insensitive)
    actor = session.query(ThreatActor).filter(ThreatActor.name.ilike(actor_id)).first()
    if actor:
        return actor
    # 3. Slug → name  (lazarus-group → "Lazarus Group")
    slug_as_name = actor_id.replace("-", " ")
    actor = session.query(ThreatActor).filter(ThreatActor.name.ilike(slug_as_name)).first()
    if actor:
        return actor
    # 4. Substring match (apt28 → "APT28", lazarus → "Lazarus Group")
    actor = session.query(ThreatActor).filter(ThreatActor.name.ilike(f"%{actor_id}%")).first()
    return actor


def _actor_to_summary(actor: ThreatActor, ttp_count: int = 0) -> ActorSummary:
    return ActorSummary(
        id=actor.id,
        name=actor.name,
        aliases=actor.aliases or [],
        country_code=actor.country_code,
        sponsor_type=actor.sponsor_type,
        motivations=actor.motivations or [],
        sectors_targeted=actor.sectors_targeted or [],
        sophistication=actor.sophistication,
        ttp_count=ttp_count,
        attck_group_id=actor.attck_group_id,
        tlp=actor.tlp,
        source=actor.source,
    )


def _ttp_summary(mapping: object, session: Session) -> TTPSummary:
    tech = session.get(AttckTechnique, mapping.technique_id)  # type: ignore[attr-defined]
    return TTPSummary(
        technique_id=mapping.technique_id,  # type: ignore[attr-defined]
        name=tech.name if tech else None,
        tactics=tech.tactics if tech else [],
        use_note=mapping.use_note,  # type: ignore[attr-defined]
    )


# ── Routes ───────────────────────────────────────────────────────────────────

@router.get("", response_model=list[ActorSummary])
async def list_actors(
    name: str | None = Query(default=None, description="Filter by name substring"),
    country: str | None = Query(default=None, description="Filter by 2-letter country code"),
    sponsor_type: str | None = Query(default=None, description="nation-state | financially-motivated | hacktivist | script-kiddie | unknown"),
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_session),
) -> list[ActorSummary]:
    q = session.query(ThreatActor)
    if name:
        q = q.filter(ThreatActor.name.ilike(f"%{name}%"))
    if country:
        q = q.filter(ThreatActor.country_code == country.upper())
    if sponsor_type:
        q = q.filter(ThreatActor.sponsor_type == sponsor_type)
    actors = q.order_by(ThreatActor.name).offset(offset).limit(limit).all()

    # Fetch TTP counts for the returned page in a single query
    actor_ids = [a.id for a in actors]
    count_rows = (
        session.query(ActorTTPMapping.actor_id, func.count(ActorTTPMapping.id))
        .filter(ActorTTPMapping.actor_id.in_(actor_ids))
        .group_by(ActorTTPMapping.actor_id)
        .all()
    )
    counts: dict[str, int] = {r[0]: r[1] for r in count_rows}

    return [_actor_to_summary(a, ttp_count=counts.get(a.id, 0)) for a in actors]


@router.get("/{actor_id}", response_model=ActorDetail)
async def get_actor(
    actor_id: str,
    session: Session = Depends(get_session),
) -> ActorDetail:
    actor = _resolve_actor(actor_id, session)
    if not actor:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Actor '{actor_id}' not found")

    ttps = [_ttp_summary(m, session) for m in actor.ttp_mappings]
    return ActorDetail(
        **_actor_to_summary(actor).model_dump(),
        description=actor.description,
        first_observed=actor.first_observed,
        geographies_targeted=actor.geographies_targeted or [],
        infrastructure_patterns=actor.infrastructure_patterns,
        references=actor.references or [],
        ttps=ttps,
    )


@router.get("/{actor_id}/killchain", response_model=KillChainView)
async def get_actor_killchain(
    actor_id: str,
    session: Session = Depends(get_session),
) -> KillChainView:
    actor = _resolve_actor(actor_id, session)
    if not actor:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Actor '{actor_id}' not found")

    phases: dict[str, list[TTPSummary]] = {p: [] for p in KILL_CHAIN_PHASES}
    for mapping in actor.ttp_mappings:
        tech = session.get(AttckTechnique, mapping.technique_id)
        if not tech:
            continue
        summary = TTPSummary(
            technique_id=tech.technique_id,
            name=tech.name,
            tactics=tech.tactics,
            use_note=mapping.use_note,
        )
        placed = False
        for tactic in tech.tactics:
            kc = ATTCK_TACTIC_TO_KILLCHAIN.get(tactic)
            if kc and summary not in phases[kc]:
                phases[kc].append(summary)
                placed = True
        if not placed:
            phases["actions-on-objectives"].append(summary)

    return KillChainView(actor_id=actor.id, actor_name=actor.name, phases=phases)


@router.get("/{actor_id}/diamond")
async def get_actor_diamond(
    actor_id: str,
    session: Session = Depends(get_session),
) -> dict[str, object]:
    actor = _resolve_actor(actor_id, session)
    if not actor:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Actor '{actor_id}' not found")

    tool_techs = [
        m.technique_id for m in actor.ttp_mappings
        if (session.get(AttckTechnique, m.technique_id) and
        "T1588" in m.technique_id) or "T1583" in m.technique_id  # Tool/Resource acquisition
    ]

    return {
        "adversary": {
            "name": actor.name,
            "aliases": actor.aliases,
            "country": actor.country_code,
            "sponsor_type": actor.sponsor_type,
        },
        "capability": {
            "technique_count": len(actor.ttp_mappings),
            "sample_techniques": [m.technique_id for m in actor.ttp_mappings[:5]],
        },
        "infrastructure": {
            "patterns": actor.infrastructure_patterns,
            "known_tool_techniques": tool_techs,
        },
        "victim": {
            "sectors": actor.sectors_targeted,
            "geographies": actor.geographies_targeted,
        },
    }


@router.get("/{actor_id}/stix", include_in_schema=True)
async def get_actor_stix(
    actor_id: str,
    session: Session = Depends(get_session),
) -> JSONResponse:
    """Export actor as a STIX 2.1 bundle (threat-actor + attack-patterns + relationships)."""
    actor = _resolve_actor(actor_id, session)
    if not actor:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Actor '{actor_id}' not found")
    bundle = stix_export_actor(actor)
    return JSONResponse(content=bundle, media_type="application/stix+json")


@router.get("/{actor_id}/diff")
async def get_actor_diff(
    actor_id: str,
    session: Session = Depends(get_session),
) -> dict[str, object]:
    actor = _resolve_actor(actor_id, session)
    if not actor:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Actor '{actor_id}' not found")
    return {
        "actor_id": actor.id,
        "note": "TTP diff tracking requires timestamped ingestion — coming in a future sync.",
        "current_ttp_count": len(actor.ttp_mappings),
    }


class EnrichResult(BaseModel):
    actor_id: str
    actor_name: str
    sophistication_before: int | None
    sophistication_after: int | None
    ttps_added: int
    ttps_source: str | None


@router.post("/{actor_id}/enrich", response_model=EnrichResult, dependencies=[Depends(require_api_key)])
async def enrich_actor(
    actor_id: str,
    session: Session = Depends(get_session),
) -> EnrichResult:
    """Recompute sophistication score and optionally infer TTPs for a single actor.

    Sophistication is always recalculated from current TTP data.  When the actor
    has a description but zero TTP mappings and ANTHROPIC_API_KEY is configured,
    Claude is used to infer a set of likely ATT&CK technique IDs.
    """
    actor = _resolve_actor(actor_id, session)
    if not actor:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Actor '{actor_id}' not found")

    soph_before = actor.sophistication

    # Infer TTPs via Claude when the actor has a description but no mappings
    ttps_added = 0
    ttps_source: str | None = None
    if not actor.ttp_mappings and actor.description:
        tech_ids = infer_ttps_from_description(actor, session)
        existing = {m.technique_id for m in actor.ttp_mappings}
        for tid in tech_ids:
            if tid not in existing:
                session.add(ActorTTPMapping(
                    actor_id=actor.id,
                    technique_id=tid,
                    use_note="inferred by Claude from actor description",
                    source="claude-inference",
                ))
                existing.add(tid)
                ttps_added += 1
        if ttps_added:
            session.flush()
            ttps_source = "claude-inference"

    soph_after = rescore_actor(actor, session)
    session.commit()

    return EnrichResult(
        actor_id=actor.id,
        actor_name=actor.name,
        sophistication_before=soph_before,
        sophistication_after=soph_after,
        ttps_added=ttps_added,
        ttps_source=ttps_source,
    )
