"""Analytics endpoints — detection coverage gap and sector targeting heatmap.

GET /v1/analytics/coverage  — observed TTPs vs Sigma/Yara coverage ratio
GET /v1/analytics/sectors   — actor-to-sector targeting heatmap
"""

from __future__ import annotations

from collections import Counter

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from pythia.core.db import get_session
from pythia.models.actor import ActorTTPMapping, ThreatActor
from pythia.models.attck import AttckTechnique
from pythia.models.rule import DetectionRule

router = APIRouter()


# ── Coverage gap ─────────────────────────────────────────────────────────────

class TechniqueGap(BaseModel):
    technique_id: str
    name: str | None = None
    tactics: list[str] = Field(default_factory=list)
    actor_count: int = 0


class CoverageReport(BaseModel):
    observed_technique_count: int
    covered_technique_count: int
    coverage_pct: float
    uncovered_count: int
    rule_count: int
    summary: str
    top_uncovered: list[TechniqueGap] = Field(default_factory=list)
    top_covered: list[TechniqueGap] = Field(default_factory=list)


@router.get("/coverage", response_model=CoverageReport)
async def coverage_gap(
    limit: int = Query(default=20, le=100, description="Max techniques to return in each list"),
    session: Session = Depends(get_session),
) -> CoverageReport:
    """Cross-reference observed TTPs (from actor mappings) against detection rules.

    Returns coverage ratio plus ranked lists of covered and uncovered techniques.
    """
    # All observed technique IDs and how many actors use each
    actor_counts: Counter[str] = Counter()
    for mapping in session.query(ActorTTPMapping).all():
        actor_counts[mapping.technique_id] += 1
    observed = set(actor_counts.keys())

    # All technique IDs with at least one detection rule
    covered: set[str] = set()
    rule_count = 0
    for rule in session.query(DetectionRule).all():
        rule_count += 1
        for tid in (rule.technique_ids or []):
            covered.add(tid.upper())

    # Normalise observed IDs to uppercase to match covered set
    observed_upper = {t.upper(): t for t in observed}
    covered_observed = {t for t in observed_upper if t in covered}
    uncovered = {t for t in observed_upper if t not in covered}

    def _enrich(tid_upper: str) -> TechniqueGap:
        original = observed_upper.get(tid_upper, tid_upper)
        tech = session.get(AttckTechnique, tid_upper) or session.get(AttckTechnique, original)
        return TechniqueGap(
            technique_id=tid_upper,
            name=tech.name if tech else None,
            tactics=tech.tactics if tech else [],
            actor_count=actor_counts.get(original, actor_counts.get(tid_upper, 0)),
        )

    # Sort uncovered by actor_count descending (most-used = biggest gap)
    top_uncovered = sorted(
        [_enrich(t) for t in uncovered],
        key=lambda x: -x.actor_count,
    )[:limit]

    top_covered = sorted(
        [_enrich(t) for t in covered_observed],
        key=lambda x: -x.actor_count,
    )[:limit]

    pct = round(len(covered_observed) / max(len(observed), 1) * 100, 1)

    return CoverageReport(
        observed_technique_count=len(observed),
        covered_technique_count=len(covered_observed),
        coverage_pct=pct,
        uncovered_count=len(uncovered),
        rule_count=rule_count,
        summary=(
            f"Detection coverage: {len(covered_observed)}/{len(observed)} observed ATT&CK techniques "
            f"({pct}%) have at least one Sigma/Yara rule. "
            f"{len(uncovered)} techniques used by known actors have no detection rule."
        ),
        top_uncovered=top_uncovered,
        top_covered=top_covered,
    )


# ── Sector targeting heatmap ──────────────────────────────────────────────────

class SectorRow(BaseModel):
    sector: str
    actor_count: int
    nation_state_count: int = 0
    financially_motivated_count: int = 0
    hacktivist_count: int = 0
    top_actors: list[str] = Field(default_factory=list)


class SectorReport(BaseModel):
    total_sectors: int
    total_actors_with_sector_data: int
    rows: list[SectorRow]


@router.get("/sectors", response_model=SectorReport)
async def sector_targeting(
    sponsor_type: str | None = Query(default=None, description="Filter actors by sponsor type"),
    country: str | None = Query(default=None, description="Filter actors by 2-letter country code"),
    limit: int = Query(default=30, le=100),
    session: Session = Depends(get_session),
) -> SectorReport:
    """Heatmap of which sectors threat actors target.

    Sorted by actor count descending. Filter by sponsor_type or country to narrow scope.
    """
    q = session.query(ThreatActor).filter(ThreatActor.sectors_targeted != "[]")
    if sponsor_type:
        q = q.filter(ThreatActor.sponsor_type == sponsor_type)
    if country:
        q = q.filter(ThreatActor.country_code == country.upper())
    actors = q.all()

    # Build sector → actors mapping
    sector_actors: dict[str, list[ThreatActor]] = {}
    for actor in actors:
        for sector in (actor.sectors_targeted or []):
            sector = sector.strip()
            if sector:
                sector_actors.setdefault(sector, []).append(actor)

    rows: list[SectorRow] = []
    for sector, actor_list in sorted(sector_actors.items(), key=lambda x: -len(x[1])):
        rows.append(SectorRow(
            sector=sector,
            actor_count=len(actor_list),
            nation_state_count=sum(1 for a in actor_list if a.sponsor_type == "nation-state"),
            financially_motivated_count=sum(1 for a in actor_list if a.sponsor_type == "financially-motivated"),
            hacktivist_count=sum(1 for a in actor_list if a.sponsor_type == "hacktivist"),
            top_actors=[a.name for a in sorted(actor_list, key=lambda a: -(a.sophistication or 0))[:5]],
        ))

    actors_with_data = len({a.id for a_list in sector_actors.values() for a in a_list})

    return SectorReport(
        total_sectors=len(rows),
        total_actors_with_sector_data=actors_with_data,
        rows=rows[:limit],
    )
