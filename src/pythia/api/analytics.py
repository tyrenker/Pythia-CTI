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
from pythia.models.ioc import IoC
from pythia.models.rule import DetectionRule

# Country/region names that appear in sectors_targeted due to mixed source data.
# Used to separate genuine sectors from geographic targets.
_GEOGRAPHY_TERMS: frozenset[str] = frozenset(
    {
        "Afghanistan",
        "Albania",
        "Algeria",
        "Angola",
        "Argentina",
        "Armenia",
        "Australia",
        "Austria",
        "Azerbaijan",
        "Bahrain",
        "Bangladesh",
        "Belarus",
        "Belgium",
        "Bolivia",
        "Bosnia",
        "Brazil",
        "Bulgaria",
        "Cambodia",
        "Canada",
        "Chile",
        "China",
        "Colombia",
        "Congo",
        "Croatia",
        "Cuba",
        "Cyprus",
        "Czech Republic",
        "Denmark",
        "Ecuador",
        "Egypt",
        "Estonia",
        "Ethiopia",
        "Finland",
        "France",
        "Georgia",
        "Germany",
        "Ghana",
        "Greece",
        "Hong Kong",
        "Hungary",
        "India",
        "Indonesia",
        "Iran",
        "Iraq",
        "Ireland",
        "Israel",
        "Italy",
        "Japan",
        "Jordan",
        "Kazakhstan",
        "Kenya",
        "Kuwait",
        "Kyrgyzstan",
        "Latvia",
        "Lebanon",
        "Libya",
        "Lithuania",
        "Luxembourg",
        "Malaysia",
        "Maldives",
        "Mexico",
        "Middle East",
        "Moldova",
        "Mongolia",
        "Morocco",
        "Myanmar",
        "Nepal",
        "Netherlands",
        "New Zealand",
        "Nigeria",
        "North Korea",
        "Norway",
        "Oman",
        "Pakistan",
        "Palestine",
        "Philippines",
        "Poland",
        "Portugal",
        "Qatar",
        "Romania",
        "Russia",
        "Rwanda",
        "Saudi Arabia",
        "Serbia",
        "Singapore",
        "Slovakia",
        "Slovenia",
        "Somalia",
        "South Africa",
        "South Korea",
        "South Sudan",
        "Spain",
        "Sri Lanka",
        "Sudan",
        "Sweden",
        "Switzerland",
        "Syria",
        "Taiwan",
        "Tajikistan",
        "Thailand",
        "Tunisia",
        "Turkey",
        "Turkmenistan",
        "UAE",
        "Uganda",
        "UK",
        "Ukraine",
        "US",
        "USA",
        "Uzbekistan",
        "Venezuela",
        "Vietnam",
        "Yemen",
        "Zimbabwe",
        # Regions / supranational
        "Central Asia",
        "East Asia",
        "Eastern Europe",
        "Europe",
        "Latin America",
        "North Africa",
        "North America",
        "South Asia",
        "Southeast Asia",
        "Sub-Saharan Africa",
        "West Africa",
        "Western Europe",
    }
)

# ISO 3166-1 alpha-2 → full country name, for normalising geographies_targeted data.
_ISO2_TO_NAME: dict[str, str] = {
    "AF": "Afghanistan",
    "AL": "Albania",
    "DZ": "Algeria",
    "AO": "Angola",
    "AR": "Argentina",
    "AM": "Armenia",
    "AU": "Australia",
    "AT": "Austria",
    "AZ": "Azerbaijan",
    "BH": "Bahrain",
    "BD": "Bangladesh",
    "BY": "Belarus",
    "BE": "Belgium",
    "BO": "Bolivia",
    "BA": "Bosnia",
    "BR": "Brazil",
    "BG": "Bulgaria",
    "KH": "Cambodia",
    "CA": "Canada",
    "CL": "Chile",
    "CN": "China",
    "CO": "Colombia",
    "CD": "Congo",
    "HR": "Croatia",
    "CU": "Cuba",
    "CY": "Cyprus",
    "CZ": "Czech Republic",
    "DK": "Denmark",
    "EC": "Ecuador",
    "EG": "Egypt",
    "EE": "Estonia",
    "ET": "Ethiopia",
    "FI": "Finland",
    "FR": "France",
    "GE": "Georgia",
    "DE": "Germany",
    "GH": "Ghana",
    "GR": "Greece",
    "HK": "Hong Kong",
    "HU": "Hungary",
    "IN": "India",
    "ID": "Indonesia",
    "IR": "Iran",
    "IQ": "Iraq",
    "IE": "Ireland",
    "IL": "Israel",
    "IT": "Italy",
    "JP": "Japan",
    "JO": "Jordan",
    "KZ": "Kazakhstan",
    "KE": "Kenya",
    "KW": "Kuwait",
    "KG": "Kyrgyzstan",
    "LV": "Latvia",
    "LB": "Lebanon",
    "LY": "Libya",
    "LT": "Lithuania",
    "LU": "Luxembourg",
    "MY": "Malaysia",
    "MV": "Maldives",
    "MX": "Mexico",
    "MD": "Moldova",
    "MN": "Mongolia",
    "MA": "Morocco",
    "MM": "Myanmar",
    "NP": "Nepal",
    "NL": "Netherlands",
    "NZ": "New Zealand",
    "NG": "Nigeria",
    "KP": "North Korea",
    "NO": "Norway",
    "OM": "Oman",
    "PK": "Pakistan",
    "PS": "Palestine",
    "PH": "Philippines",
    "PL": "Poland",
    "PT": "Portugal",
    "QA": "Qatar",
    "RO": "Romania",
    "RU": "Russia",
    "RW": "Rwanda",
    "SA": "Saudi Arabia",
    "RS": "Serbia",
    "SG": "Singapore",
    "SK": "Slovakia",
    "SI": "Slovenia",
    "SO": "Somalia",
    "ZA": "South Africa",
    "KR": "South Korea",
    "SS": "South Sudan",
    "ES": "Spain",
    "LK": "Sri Lanka",
    "SD": "Sudan",
    "SE": "Sweden",
    "CH": "Switzerland",
    "SY": "Syria",
    "TW": "Taiwan",
    "TJ": "Tajikistan",
    "TH": "Thailand",
    "TN": "Tunisia",
    "TR": "Turkey",
    "TM": "Turkmenistan",
    "AE": "UAE",
    "UG": "Uganda",
    "GB": "UK",
    "UA": "Ukraine",
    "US": "US",
    "UZ": "Uzbekistan",
    "VE": "Venezuela",
    "VN": "Vietnam",
    "YE": "Yemen",
    "ZW": "Zimbabwe",
}


def _norm_geo(value: str) -> str:
    """Normalise a geography value: expand ISO-2 codes to full names."""
    return _ISO2_TO_NAME.get(value.upper(), value)


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
        for tid in rule.technique_ids or []:
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

    # Build sector → actors mapping (skip geographic terms mixed into this field)
    sector_actors: dict[str, list[ThreatActor]] = {}
    for actor in actors:
        for sector in actor.sectors_targeted or []:
            sector = sector.strip()
            if sector and sector not in _GEOGRAPHY_TERMS:
                sector_actors.setdefault(sector, []).append(actor)

    rows: list[SectorRow] = []
    for sector, actor_list in sorted(sector_actors.items(), key=lambda x: -len(x[1])):
        rows.append(
            SectorRow(
                sector=sector,
                actor_count=len(actor_list),
                nation_state_count=sum(1 for a in actor_list if a.sponsor_type == "nation-state"),
                financially_motivated_count=sum(
                    1 for a in actor_list if a.sponsor_type == "financially-motivated"
                ),
                hacktivist_count=sum(1 for a in actor_list if a.sponsor_type == "hacktivist"),
                top_actors=[
                    a.name for a in sorted(actor_list, key=lambda a: -(a.sophistication or 0))[:5]
                ],
            )
        )

    actors_with_data = len({a.id for a_list in sector_actors.values() for a in a_list})

    return SectorReport(
        total_sectors=len(rows),
        total_actors_with_sector_data=actors_with_data,
        rows=rows[:limit],
    )


# ── Dashboard summary ──────────────────────────────────────────────────────────


class DashboardSummary(BaseModel):
    actor_by_sponsor: dict[str, int]
    ioc_by_type: dict[str, int]
    ttp_by_tactic: dict[str, int]
    technique_count: int


@router.get("/summary", response_model=DashboardSummary)
def get_dashboard_summary(session: Session = Depends(get_session)) -> DashboardSummary:
    """Lightweight breakdown counts for the home dashboard."""
    actor_by_sponsor: Counter[str] = Counter()
    for (sponsor,) in session.query(ThreatActor.sponsor_type).all():
        actor_by_sponsor[sponsor or "unknown"] += 1

    ioc_by_type: Counter[str] = Counter()
    for (ioc_type,) in session.query(IoC.type).all():
        ioc_by_type[ioc_type] += 1

    observed_ids = {tid for (tid,) in session.query(ActorTTPMapping.technique_id).distinct().all()}
    ttp_by_tactic: Counter[str] = Counter()
    if observed_ids:
        techs = (
            session.query(AttckTechnique.tactics)
            .filter(AttckTechnique.technique_id.in_(observed_ids))
            .all()
        )
        for (tactics,) in techs:
            for tactic in tactics or []:
                ttp_by_tactic[tactic] += 1

    technique_count = session.query(AttckTechnique).count()

    return DashboardSummary(
        actor_by_sponsor=dict(actor_by_sponsor),
        ioc_by_type=dict(ioc_by_type),
        ttp_by_tactic=dict(ttp_by_tactic),
        technique_count=technique_count,
    )


# ── Geography targeting ───────────────────────────────────────────────────────


@router.get("/geographies", response_model=SectorReport)
def geography_targeting(
    sponsor_type: str | None = Query(default=None),
    country: str | None = Query(default=None),
    limit: int = Query(default=30, le=100),
    session: Session = Depends(get_session),
) -> SectorReport:
    """Heatmap of geographic regions/countries actors target.

    Pulls from both geographies_targeted and any country-like values in
    sectors_targeted, so mixed-format source data is handled correctly.
    """
    q = session.query(ThreatActor)
    if sponsor_type:
        q = q.filter(ThreatActor.sponsor_type == sponsor_type)
    if country:
        q = q.filter(ThreatActor.country_code == country.upper())
    actors = q.all()

    geo_actors: dict[str, list[ThreatActor]] = {}
    for actor in actors:
        seen: set[str] = set()
        # Explicit geographies_targeted first (normalise ISO-2 codes to full names)
        for geo in actor.geographies_targeted or []:
            geo = _norm_geo(geo.strip())
            if geo and geo not in seen:
                seen.add(geo)
                geo_actors.setdefault(geo, []).append(actor)
        # Also pick up country-like terms that ended up in sectors_targeted
        for term in actor.sectors_targeted or []:
            term = _norm_geo(term.strip())
            if term and term in _GEOGRAPHY_TERMS and term not in seen:
                seen.add(term)
                geo_actors.setdefault(term, []).append(actor)

    rows: list[SectorRow] = []
    for geo, actor_list in sorted(geo_actors.items(), key=lambda x: -len(x[1])):
        rows.append(
            SectorRow(
                sector=geo,
                actor_count=len(actor_list),
                nation_state_count=sum(1 for a in actor_list if a.sponsor_type == "nation-state"),
                financially_motivated_count=sum(
                    1 for a in actor_list if a.sponsor_type == "financially-motivated"
                ),
                hacktivist_count=sum(1 for a in actor_list if a.sponsor_type == "hacktivist"),
                top_actors=[
                    a.name for a in sorted(actor_list, key=lambda a: -(a.sophistication or 0))[:5]
                ],
            )
        )

    actors_with_data = len({a.id for a_list in geo_actors.values() for a in a_list})

    return SectorReport(
        total_sectors=len(rows),
        total_actors_with_sector_data=actors_with_data,
        rows=rows[:limit],
    )
