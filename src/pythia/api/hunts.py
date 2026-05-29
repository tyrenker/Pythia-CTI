"""Threat hunt workbench endpoints."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import anthropic
from anthropic.types import TextBlock
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import or_
from sqlalchemy.orm import Session

from pythia.core.config import get_settings
from pythia.core.db import get_session
from pythia.core.security import require_api_key
from pythia.models.actor import ThreatActor
from pythia.models.attck import AttckTechnique
from pythia.models.hunt import (
    OBS_TYPE_TO_PYRAMID,
    HuntDraftDetection,
    HuntNote,
    HuntObservation,
    HuntSession,
)
from pythia.models.ioc import IoC
from pythia.models.rule import DetectionRule

router = APIRouter()

_PROMPTS = Path(__file__).resolve().parent.parent / "ingestion" / "prompts"


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class CreateSessionRequest(BaseModel):
    name: str
    hypothesis: str | None = None
    analyst: str | None = None
    sector_focus: list[str] = Field(default_factory=list)
    motivation_focus: list[str] = Field(default_factory=list)


class UpdateSessionRequest(BaseModel):
    name: str | None = None
    hypothesis: str | None = None
    status: str | None = None
    analyst: str | None = None
    sector_focus: list[str] | None = None
    motivation_focus: list[str] | None = None


class ObservationOut(BaseModel):
    id: str
    session_id: str
    obs_type: str
    value: str
    pyramid_tier: str | None
    confidence_source: str
    confidence_info: str
    linked_record_id: str | None
    notes: str | None
    created_at: datetime


class SessionSummary(BaseModel):
    id: str
    name: str
    hypothesis: str | None
    status: str
    analyst: str | None
    sector_focus: list[str]
    motivation_focus: list[str]
    observation_count: int
    detection_count: int
    created_at: datetime
    updated_at: datetime


class SessionDetail(BaseModel):
    id: str
    name: str
    hypothesis: str | None
    status: str
    analyst: str | None
    sector_focus: list[str]
    motivation_focus: list[str]
    observations: list[ObservationOut]
    created_at: datetime
    updated_at: datetime


class CreateObservationRequest(BaseModel):
    obs_type: str
    value: str
    confidence_source: str = "F"
    confidence_info: str = "6"
    notes: str | None = None


class NoteOut(BaseModel):
    session_id: str
    content: str
    updated_at: datetime


class UpdateNotesRequest(BaseModel):
    content: str


class DraftDetectionOut(BaseModel):
    id: str
    session_id: str
    title: str
    rule_type: str
    content: str
    pyramid_tier: str
    linked_ttp_ids: list[str]
    linked_obs_ids: list[str]
    rationale: str | None
    status: str
    created_at: datetime
    updated_at: datetime


class UpdateDetectionRequest(BaseModel):
    title: str | None = None
    content: str | None = None
    status: str | None = None
    rationale: str | None = None
    pyramid_tier: str | None = None


class DraftDetectionRequest(BaseModel):
    obs_ids: list[str] = Field(description="Observation IDs to use as detection basis")
    rule_type: str = Field(default="sigma", description="sigma | kql | spl | eql | yara")


# ---------------------------------------------------------------------------
# Helper: get session or 404
# ---------------------------------------------------------------------------


def _get_session_or_404(session_id: str, db: Session) -> HuntSession:
    hunt = db.get(HuntSession, session_id)
    if not hunt:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Hunt '{session_id}' not found")
    return hunt


def _obs_to_out(o: HuntObservation) -> ObservationOut:
    return ObservationOut(
        id=o.id,
        session_id=o.session_id,
        obs_type=o.obs_type,
        value=o.value,
        pyramid_tier=o.pyramid_tier,
        confidence_source=o.confidence_source,
        confidence_info=o.confidence_info,
        linked_record_id=o.linked_record_id,
        notes=o.notes,
        created_at=o.created_at,
    )


def _detection_to_out(d: HuntDraftDetection) -> DraftDetectionOut:
    return DraftDetectionOut(
        id=d.id,
        session_id=d.session_id,
        title=d.title,
        rule_type=d.rule_type,
        content=d.content,
        pyramid_tier=d.pyramid_tier,
        linked_ttp_ids=d.linked_ttp_ids or [],
        linked_obs_ids=d.linked_obs_ids or [],
        rationale=d.rationale,
        status=d.status,
        created_at=d.created_at,
        updated_at=d.updated_at,
    )


def _try_link_observation(obs: HuntObservation, db: Session) -> None:
    """Auto-link observation to existing DB record if one matches."""
    if obs.obs_type in ("ioc_ip", "ioc_domain", "ioc_hash", "ioc_url", "ioc_email", "ioc_mutex", "ioc_registry"):
        ioc_match = db.query(IoC).filter(IoC.value == obs.value).first()
        if ioc_match:
            obs.linked_record_id = ioc_match.id
    elif obs.obs_type == "ttp":
        ttp_match = db.get(AttckTechnique, obs.value.upper())
        if ttp_match:
            obs.linked_record_id = ttp_match.technique_id
    elif obs.obs_type == "actor":
        actor_match = (
            db.query(ThreatActor)
            .filter(or_(ThreatActor.name.ilike(obs.value), ThreatActor.attck_group_id == obs.value))
            .first()
        )
        if actor_match:
            obs.linked_record_id = actor_match.id


# ---------------------------------------------------------------------------
# Claude helpers
# ---------------------------------------------------------------------------


def _call_claude(prompt_file: str, user_content: str) -> dict[str, object]:
    settings = get_settings()
    if not settings.anthropic_api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ANTHROPIC_API_KEY not configured",
        )
    system_prompt = (_PROMPTS / prompt_file).read_text()
    client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
    message = client.messages.create(
        model=settings.claude_model,
        max_tokens=4096,
        system=system_prompt,
        messages=[{"role": "user", "content": user_content}],
    )
    text_block = next(b for b in message.content if isinstance(b, TextBlock))
    raw = text_block.text.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()
    return json.loads(raw)  # type: ignore[no-any-return]


def _build_actor_context(hunt: HuntSession, db: Session) -> list[dict[str, object]]:
    """Return up to 50 actor summaries relevant to the hunt's sector/motivation focus."""
    q = db.query(ThreatActor)

    # Prefer actors that overlap on sector or motivation.
    sector_filters = [
        ThreatActor.sectors_targeted.contains(s) for s in (hunt.sector_focus or [])
    ]
    motivation_filters = [
        ThreatActor.motivations.contains(m) for m in (hunt.motivation_focus or [])
    ]
    if sector_filters or motivation_filters:
        q = q.filter(or_(*sector_filters, *motivation_filters))

    actors = q.order_by(ThreatActor.sophistication.desc()).limit(50).all()

    # Fall back to top actors if nothing matched.
    if not actors:
        actors = db.query(ThreatActor).order_by(ThreatActor.sophistication.desc()).limit(50).all()

    return [
        {
            "id": a.id,
            "name": a.name,
            "aliases": a.aliases[:3] if a.aliases else [],
            "country_code": a.country_code,
            "sponsor_type": a.sponsor_type,
            "motivations": a.motivations,
            "sectors_targeted": a.sectors_targeted[:10] if a.sectors_targeted else [],
            "sophistication": a.sophistication,
        }
        for a in actors
    ]


# ---------------------------------------------------------------------------
# Session CRUD
# ---------------------------------------------------------------------------


@router.post("", response_model=SessionDetail, status_code=status.HTTP_201_CREATED)
async def create_hunt(
    body: CreateSessionRequest,
    db: Session = Depends(get_session),
    _: None = Depends(require_api_key),
) -> SessionDetail:
    hunt = HuntSession(
        name=body.name,
        hypothesis=body.hypothesis,
        analyst=body.analyst,
        sector_focus=body.sector_focus,
        motivation_focus=body.motivation_focus,
    )
    db.add(hunt)
    db.commit()
    db.refresh(hunt)
    return SessionDetail(
        id=hunt.id,
        name=hunt.name,
        hypothesis=hunt.hypothesis,
        status=hunt.status,
        analyst=hunt.analyst,
        sector_focus=hunt.sector_focus or [],
        motivation_focus=hunt.motivation_focus or [],
        observations=[],
        created_at=hunt.created_at,
        updated_at=hunt.updated_at,
    )


@router.get("", response_model=list[SessionSummary])
async def list_hunts(
    status_filter: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=20, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_session),
) -> list[SessionSummary]:
    q = db.query(HuntSession)
    if status_filter:
        q = q.filter(HuntSession.status == status_filter)
    hunts = q.order_by(HuntSession.updated_at.desc()).offset(offset).limit(limit).all()
    return [
        SessionSummary(
            id=h.id,
            name=h.name,
            hypothesis=h.hypothesis,
            status=h.status,
            analyst=h.analyst,
            sector_focus=h.sector_focus or [],
            motivation_focus=h.motivation_focus or [],
            observation_count=len(h.observations),
            detection_count=len(h.detections),
            created_at=h.created_at,
            updated_at=h.updated_at,
        )
        for h in hunts
    ]


@router.get("/{session_id}", response_model=SessionDetail)
async def get_hunt(
    session_id: str,
    db: Session = Depends(get_session),
) -> SessionDetail:
    hunt = _get_session_or_404(session_id, db)
    return SessionDetail(
        id=hunt.id,
        name=hunt.name,
        hypothesis=hunt.hypothesis,
        status=hunt.status,
        analyst=hunt.analyst,
        sector_focus=hunt.sector_focus or [],
        motivation_focus=hunt.motivation_focus or [],
        observations=[_obs_to_out(o) for o in hunt.observations],
        created_at=hunt.created_at,
        updated_at=hunt.updated_at,
    )


@router.put("/{session_id}", response_model=SessionDetail)
async def update_hunt(
    session_id: str,
    body: UpdateSessionRequest,
    db: Session = Depends(get_session),
    _: None = Depends(require_api_key),
) -> SessionDetail:
    hunt = _get_session_or_404(session_id, db)
    if body.name is not None:
        hunt.name = body.name
    if body.hypothesis is not None:
        hunt.hypothesis = body.hypothesis
    if body.status is not None:
        hunt.status = body.status
    if body.analyst is not None:
        hunt.analyst = body.analyst
    if body.sector_focus is not None:
        hunt.sector_focus = body.sector_focus
    if body.motivation_focus is not None:
        hunt.motivation_focus = body.motivation_focus
    hunt.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(hunt)
    return SessionDetail(
        id=hunt.id,
        name=hunt.name,
        hypothesis=hunt.hypothesis,
        status=hunt.status,
        analyst=hunt.analyst,
        sector_focus=hunt.sector_focus or [],
        motivation_focus=hunt.motivation_focus or [],
        observations=[_obs_to_out(o) for o in hunt.observations],
        created_at=hunt.created_at,
        updated_at=hunt.updated_at,
    )


@router.delete("/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_hunt(
    session_id: str,
    db: Session = Depends(get_session),
    _: None = Depends(require_api_key),
) -> None:
    hunt = _get_session_or_404(session_id, db)
    db.delete(hunt)
    db.commit()


# ---------------------------------------------------------------------------
# Observations
# ---------------------------------------------------------------------------


@router.post("/{session_id}/observations", response_model=ObservationOut, status_code=status.HTTP_201_CREATED)
async def add_observation(
    session_id: str,
    body: CreateObservationRequest,
    db: Session = Depends(get_session),
    _: None = Depends(require_api_key),
) -> ObservationOut:
    _get_session_or_404(session_id, db)
    if body.obs_type not in OBS_TYPE_TO_PYRAMID:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown obs_type '{body.obs_type}'. Valid: {list(OBS_TYPE_TO_PYRAMID)}",
        )
    obs = HuntObservation(
        session_id=session_id,
        obs_type=body.obs_type,
        value=body.value,
        pyramid_tier=OBS_TYPE_TO_PYRAMID[body.obs_type],
        confidence_source=body.confidence_source,
        confidence_info=body.confidence_info,
        notes=body.notes,
    )
    _try_link_observation(obs, db)
    db.add(obs)
    # Touch session updated_at
    hunt = db.get(HuntSession, session_id)
    if hunt:
        hunt.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(obs)
    return _obs_to_out(obs)


@router.delete("/{session_id}/observations/{obs_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_observation(
    session_id: str,
    obs_id: str,
    db: Session = Depends(get_session),
    _: None = Depends(require_api_key),
) -> None:
    obs = db.query(HuntObservation).filter(
        HuntObservation.id == obs_id, HuntObservation.session_id == session_id
    ).first()
    if not obs:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Observation not found")
    db.delete(obs)
    db.commit()


# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------


@router.get("/{session_id}/notes", response_model=NoteOut)
async def get_notes(
    session_id: str,
    db: Session = Depends(get_session),
) -> NoteOut:
    hunt = _get_session_or_404(session_id, db)
    note = hunt.note
    if not note:
        return NoteOut(session_id=session_id, content="", updated_at=hunt.created_at)
    return NoteOut(session_id=session_id, content=note.content, updated_at=note.updated_at)


@router.put("/{session_id}/notes", response_model=NoteOut)
async def upsert_notes(
    session_id: str,
    body: UpdateNotesRequest,
    db: Session = Depends(get_session),
    _: None = Depends(require_api_key),
) -> NoteOut:
    hunt = _get_session_or_404(session_id, db)
    note = hunt.note
    if note:
        note.content = body.content
        note.updated_at = datetime.utcnow()
    else:
        note = HuntNote(session_id=session_id, content=body.content)
        db.add(note)
    hunt.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(note)
    return NoteOut(session_id=session_id, content=note.content, updated_at=note.updated_at)


# ---------------------------------------------------------------------------
# Claude: actor suggestions
# ---------------------------------------------------------------------------


@router.post("/{session_id}/suggest-actors")
async def suggest_actors(
    session_id: str,
    db: Session = Depends(get_session),
    _: None = Depends(require_api_key),
) -> dict[str, object]:
    hunt = _get_session_or_404(session_id, db)
    actor_context = _build_actor_context(hunt, db)
    note_content = hunt.note.content if hunt.note else ""

    user_content = json.dumps(
        {
            "hunt": {
                "name": hunt.name,
                "hypothesis": hunt.hypothesis,
                "sector_focus": hunt.sector_focus or [],
                "motivation_focus": hunt.motivation_focus or [],
            },
            "observations": [
                {
                    "obs_type": o.obs_type,
                    "value": o.value,
                    "pyramid_tier": o.pyramid_tier,
                    "notes": o.notes,
                }
                for o in hunt.observations
            ],
            "analyst_notes_excerpt": note_content[:2000] if note_content else "",
            "known_actors": actor_context,
        },
        indent=2,
    )
    return _call_claude("hunt_suggest_actors.md", user_content)


# ---------------------------------------------------------------------------
# Claude: hypothesis refinement
# ---------------------------------------------------------------------------


@router.post("/{session_id}/refine-hypothesis")
async def refine_hypothesis(
    session_id: str,
    db: Session = Depends(get_session),
    _: None = Depends(require_api_key),
) -> dict[str, object]:
    hunt = _get_session_or_404(session_id, db)
    note_content = hunt.note.content if hunt.note else ""

    user_content = json.dumps(
        {
            "hypothesis": hunt.hypothesis or "(no hypothesis set)",
            "observations": [
                {
                    "obs_type": o.obs_type,
                    "value": o.value,
                    "pyramid_tier": o.pyramid_tier,
                    "confidence": f"{o.confidence_source}{o.confidence_info}",
                    "notes": o.notes,
                }
                for o in hunt.observations
            ],
            "analyst_notes": note_content[:3000] if note_content else "",
            "sector_focus": hunt.sector_focus or [],
            "motivation_focus": hunt.motivation_focus or [],
        },
        indent=2,
    )
    return _call_claude("hunt_refine_hypothesis.md", user_content)


# ---------------------------------------------------------------------------
# Claude: draft detection
# ---------------------------------------------------------------------------


@router.post("/{session_id}/draft-detection", response_model=DraftDetectionOut, status_code=status.HTTP_201_CREATED)
async def draft_detection(
    session_id: str,
    body: DraftDetectionRequest,
    db: Session = Depends(get_session),
    _: None = Depends(require_api_key),
) -> DraftDetectionOut:
    hunt = _get_session_or_404(session_id, db)

    target_obs = [
        o for o in hunt.observations if o.id in body.obs_ids
    ]
    if not target_obs:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="No matching observations found for provided obs_ids",
        )

    user_content = json.dumps(
        {
            "target_observations": [
                {
                    "obs_type": o.obs_type,
                    "value": o.value,
                    "pyramid_tier": o.pyramid_tier,
                    "notes": o.notes,
                }
                for o in target_obs
            ],
            "all_observations": [
                {"obs_type": o.obs_type, "value": o.value}
                for o in hunt.observations
            ],
            "rule_type": body.rule_type,
            "hunt_context": {
                "hypothesis": hunt.hypothesis,
                "sector_focus": hunt.sector_focus or [],
                "motivation_focus": hunt.motivation_focus or [],
            },
        },
        indent=2,
    )
    result = _call_claude("hunt_draft_detection.md", user_content)

    detection = HuntDraftDetection(
        session_id=session_id,
        title=str(result.get("title", "Untitled Detection")),
        rule_type=str(result.get("rule_type", body.rule_type)),
        content=str(result.get("content", "")),
        pyramid_tier=str(result.get("pyramid_tier", "ttp")),
        linked_ttp_ids=result.get("linked_ttp_ids", []),
        linked_obs_ids=body.obs_ids,
        rationale=str(result.get("pyramid_rationale", "")) if result.get("pyramid_rationale") else None,
        status="draft",
    )
    db.add(detection)
    hunt.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(detection)
    return _detection_to_out(detection)


# ---------------------------------------------------------------------------
# Draft detections CRUD
# ---------------------------------------------------------------------------


@router.get("/{session_id}/detections", response_model=list[DraftDetectionOut])
async def list_detections(
    session_id: str,
    db: Session = Depends(get_session),
) -> list[DraftDetectionOut]:
    _get_session_or_404(session_id, db)
    detections = (
        db.query(HuntDraftDetection)
        .filter(HuntDraftDetection.session_id == session_id)
        .order_by(HuntDraftDetection.created_at)
        .all()
    )
    return [_detection_to_out(d) for d in detections]


@router.put("/{session_id}/detections/{detection_id}", response_model=DraftDetectionOut)
async def update_detection(
    session_id: str,
    detection_id: str,
    body: UpdateDetectionRequest,
    db: Session = Depends(get_session),
    _: None = Depends(require_api_key),
) -> DraftDetectionOut:
    detection = db.query(HuntDraftDetection).filter(
        HuntDraftDetection.id == detection_id,
        HuntDraftDetection.session_id == session_id,
    ).first()
    if not detection:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Detection not found")
    if body.title is not None:
        detection.title = body.title
    if body.content is not None:
        detection.content = body.content
    if body.status is not None:
        detection.status = body.status
    if body.rationale is not None:
        detection.rationale = body.rationale
    if body.pyramid_tier is not None:
        detection.pyramid_tier = body.pyramid_tier
    detection.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(detection)
    return _detection_to_out(detection)


# ---------------------------------------------------------------------------
# Export endpoints
# ---------------------------------------------------------------------------


@router.get("/{session_id}/export/markdown")
async def export_markdown(
    session_id: str,
    db: Session = Depends(get_session),
) -> Response:
    hunt = _get_session_or_404(session_id, db)
    from pythia.exporters.hunt import export_hunt_markdown
    content = export_hunt_markdown(hunt)
    filename = f"hunt-{session_id[:8]}.md"
    return Response(
        content=content.encode("utf-8"),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{session_id}/export/stix")
async def export_stix(
    session_id: str,
    db: Session = Depends(get_session),
) -> Response:
    hunt = _get_session_or_404(session_id, db)
    from pythia.exporters.hunt import export_hunt_stix
    bundle = export_hunt_stix(hunt)
    filename = f"hunt-{session_id[:8]}-stix.json"
    return Response(
        content=json.dumps(bundle, indent=2).encode("utf-8"),
        media_type="application/json; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{session_id}/export/pdf")
async def export_pdf(
    session_id: str,
    template: str = Query(default="executive", pattern="^(executive|technical)$"),
    db: Session = Depends(get_session),
) -> Response:
    hunt = _get_session_or_404(session_id, db)
    from pythia.reporting.pdf import render_hunt_report
    pdf_bytes = render_hunt_report(hunt, template)
    filename = f"hunt-{session_id[:8]}-{template}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/{session_id}/detections/{detection_id}/promote", status_code=status.HTTP_201_CREATED)
async def promote_detection(
    session_id: str,
    detection_id: str,
    db: Session = Depends(get_session),
    _: None = Depends(require_api_key),
) -> dict[str, str]:
    """Copy a draft detection into the main detection_rules table as pending_review."""
    detection = db.query(HuntDraftDetection).filter(
        HuntDraftDetection.id == detection_id,
        HuntDraftDetection.session_id == session_id,
    ).first()
    if not detection:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Detection not found")

    rule = DetectionRule(
        rule_type=detection.rule_type if detection.rule_type in ("sigma", "yara") else "sigma",
        title=detection.title,
        content=detection.content,
        technique_ids=detection.linked_ttp_ids or [],
        status="pending_review",
        source_url=f"hunt:{session_id}",
    )
    db.add(rule)
    detection.status = "promoted"
    detection.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(rule)
    return {"rule_id": rule.id, "message": "Promoted to detection_rules as pending_review"}
