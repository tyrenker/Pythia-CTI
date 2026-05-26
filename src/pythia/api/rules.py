"""Detection rule endpoints (Sigma / Yara)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from pythia.core.db import get_session
from pythia.core.security import require_api_key
from pythia.models.rule import DetectionRule

router = APIRouter()


class RuleCreate(BaseModel):
    rule_type: str  # sigma | yara
    title: str
    content: str
    severity: str | None = None
    technique_ids: list[str] = Field(default_factory=list)
    actor_ids: list[str] = Field(default_factory=list)
    status: str | None = None
    source_url: str | None = None


class RuleUpdate(BaseModel):
    title: str | None = None
    content: str | None = None
    severity: str | None = None
    technique_ids: list[str] | None = None
    actor_ids: list[str] | None = None
    status: str | None = None
    source_url: str | None = None


class RuleSummary(BaseModel):
    id: str
    rule_type: str
    title: str
    technique_ids: list[str] = Field(default_factory=list)
    severity: str | None = None
    status: str | None = None
    source_url: str | None = None


class RuleDetail(RuleSummary):
    content: str
    actor_ids: list[str] = Field(default_factory=list)


@router.get("", response_model=list[RuleSummary])
async def list_rules(
    rule_type: str | None = Query(default=None, description="Filter by type: sigma | yara"),
    technique_id: str | None = Query(default=None, description="Filter by linked ATT&CK technique ID"),
    severity: str | None = Query(default=None, description="Filter by severity"),
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_session),
) -> list[RuleSummary]:
    q = session.query(DetectionRule)
    if rule_type:
        q = q.filter(DetectionRule.rule_type == rule_type.lower())
    if severity:
        q = q.filter(DetectionRule.severity == severity.lower())
    if technique_id:
        q = q.filter(DetectionRule.technique_ids.contains(technique_id.upper()))
    rules = q.order_by(DetectionRule.title).offset(offset).limit(limit).all()
    return [
        RuleSummary(
            id=r.id,
            rule_type=r.rule_type,
            title=r.title,
            technique_ids=r.technique_ids or [],
            severity=r.severity,
            status=r.status,
            source_url=r.source_url,
        )
        for r in rules
    ]


@router.get("/sigma/{rule_id}", response_model=RuleDetail)
async def get_sigma_rule(
    rule_id: str,
    session: Session = Depends(get_session),
) -> RuleDetail:
    rule = session.get(DetectionRule, rule_id)
    if not rule or rule.rule_type != "sigma":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Sigma rule '{rule_id}' not found")
    return RuleDetail(
        id=rule.id,
        rule_type=rule.rule_type,
        title=rule.title,
        content=rule.content,
        technique_ids=rule.technique_ids or [],
        actor_ids=rule.actor_ids or [],
        severity=rule.severity,
        status=rule.status,
        source_url=rule.source_url,
    )


@router.get("/yara/{rule_id}", response_model=RuleDetail)
async def get_yara_rule(
    rule_id: str,
    session: Session = Depends(get_session),
) -> RuleDetail:
    rule = session.get(DetectionRule, rule_id)
    if not rule or rule.rule_type != "yara":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Yara rule '{rule_id}' not found")
    return RuleDetail(
        id=rule.id,
        rule_type=rule.rule_type,
        title=rule.title,
        content=rule.content,
        technique_ids=rule.technique_ids or [],
        actor_ids=rule.actor_ids or [],
        severity=rule.severity,
        status=rule.status,
        source_url=rule.source_url,
    )


@router.post("", response_model=RuleDetail, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_api_key)])
async def create_rule(
    body: RuleCreate,
    session: Session = Depends(get_session),
) -> RuleDetail:
    """Create a new Sigma or Yara detection rule."""
    rule_type = body.rule_type.lower()
    if rule_type not in ("sigma", "yara"):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="rule_type must be 'sigma' or 'yara'")

    rule = DetectionRule(
        rule_type=rule_type,
        title=body.title.strip(),
        content=body.content,
        severity=body.severity,
        technique_ids=[t.upper() for t in body.technique_ids],
        actor_ids=body.actor_ids,
        status=body.status,
        source_url=body.source_url,
    )
    session.add(rule)
    session.commit()
    session.refresh(rule)
    return RuleDetail(
        id=rule.id,
        rule_type=rule.rule_type,
        title=rule.title,
        content=rule.content,
        technique_ids=rule.technique_ids or [],
        actor_ids=rule.actor_ids or [],
        severity=rule.severity,
        status=rule.status,
        source_url=rule.source_url,
    )


def _get_rule_or_404(rule_id: str, session: Session) -> DetectionRule:
    rule = session.get(DetectionRule, rule_id)
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule '{rule_id}' not found")
    return rule


@router.patch("/{rule_id}", response_model=RuleDetail, dependencies=[Depends(require_api_key)])
async def update_rule(
    rule_id: str,
    body: RuleUpdate,
    session: Session = Depends(get_session),
) -> RuleDetail:
    """Partially update a detection rule."""
    rule = _get_rule_or_404(rule_id, session)
    if body.title is not None:
        rule.title = body.title.strip()
    if body.content is not None:
        rule.content = body.content
    if body.severity is not None:
        rule.severity = body.severity or None
    if body.status is not None:
        rule.status = body.status or None
    if body.technique_ids is not None:
        rule.technique_ids = [t.upper() for t in body.technique_ids]
    if body.actor_ids is not None:
        rule.actor_ids = body.actor_ids
    if body.source_url is not None:
        rule.source_url = body.source_url or None
    session.commit()
    session.refresh(rule)
    return RuleDetail(
        id=rule.id,
        rule_type=rule.rule_type,
        title=rule.title,
        content=rule.content,
        technique_ids=rule.technique_ids or [],
        actor_ids=rule.actor_ids or [],
        severity=rule.severity,
        status=rule.status,
        source_url=rule.source_url,
    )


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_api_key)])
async def delete_rule(
    rule_id: str,
    session: Session = Depends(get_session),
) -> None:
    """Permanently delete a detection rule."""
    rule = _get_rule_or_404(rule_id, session)
    session.delete(rule)
    session.commit()
