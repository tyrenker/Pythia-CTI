"""SIEM integration API.

GET    /v1/siem/status                  Test connection; return SIEM type and status
POST   /v1/siem/rules/deploy/{rule_id}  Convert + push one rule to SIEM
POST   /v1/siem/rules/deploy-all        Push all active DetectionRules
DELETE /v1/siem/rules/{rule_id}         Remove from SIEM
GET    /v1/siem/alerts                  List SiemAlerts
GET    /v1/siem/alerts/stats            Alert counts by severity and triage status
GET    /v1/siem/alerts/{id}             Alert detail
POST   /v1/siem/alerts                  Webhook receiver
PATCH  /v1/siem/alerts/{id}/triage      Update triage status
"""

from __future__ import annotations

import contextlib
import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from pythia.core.db import get_session
from pythia.core.security import require_api_key
from pythia.models.honeypot import HoneypotCampaign, HoneypotEvent, SiemAlert
from pythia.models.rule import DetectionRule

router = APIRouter()


# ── Response schemas ──────────────────────────────────────────────────────────


class SiemAlertOut(BaseModel):
    id: str
    siem_source: str
    external_alert_id: str | None
    rule_id: str | None
    campaign_id: str | None
    severity: str
    title: str
    attacker_ip: str | None
    mitre_techniques: list[str]
    triage_status: str
    analyst_notes: str | None
    triaged_by: str | None
    triaged_at: datetime | None
    received_at: datetime

    model_config = {"from_attributes": True}


class TriageBody(BaseModel):
    triage_status: str
    analyst_notes: str | None = None
    triaged_by: str | None = None


class RuleDeployOut(BaseModel):
    rule_id: str
    siem_rule_id: str
    deployed_at: datetime


# ── Status ────────────────────────────────────────────────────────────────────


@router.get("/status")
def siem_status() -> dict[str, Any]:
    from pythia.core.config import get_settings
    from pythia.integrations.siem.factory import get_siem_client

    settings = get_settings()
    client = get_siem_client()
    if client is None:
        return {"configured": False, "siem_type": settings.siem_type}
    connected = client.test_connection()
    return {"configured": True, "siem_type": settings.siem_type, "connected": connected}


# ── Rule deployment ───────────────────────────────────────────────────────────


@router.post("/rules/deploy/{rule_id}", response_model=RuleDeployOut)
def deploy_rule(
    rule_id: str,
    _: Annotated[None, Depends(require_api_key)],
    session: Session = Depends(get_session),
) -> RuleDeployOut:
    from pythia.integrations.siem.factory import get_siem_client

    client = get_siem_client()
    if client is None:
        raise HTTPException(status_code=503, detail="No SIEM configured")
    rule = session.get(DetectionRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    try:
        siem_rule_id = client.deploy_rule(rule)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"SIEM deploy failed: {exc}") from exc
    rule.siem_rule_id = siem_rule_id
    rule.siem_deployed_at = datetime.utcnow()
    session.commit()
    return RuleDeployOut(
        rule_id=rule.id, siem_rule_id=siem_rule_id, deployed_at=rule.siem_deployed_at
    )


@router.post("/rules/deploy-all")
def deploy_all_rules(
    _: Annotated[None, Depends(require_api_key)],
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    from pythia.integrations.siem.factory import get_siem_client

    client = get_siem_client()
    if client is None:
        raise HTTPException(status_code=503, detail="No SIEM configured")
    rules = session.query(DetectionRule).filter(DetectionRule.status == "active").all()
    deployed = []
    failed = []
    for rule in rules:
        try:
            siem_rule_id = client.deploy_rule(rule)
            rule.siem_rule_id = siem_rule_id
            rule.siem_deployed_at = datetime.utcnow()
            deployed.append(rule.id)
        except Exception:
            failed.append(rule.id)
    session.commit()
    return {"deployed": len(deployed), "failed": len(failed), "rule_ids": deployed}


@router.delete("/rules/{rule_id}", status_code=204)
def remove_rule_from_siem(
    rule_id: str,
    _: Annotated[None, Depends(require_api_key)],
    session: Session = Depends(get_session),
) -> None:
    from pythia.integrations.siem.factory import get_siem_client

    client = get_siem_client()
    if client is None:
        raise HTTPException(status_code=503, detail="No SIEM configured")
    rule = session.get(DetectionRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    if not rule.siem_rule_id:
        raise HTTPException(status_code=404, detail="Rule not deployed to SIEM")
    try:
        client.delete_rule(rule.siem_rule_id)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"SIEM delete failed: {exc}") from exc
    rule.siem_rule_id = None
    rule.siem_deployed_at = None
    session.commit()


# ── Alerts ────────────────────────────────────────────────────────────────────


@router.get("/alerts/stats")
def alert_stats(session: Session = Depends(get_session)) -> dict[str, Any]:
    from collections import Counter

    alerts = session.query(SiemAlert).all()
    by_severity: Counter[str] = Counter(a.severity for a in alerts)
    by_triage: Counter[str] = Counter(a.triage_status for a in alerts)
    return {"by_severity": dict(by_severity), "by_triage": dict(by_triage), "total": len(alerts)}


@router.get("/alerts", response_model=list[SiemAlertOut])
def list_alerts(
    triage_status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    since: datetime | None = Query(default=None),
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_session),
) -> list[SiemAlert]:
    q = session.query(SiemAlert)
    if triage_status:
        q = q.filter(SiemAlert.triage_status == triage_status)
    if severity:
        q = q.filter(SiemAlert.severity == severity)
    if since:
        q = q.filter(SiemAlert.received_at >= since)
    return q.order_by(SiemAlert.received_at.desc()).offset(offset).limit(limit).all()


@router.get("/alerts/{alert_id}", response_model=SiemAlertOut)
def get_alert(alert_id: str, session: Session = Depends(get_session)) -> SiemAlert:
    alert = session.get(SiemAlert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.post("/alerts", status_code=201)
def receive_alert(
    raw_body: dict[str, Any],
    session: Session = Depends(get_session),
) -> dict[str, str]:
    """Webhook receiver — SIEM posts here when a rule fires."""
    from pythia.core.config import get_settings

    siem_type = raw_body.get("siem_source") or get_settings().siem_type or "demo"
    title = (
        raw_body.get("rule", {}).get("description")
        or raw_body.get("title")
        or raw_body.get("name")
        or "Unknown Alert"
    )
    severity = raw_body.get("rule", {}).get("level") or raw_body.get("severity") or "medium"
    attacker_ip = (
        raw_body.get("data", {}).get("srcip")
        or raw_body.get("attacker_ip")
        or raw_body.get("src_ip")
    )
    external_id = raw_body.get("id") or raw_body.get("alert_id")
    mitre_techniques: list[str] = raw_body.get("rule", {}).get("mitre", {}).get(
        "id", []
    ) or raw_body.get("mitre_techniques", [])

    # Match to rule by title
    rule_id: str | None = None
    rule = session.query(DetectionRule).filter(DetectionRule.title.ilike(f"%{title[:40]}%")).first()
    if rule:
        rule_id = rule.id

    # Match attacker IP to campaign
    campaign_id: str | None = None
    if attacker_ip:
        ev = (
            session.query(HoneypotEvent)
            .filter(HoneypotEvent.attacker_ip == attacker_ip)
            .filter(HoneypotEvent.campaign_id.isnot(None))
            .first()
        )
        if ev:
            campaign_id = ev.campaign_id

    alert = SiemAlert(
        id=str(uuid.uuid4()),
        siem_source=siem_type,
        external_alert_id=str(external_id) if external_id else None,
        rule_id=rule_id,
        campaign_id=campaign_id,
        severity=str(severity),
        title=str(title),
        raw_event=raw_body,
        attacker_ip=attacker_ip,
        mitre_techniques=mitre_techniques,
        triage_status="new",
        received_at=datetime.utcnow(),
    )
    session.add(alert)
    session.commit()

    # Fire watchlist webhook if campaign matched
    if campaign_id:
        campaign = session.get(HoneypotCampaign, campaign_id)
        if campaign:
            with contextlib.suppress(Exception):
                _fire_campaign_webhook(campaign, alert)

    return {"alert_id": alert.id}


def _fire_campaign_webhook(campaign: HoneypotCampaign, alert: SiemAlert) -> None:
    import json as _json
    import urllib.request

    from pythia.core.db import SessionLocal
    from pythia.models.watchlist import Watchlist

    with SessionLocal() as session:
        watchlists = session.query(Watchlist).filter(Watchlist.enabled.is_(True)).all()
        for wl in watchlists:
            if not wl.webhook_url:
                continue
            payload = {
                "event": "siem_alert",
                "campaign_name": campaign.name,
                "campaign_id": campaign.id,
                "event_count": campaign.event_count,
                "ttp_ids": campaign.ttp_ids,
                "alert_id": alert.id,
                "alert_title": alert.title,
                "severity": alert.severity,
                "attacker_ip": alert.attacker_ip,
            }
            body = _json.dumps(payload).encode()
            req = urllib.request.Request(
                wl.webhook_url,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=10):
                    pass
            except Exception:
                pass


@router.patch("/alerts/{alert_id}/triage", response_model=SiemAlertOut)
def triage_alert(
    alert_id: str,
    body: TriageBody,
    _: Annotated[None, Depends(require_api_key)],
    session: Session = Depends(get_session),
) -> SiemAlert:
    alert = session.get(SiemAlert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    valid_statuses = {"new", "investigating", "true_positive", "false_positive", "closed"}
    if body.triage_status not in valid_statuses:
        raise HTTPException(
            status_code=422, detail=f"Invalid triage_status. Valid: {valid_statuses}"
        )
    alert.triage_status = body.triage_status
    if body.analyst_notes is not None:
        alert.analyst_notes = body.analyst_notes
    if body.triaged_by is not None:
        alert.triaged_by = body.triaged_by
    alert.triaged_at = datetime.utcnow()
    session.commit()
    session.refresh(alert)
    return alert
