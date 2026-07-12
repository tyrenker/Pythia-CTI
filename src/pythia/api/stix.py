"""STIX 2.1 Export Endpoints."""

from __future__ import annotations

import json
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from pythia.core.db import get_session
from pythia.models.actor import ThreatActor
from pythia.models.report import SourceReport

router = APIRouter()


class STIXBundle(BaseModel):
    type: str = "bundle"
    id: str
    spec_version: str = "2.1"
    objects: list[dict]


@router.get("/actor/{actor_id}", response_model=STIXBundle)
def export_actor_stix(
    actor_id: str,
    session: Session = Depends(get_session),
) -> STIXBundle:
    """Export a Threat Actor as a STIX 2.1 bundle."""
    actor = session.get(ThreatActor, actor_id)
    if not actor:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Threat Actor '{actor_id}' not found"
        )

    actor_stix = {
        "type": "threat-actor",
        "spec_version": "2.1",
        "id": f"threat-actor--{actor.id}",
        "created": actor.created_at.isoformat() + "Z",
        "modified": actor.updated_at.isoformat() + "Z",
        "name": actor.name,
        "description": actor.description or "",
        "aliases": actor.aliases or [],
        "roles": [actor.sponsor_type] if actor.sponsor_type else [],
        "goals": actor.motivations or [],
    }

    bundle = STIXBundle(
        id=f"bundle--{uuid.uuid4()}",
        objects=[actor_stix]
    )
    return bundle


@router.get("/report/{report_id}", response_model=STIXBundle)
def export_report_stix(
    report_id: str,
    session: Session = Depends(get_session),
) -> STIXBundle:
    """Export a SourceReport (Campaign) as a STIX 2.1 bundle."""
    report = session.get(SourceReport, report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Report '{report_id}' not found"
        )

    pd = report.parsed_data or {}
    
    report_stix = {
        "type": "report",
        "spec_version": "2.1",
        "id": f"report--{report.id}",
        "created": (report.created_at or datetime.utcnow()).isoformat() + "Z",
        "modified": (report.updated_at or datetime.utcnow()).isoformat() + "Z",
        "name": report.title or "Untitled Report",
        "description": pd.get("summary", ""),
        "published": (report.publication_date or datetime.utcnow().isoformat()) + "Z",
        "object_refs": [],
    }

    objects = [report_stix]
    
    # Process extracted IoCs if any
    iocs = pd.get("iocs") or []
    for ioc in iocs:
        ioc_val = ioc.get("value")
        ioc_type = ioc.get("type", "unknown")
        if not ioc_val:
            continue
            
        pattern = ""
        if ioc_type == "ip":
            pattern = f"[ipv4-addr:value = '{ioc_val}']"
        elif ioc_type == "domain":
            pattern = f"[domain-name:value = '{ioc_val}']"
        elif ioc_type in ("md5", "sha1", "sha256"):
            pattern = f"[file:hashes.'{ioc_type.upper()}' = '{ioc_val}']"
        
        if pattern:
            ind_id = f"indicator--{uuid.uuid4()}"
            indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": ind_id,
                "created": datetime.utcnow().isoformat() + "Z",
                "modified": datetime.utcnow().isoformat() + "Z",
                "name": ioc_val,
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": datetime.utcnow().isoformat() + "Z",
            }
            objects.append(indicator)
            report_stix["object_refs"].append(ind_id)

    bundle = STIXBundle(
        id=f"bundle--{uuid.uuid4()}",
        objects=objects
    )
    return bundle
