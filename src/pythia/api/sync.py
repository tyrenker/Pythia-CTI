"""Sync status API endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from pythia.core.config import get_settings
from pythia.core.db import get_session
from pythia.models.sync_log import SyncLog

router = APIRouter()


@router.get("/status")
def get_sync_status(session: Session = Depends(get_session)) -> dict[str, Any]:
    """Get the last run datetime and sync status for each threat intelligence feed."""
    settings = get_settings()

    # Query all sync logs
    logs = session.query(SyncLog).all()
    sources_data = {
        log.source: {
            "last_run": log.last_run.isoformat() if log.last_run else None,
            "status": log.status,
        }
        for log in logs
    }

    # Pre-populate default states for feeds that haven't run yet
    default_feeds = [
        "attck",
        "misp_galaxy",
        "mitre_malware",
        "misp_malware",
        "apt_sheet",
        "abuse_ch",
        "ipsum",
        "phishtank",
        "yara_rules",
        "icewater",
        "signature_base",
        "sigma_full",
    ]

    # Check if optional feed keys are missing to set initial 'no_key' status
    for feed in default_feeds:
        if feed not in sources_data:
            status = "skip"
            if feed == "phishtank" and not settings.phishtank_api_key:
                status = "no_key"
            sources_data[feed] = {
                "last_run": None,
                "status": status,
            }

    return {
        "sources": sources_data,
        "scheduler_enabled": settings.enable_scheduler,
    }
