"""Watchlist subscription CRUD for webhook alerting.

POST   /v1/watchlist       — create subscription (auth required)
GET    /v1/watchlist       — list subscriptions
DELETE /v1/watchlist/{id}  — delete subscription (auth required)
POST   /v1/watchlist/test  — fire a test ping to a webhook URL
"""

from __future__ import annotations

import json
import urllib.request

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy.orm import Session

from pythia.core.db import get_session
from pythia.core.security import require_api_key
from pythia.models.watchlist import Watchlist

router = APIRouter()


class WatchlistCreate(BaseModel):
    name: str = Field(description="Human-readable label for this subscription")
    filter_actor: str | None = Field(default=None, description="Alert when actor name contains this substring")
    filter_ttp: str | None = Field(default=None, description="Alert when TTPs include this technique ID (e.g. T1566)")
    filter_sector: str | None = Field(default=None, description="Alert when sectors_targeted contains this substring")
    webhook_url: str = Field(description="URL to POST to on match")
    webhook_type: str = Field(default="slack", description="slack | discord | generic")


class WatchlistOut(BaseModel):
    id: str
    name: str
    filter_actor: str | None = None
    filter_ttp: str | None = None
    filter_sector: str | None = None
    webhook_url: str
    webhook_type: str
    enabled: bool


@router.post("", response_model=WatchlistOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_api_key)])
async def create_watchlist(
    body: WatchlistCreate,
    session: Session = Depends(get_session),
) -> WatchlistOut:
    """Create a new watchlist subscription. At least one filter field is required."""
    if not any([body.filter_actor, body.filter_ttp, body.filter_sector]):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Provide at least one filter: filter_actor, filter_ttp, or filter_sector.",
        )
    wl = Watchlist(
        name=body.name,
        filter_actor=body.filter_actor,
        filter_ttp=body.filter_ttp,
        filter_sector=body.filter_sector,
        webhook_url=body.webhook_url,
        webhook_type=body.webhook_type,
    )
    session.add(wl)
    session.commit()
    session.refresh(wl)
    return WatchlistOut(
        id=wl.id,
        name=wl.name,
        filter_actor=wl.filter_actor,
        filter_ttp=wl.filter_ttp,
        filter_sector=wl.filter_sector,
        webhook_url=wl.webhook_url,
        webhook_type=wl.webhook_type,
        enabled=wl.enabled,
    )


@router.get("", response_model=list[WatchlistOut])
async def list_watchlists(
    session: Session = Depends(get_session),
) -> list[WatchlistOut]:
    """List all watchlist subscriptions."""
    return [
        WatchlistOut(
            id=wl.id,
            name=wl.name,
            filter_actor=wl.filter_actor,
            filter_ttp=wl.filter_ttp,
            filter_sector=wl.filter_sector,
            webhook_url=wl.webhook_url,
            webhook_type=wl.webhook_type,
            enabled=wl.enabled,
        )
        for wl in session.query(Watchlist).order_by(Watchlist.created_at.desc()).all()
    ]


@router.delete("/{watchlist_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_api_key)])
async def delete_watchlist(
    watchlist_id: str,
    session: Session = Depends(get_session),
) -> None:
    """Delete a watchlist subscription."""
    wl = session.get(Watchlist, watchlist_id)
    if not wl:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Watchlist '{watchlist_id}' not found")
    session.delete(wl)
    session.commit()


class TestPayload(BaseModel):
    webhook_url: str
    webhook_type: str = "slack"


@router.post("/test", status_code=status.HTTP_200_OK, dependencies=[Depends(require_api_key)])
async def test_webhook(body: TestPayload) -> dict[str, str]:
    """Send a test ping to a webhook URL to verify connectivity."""
    if body.webhook_type in ("slack", "discord"):
        payload = json.dumps({
            "text": ":white_check_mark: *Pythia Watchlist* — test ping successful. Alerts are wired up.",
        }).encode()
    else:
        payload = json.dumps({"event": "test", "source": "pythia"}).encode()

    req = urllib.request.Request(
        body.webhook_url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "Pythia/0.1"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return {"status": "ok", "http_status": str(resp.status)}
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Webhook delivery failed: {exc}",
        ) from exc
