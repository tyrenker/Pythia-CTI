"""Webhook alerting — check watchlists after intel ingestion and fire matching hooks."""

from __future__ import annotations

import json
import urllib.request
from typing import Any

from sqlalchemy.orm import Session

from pythia.models.report import SourceReport
from pythia.models.watchlist import Watchlist


def _matches(watchlist: Watchlist, report: SourceReport) -> bool:
    """Return True if the report satisfies all non-null watchlist filters."""
    pd: dict[str, Any] = report.parsed_data or {}

    if watchlist.filter_actor:
        actors = [a.get("name", "") for a in (pd.get("actors") or [])]
        kw = watchlist.filter_actor.lower()
        if not any(kw in a.lower() for a in actors):
            return False

    if watchlist.filter_ttp:
        ttps = [t.get("technique_id", "") for t in (pd.get("ttps") or [])]
        kw = watchlist.filter_ttp.upper()
        if kw not in [t.upper() for t in ttps]:
            return False

    if watchlist.filter_sector:
        sectors = pd.get("sectors_targeted") or []
        kw = watchlist.filter_sector.lower()
        if not any(kw in s.lower() for s in sectors):
            return False

    return True


def _slack_payload(watchlist: Watchlist, report: SourceReport) -> bytes:
    pd: dict[str, Any] = report.parsed_data or {}
    summary = pd.get("summary") or report.title or report.id
    actors = ", ".join(a.get("name", "") for a in (pd.get("actors") or []) if a.get("name")) or "Unknown"
    ttps = ", ".join(t.get("technique_id", "") for t in (pd.get("ttps") or []) if t.get("technique_id")) or "None"

    payload = {
        "text": f":bell: *Pythia Watchlist Alert* — `{watchlist.name}`",
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"Pythia Alert: {watchlist.name}"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Report:*\n{report.title or report.id}"},
                    {"type": "mrkdwn", "text": f"*TLP:*\n{report.tlp}"},
                    {"type": "mrkdwn", "text": f"*Actors:*\n{actors}"},
                    {"type": "mrkdwn", "text": f"*TTPs:*\n{ttps}"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Summary:*\n{summary[:500]}"},
            },
        ],
    }
    return json.dumps(payload).encode()


def _generic_payload(watchlist: Watchlist, report: SourceReport) -> bytes:
    pd: dict[str, Any] = report.parsed_data or {}
    payload = {
        "event": "new_intel",
        "watchlist_id": watchlist.id,
        "watchlist_name": watchlist.name,
        "report_id": report.id,
        "title": report.title,
        "tlp": report.tlp,
        "summary": pd.get("summary"),
        "actors": [a.get("name") for a in (pd.get("actors") or []) if a.get("name")],
        "ttps": [t.get("technique_id") for t in (pd.get("ttps") or []) if t.get("technique_id")],
    }
    return json.dumps(payload).encode()


def _fire_webhook(watchlist: Watchlist, report: SourceReport) -> None:
    if watchlist.webhook_type in ("slack", "discord"):
        body = _slack_payload(watchlist, report)
    else:
        body = _generic_payload(watchlist, report)

    req = urllib.request.Request(
        watchlist.webhook_url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "Pythia/0.1"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10):
            pass
    except Exception:
        pass  # Don't let webhook failures block the parse response


def check_and_fire(report: SourceReport, session: Session) -> int:
    """Check all enabled watchlists against the report and fire matching webhooks.

    Returns the number of webhooks fired.
    """
    watchlists = session.query(Watchlist).filter(Watchlist.enabled.is_(True)).all()
    fired = 0
    for wl in watchlists:
        if _matches(wl, report):
            _fire_webhook(wl, report)
            fired += 1
    return fired
