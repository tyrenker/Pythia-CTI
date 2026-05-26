"""RSS/Atom feed endpoint.

GET /v1/feed.atom  — Atom 1.0 feed of recent ingested threat intel reports.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from pythia.core.config import get_settings
from pythia.core.db import get_session
from pythia.models.report import SourceReport

router = APIRouter()

_ATOM_NS = 'xmlns="http://www.w3.org/2005/Atom"'


def _esc(text: str | None) -> str:
    return html.escape(text or "", quote=False)


def _fmt_dt(dt: datetime | None) -> str:
    if dt is None:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_atom(reports: list[Any], base_url: str) -> str:
    now = _fmt_dt(datetime.now(timezone.utc))
    updated = _fmt_dt(reports[0].created_at) if reports else now

    entries: list[str] = []
    for r in reports:
        pd: dict[str, Any] = r.parsed_data or {}
        summary = _esc(pd.get("summary") or r.title or "No summary.")
        actors = ", ".join(
            a.get("name", "") for a in (pd.get("actors") or []) if a.get("name")
        )
        ttps = ", ".join(
            t.get("technique_id", "") for t in (pd.get("ttps") or []) if t.get("technique_id")
        )
        content_lines = [summary]
        if actors:
            content_lines.append(f"Actors: {_esc(actors)}")
        if ttps:
            content_lines.append(f"TTPs: {_esc(ttps)}")
        content = " | ".join(content_lines)

        link = _esc(r.url or f"{base_url}/v1/threats/{r.id}")
        entries.append(f"""  <entry>
    <id>{_esc(base_url)}/v1/threats/{r.id}</id>
    <title>{_esc(r.title or r.id)}</title>
    <link href="{link}" rel="alternate"/>
    <updated>{_fmt_dt(r.created_at)}</updated>
    <summary type="text">{_esc(content)}</summary>
    <category term="tlp:{r.tlp.lower()}"/>
  </entry>""")

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<feed {_ATOM_NS}>
  <id>{_esc(base_url)}/v1/feed.atom</id>
  <title>Pythia Threat Intelligence Feed</title>
  <subtitle>Oracle-grade threat intelligence, served as an API.</subtitle>
  <link href="{_esc(base_url)}/v1/feed.atom" rel="self"/>
  <link href="{_esc(base_url)}" rel="alternate"/>
  <updated>{updated}</updated>
  <generator uri="https://github.com/tyrenker/pythia">Pythia</generator>
{chr(10).join(entries)}
</feed>"""


@router.get("/feed.atom", include_in_schema=True)
async def atom_feed(
    limit: int = Query(default=50, le=200, description="Number of entries"),
    tlp: str | None = Query(default=None, description="Filter by TLP (WHITE, GREEN, AMBER, RED)"),
    session: Session = Depends(get_session),
) -> Response:
    """Atom 1.0 feed of recently ingested threat intel reports.

    Subscribe in Feedly, Inoreader, or any Atom-compatible reader.
    """
    settings = get_settings()
    q = session.query(SourceReport)
    if tlp:
        q = q.filter(SourceReport.tlp == tlp.upper())
    reports = q.order_by(SourceReport.created_at.desc()).limit(limit).all()

    base_url = f"http://{settings.host}:{settings.port}"
    xml = _build_atom(reports, base_url)
    return Response(content=xml, media_type="application/atom+xml; charset=utf-8")
