"""Claude-powered intel article parsing endpoint."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from pythia.core.db import get_session
from pythia.models.report import SourceReport

router = APIRouter()


class ParseRequest(BaseModel):
    url: str | None = Field(default=None, description="URL to fetch and parse")
    text: str | None = Field(default=None, description="Raw article text to parse directly")


class ParseResponse(BaseModel):
    report_id: str
    title: str | None = None
    tlp: str
    status: str
    parsed_data: dict[str, object] = Field(default_factory=dict)


@router.post("", response_model=ParseResponse, status_code=status.HTTP_201_CREATED)
async def parse_intel(
    request: ParseRequest,
    session: Session = Depends(get_session),
) -> ParseResponse:
    if not request.url and not request.text:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Provide either 'url' or 'text'.",
        )

    raw_text: str = ""
    if request.url:
        try:
            import trafilatura
            downloaded = trafilatura.fetch_url(request.url)
            if downloaded:
                raw_text = trafilatura.extract(downloaded) or ""
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Failed to fetch URL: {exc}",
            ) from exc

    if request.text:
        raw_text = request.text

    if not raw_text.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Could not extract text from the provided URL.",
        )

    try:
        from pythia.ingestion.claude_parser import parse_article
        parsed = parse_article(raw_text, source_url=request.url)
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Claude parsing failed: {exc}",
        ) from exc

    report = SourceReport(
        id=str(uuid.uuid4()),
        title=parsed.get("title"),  # type: ignore[arg-type]
        url=request.url,
        raw_text=raw_text[:50_000],  # guard against huge articles
        publication_date=parsed.get("publication_date"),  # type: ignore[arg-type]
        status="pending_review",
        parsed_data=parsed,
        tlp=str(parsed.get("tlp", "GREEN")),
    )
    session.add(report)
    session.commit()

    # Fire watchlist webhooks for any matching subscriptions (best-effort, non-blocking)
    try:
        from pythia.core.alerting import check_and_fire
        check_and_fire(report, session)
    except Exception:
        pass

    return ParseResponse(
        report_id=report.id,
        title=report.title,
        tlp=report.tlp,
        status=report.status,
        parsed_data=parsed,
    )
