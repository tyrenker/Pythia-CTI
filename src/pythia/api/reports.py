"""PDF report generation endpoints."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response
from sqlalchemy.orm import Session

from pythia.core.db import get_session
from pythia.models.report import SourceReport

router = APIRouter()

_HONEYPOT_REPORT_TYPES = {"honeypot_daily", "campaign_intel"}


@router.get("/{report_id}/pdf")
async def get_report_pdf(
    report_id: str,
    template: Literal["executive", "tactical", "honeypot_daily", "campaign_intel"] = Query(
        default="executive", description="Report template"
    ),
    session: Session = Depends(get_session),
) -> Response:
    """Render a parsed threat report as a PDF."""
    report = session.get(SourceReport, report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Report '{report_id}' not found"
        )

    pd: dict[str, Any] = report.parsed_data or {}
    report_type = pd.get("report_type", "")

    # Auto-detect template from stored report_type when caller uses default "executive"
    if template == "executive" and report_type in _HONEYPOT_REPORT_TYPES:
        template = report_type  # type: ignore[assignment]

    try:
        if template in _HONEYPOT_REPORT_TYPES:
            from pythia.reporting.pdf import render_honeypot_report

            pdf_bytes = render_honeypot_report(report, template=template)  # type: ignore[arg-type]
        else:
            from pythia.reporting.pdf import render_report

            pdf_bytes = render_report(report, template=template)  # type: ignore[arg-type]
    except ImportError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="PDF rendering requires the [reporting] extras. Run: pip install -e '.[reporting]'",
        ) from exc

    filename = f"pythia-{template}-{report_id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
