"""PDF report generation endpoints."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response
from sqlalchemy.orm import Session

from pythia.core.db import get_session
from pythia.models.report import SourceReport

router = APIRouter()


@router.get("/{report_id}/pdf")
async def get_report_pdf(
    report_id: str,
    template: Literal["executive", "tactical"] = Query(default="executive", description="Report template"),
    session: Session = Depends(get_session),
) -> Response:
    """Render a parsed threat report as a PDF (executive or tactical layout)."""
    report = session.get(SourceReport, report_id)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Report '{report_id}' not found")

    try:
        from pythia.reporting.pdf import render_report
        pdf_bytes = render_report(report, template=template)
    except ImportError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="PDF rendering requires the [reporting] extras. Run: pip install -e '.[reporting]'",
        )

    filename = f"pythia-{template}-{report_id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
