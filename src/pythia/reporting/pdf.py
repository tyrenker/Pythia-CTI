"""PDF report rendering via Jinja2 + WeasyPrint."""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any, Literal

Template = Literal["tactical", "executive"]

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


def _render_html(template_name: str, context: dict[str, Any]) -> str:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    tmpl = env.get_template(f"{template_name}.html")
    return tmpl.render(**context)


def render_report(report: Any, template: Template = "executive") -> bytes:
    """Render a SourceReport to PDF bytes.

    `report` is a SourceReport ORM instance (or any object with the same fields).
    """
    from weasyprint import HTML

    pd: dict[str, Any] = report.parsed_data or {}

    context: dict[str, Any] = {
        "report_id": report.id,
        "title": report.title or pd.get("title") or "Threat Intelligence Report",
        "tlp": report.tlp,
        "tlp_label": f"TLP:{report.tlp}",
        "report_type": "Executive Summary Report" if template == "executive" else "Tactical Analysis Report",
        "generated_date": date.today().isoformat(),
        "pub_date": report.publication_date,
        "summary": pd.get("summary"),
        "actors": pd.get("actors") or [],
        "ttps": pd.get("ttps") or [],
        "iocs": pd.get("iocs") or [],
        "cves": pd.get("cves") or [],
        "sectors_targeted": pd.get("sectors_targeted") or [],
        "geographies_targeted": pd.get("geographies_targeted") or [],
        "killchain_phases": pd.get("killchain_phases") or [],
        "atlas_techniques": pd.get("atlas_techniques") or [],
        "owasp_llm": pd.get("owasp_llm_top10") or [],
        "admiralty": pd.get("confidence_admiralty") or "F6",
        "ioc_count": len(pd.get("iocs") or []) + len(pd.get("cves") or []),
        "source_url": report.url,
    }

    if template == "executive" and pd.get("business_impact_draft"):
        context["business_impact"] = pd["business_impact_draft"]

    html_content = _render_html(template, context)
    return HTML(string=html_content, base_url=str(_TEMPLATES_DIR)).write_pdf()  # type: ignore[return-value]
