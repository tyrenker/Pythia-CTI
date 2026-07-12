"""Find-or-create Indicators of Compromise during article ingestion."""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from pythia.models.ioc import IoC

logger = logging.getLogger(__name__)


def link_iocs_from_report(session: Session, parsed_data: dict[str, Any], report_url: str | None = None, report: Any = None) -> list[str]:
    """Extract IoCs from the parsed report, auto-create them, and inject their IDs back into parsed_data."""
    extracted_iocs = parsed_data.get("iocs") or []
    if not extracted_iocs:
        return []

    linked_ids = []
    modified = False
    
    for ioc_dict in extracted_iocs:
        ioc_type = ioc_dict.get("type")
        ioc_value = ioc_dict.get("value")
        if not ioc_type or not ioc_value:
            continue
            
        # Clean value
        ioc_value = str(ioc_value).strip()
        ioc_type = str(ioc_type).strip().lower()
        
        # Find existing IoC by value
        ioc = session.query(IoC).filter(IoC.value == ioc_value).first()
        
        if not ioc:
            # Create new IoC
            ioc = IoC(
                type=ioc_type,
                value=ioc_value,
                context=ioc_dict.get("context"),
                source_url=report_url,
                # Default to some standard confidence since it's from an intel report
                confidence_source="B", 
                confidence_info="2",
            )
            session.add(ioc)
            session.flush() # flush to get the ID
            
        linked_ids.append(ioc.id)
        
        # Inject the ID back into the parsed_data dict if it doesn't already have it
        if ioc_dict.get("id") != ioc.id:
            ioc_dict["id"] = ioc.id
            modified = True

    if modified and report:
        # report.parsed_data was mutated. Let SQLAlchemy know.
        flag_modified(report, "parsed_data")

    return linked_ids
