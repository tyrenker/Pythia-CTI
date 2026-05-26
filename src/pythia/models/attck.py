"""MITRE ATT&CK technique ORM model."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from pythia.core.db import Base


class AttckTechnique(Base):
    __tablename__ = "attck_techniques"

    technique_id: Mapped[str] = mapped_column(String, primary_key=True)  # T1234 or T1234.001
    name: Mapped[str] = mapped_column(String, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    tactics: Mapped[list] = mapped_column(JSON, default=list)  # ["initial-access", "execution"]
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, default=False)
    parent_id: Mapped[str | None] = mapped_column(String, nullable=True)
    domain: Mapped[str] = mapped_column(String, default="enterprise")  # enterprise|mobile|ics
    detection_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    platforms: Mapped[list] = mapped_column(JSON, default=list)
    data_sources: Mapped[list] = mapped_column(JSON, default=list)
    mitigations: Mapped[list] = mapped_column(JSON, default=list)  # [{"id": ..., "name": ..., "desc": ...}]
    source_url: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Self-referential parent/subtechnique links are navigated via parent_id (string)
    # rather than ORM relationships to keep mapping configuration simple.
