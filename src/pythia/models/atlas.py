"""MITRE ATLAS AI/ML technique ORM model."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from pythia.core.db import Base


class AtlasTechnique(Base):
    __tablename__ = "atlas_techniques"

    technique_id: Mapped[str] = mapped_column(String, primary_key=True)  # AML.Txxxx
    name: Mapped[str] = mapped_column(String, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    tactics: Mapped[list] = mapped_column(JSON, default=list)
    subtechniques: Mapped[list] = mapped_column(JSON, default=list)  # [{id, name}]
    mitigations: Mapped[list] = mapped_column(JSON, default=list)  # [{id, name}]
    case_study_refs: Mapped[list] = mapped_column(JSON, default=list)
    source_url: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
