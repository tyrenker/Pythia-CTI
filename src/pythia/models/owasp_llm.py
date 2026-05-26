"""OWASP LLM Top 10 (2025) ORM model."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from pythia.core.db import Base


class OwaspLlmItem(Base):
    __tablename__ = "owasp_llm_top10"

    item_id: Mapped[str] = mapped_column(String, primary_key=True)  # LLM01:2025
    rank: Mapped[int] = mapped_column(Integer, index=True)
    name: Mapped[str] = mapped_column(String, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    detection_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    atlas_mappings: Mapped[list] = mapped_column(JSON, default=list)   # [AML.Txxx]
    cwe_ids: Mapped[list] = mapped_column(JSON, default=list)           # [CWE-77]
    mitigations: Mapped[list] = mapped_column(JSON, default=list)
    real_world_examples: Mapped[list] = mapped_column(JSON, default=list)
    references: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
