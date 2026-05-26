"""Source report and business impact brief ORM models."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from pythia.core.db import Base


class SourceReport(Base):
    __tablename__ = "source_reports"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    title: Mapped[str | None] = mapped_column(String, nullable=True)
    url: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    raw_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    publication_date: Mapped[str | None] = mapped_column(String(10), nullable=True)
    status: Mapped[str] = mapped_column(String, default="pending_review")  # pending_review|accepted|rejected
    parsed_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    tlp: Mapped[str] = mapped_column(String, default="GREEN")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class BusinessImpactBrief(Base):
    __tablename__ = "business_impact_briefs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    report_id: Mapped[str | None] = mapped_column(
        ForeignKey("source_reports.id", ondelete="SET NULL"), nullable=True
    )
    so_what: Mapped[str | None] = mapped_column(Text, nullable=True)
    financial_low_usd: Mapped[int | None] = mapped_column(nullable=True)
    financial_high_usd: Mapped[int | None] = mapped_column(nullable=True)
    operational_impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    regulatory_impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    board_actions: Mapped[list] = mapped_column(JSON, default=list)
    risk_score: Mapped[str | None] = mapped_column(String, nullable=True)  # Low|Medium|High|Critical
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
