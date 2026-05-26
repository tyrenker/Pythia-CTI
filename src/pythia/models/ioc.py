"""Indicator of Compromise ORM model."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from pythia.core.db import Base


class IoC(Base):
    __tablename__ = "iocs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    type: Mapped[str] = mapped_column(String, index=True)
    value: Mapped[str] = mapped_column(String, index=True)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    confidence_source: Mapped[str] = mapped_column(String(1), default="F")  # A-F admiralty
    confidence_info: Mapped[str] = mapped_column(String(1), default="6")    # 1-6 admiralty
    tlp: Mapped[str] = mapped_column(String, default="WHITE")
    pyramid_tier: Mapped[str] = mapped_column(String, default="hash")
    context: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_url: Mapped[str | None] = mapped_column(String, nullable=True)
    technique_ids: Mapped[list] = mapped_column(JSON, default=list)
    actor_id: Mapped[str | None] = mapped_column(
        ForeignKey("threat_actors.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
