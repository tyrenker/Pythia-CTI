"""Detection rule ORM model (Sigma / Yara)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from pythia.core.db import Base


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    rule_type: Mapped[str] = mapped_column(String, index=True)  # sigma | yara
    title: Mapped[str] = mapped_column(String, index=True)
    content: Mapped[str] = mapped_column(Text)
    technique_ids: Mapped[list] = mapped_column(JSON, default=list)
    actor_ids: Mapped[list] = mapped_column(JSON, default=list)
    severity: Mapped[str | None] = mapped_column(String, nullable=True)
    status: Mapped[str | None] = mapped_column(String, nullable=True)
    source: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    source_url: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
