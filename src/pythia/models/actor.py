"""Threat actor ORM model and Pydantic response schema."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from pythia.core.db import Base


class ThreatActor(Base):
    __tablename__ = "threat_actors"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String, unique=True, index=True)
    aliases: Mapped[list] = mapped_column(JSON, default=list)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    first_observed: Mapped[str | None] = mapped_column(String(10), nullable=True)  # YYYY or YYYY-MM-DD
    country_code: Mapped[str | None] = mapped_column(String(4), nullable=True)
    sponsor_type: Mapped[str] = mapped_column(String, default="unknown")
    motivations: Mapped[list] = mapped_column(JSON, default=list)
    sophistication: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sectors_targeted: Mapped[list] = mapped_column(JSON, default=list)
    geographies_targeted: Mapped[list] = mapped_column(JSON, default=list)
    infrastructure_patterns: Mapped[str | None] = mapped_column(Text, nullable=True)
    references: Mapped[list] = mapped_column(JSON, default=list)
    tlp: Mapped[str] = mapped_column(String, default="WHITE")
    attck_group_id: Mapped[str | None] = mapped_column(String(10), nullable=True, index=True)
    source: Mapped[str] = mapped_column(String, default="manual")
    source_url: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    ttp_mappings: Mapped[list[ActorTTPMapping]] = relationship(
        back_populates="actor", cascade="all, delete-orphan"
    )


class ActorTTPMapping(Base):
    __tablename__ = "actor_ttp_mappings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor_id: Mapped[str] = mapped_column(ForeignKey("threat_actors.id", ondelete="CASCADE"), index=True)
    technique_id: Mapped[str] = mapped_column(String, index=True)
    use_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String, default="attck")

    actor: Mapped[ThreatActor] = relationship(back_populates="ttp_mappings")
