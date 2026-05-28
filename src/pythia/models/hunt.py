"""Threat hunt workbench ORM models."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from pythia.core.db import Base

# Mapping from obs_type to Pyramid of Pain tier.
OBS_TYPE_TO_PYRAMID: dict[str, str | None] = {
    "ioc_ip": "ip",
    "ioc_domain": "domain",
    "ioc_hash": "hash",
    "ioc_url": "artifact",
    "ioc_email": "artifact",
    "ioc_mutex": "artifact",
    "ioc_registry": "artifact",
    "ttp": "ttp",
    "tool": "tool",
    "actor": None,
    "sector": None,
    "motivation": None,
}


class HuntSession(Base):
    __tablename__ = "hunt_sessions"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String, index=True)
    hypothesis: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String, default="active")  # active | archived | closed
    analyst: Mapped[str | None] = mapped_column(String, nullable=True)
    sector_focus: Mapped[list] = mapped_column(JSON, default=list)
    motivation_focus: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    observations: Mapped[list[HuntObservation]] = relationship(
        back_populates="session", cascade="all, delete-orphan", order_by="HuntObservation.created_at"
    )
    note: Mapped[HuntNote | None] = relationship(
        back_populates="session", cascade="all, delete-orphan", uselist=False
    )
    detections: Mapped[list[HuntDraftDetection]] = relationship(
        back_populates="session", cascade="all, delete-orphan", order_by="HuntDraftDetection.created_at"
    )


class HuntObservation(Base):
    __tablename__ = "hunt_observations"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id: Mapped[str] = mapped_column(
        ForeignKey("hunt_sessions.id", ondelete="CASCADE"), index=True
    )
    obs_type: Mapped[str] = mapped_column(String)  # see OBS_TYPE_TO_PYRAMID keys
    value: Mapped[str] = mapped_column(String)
    pyramid_tier: Mapped[str | None] = mapped_column(String, nullable=True)
    confidence_source: Mapped[str] = mapped_column(String(1), default="F")  # Admiralty A-F
    confidence_info: Mapped[str] = mapped_column(String(1), default="6")    # Admiralty 1-6
    linked_record_id: Mapped[str | None] = mapped_column(String, nullable=True)  # UUID of matched DB record
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    session: Mapped[HuntSession] = relationship(back_populates="observations")


class HuntNote(Base):
    __tablename__ = "hunt_notes"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id: Mapped[str] = mapped_column(
        ForeignKey("hunt_sessions.id", ondelete="CASCADE"), unique=True, index=True
    )
    content: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    session: Mapped[HuntSession] = relationship(back_populates="note")


class HuntDraftDetection(Base):
    __tablename__ = "hunt_draft_detections"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id: Mapped[str] = mapped_column(
        ForeignKey("hunt_sessions.id", ondelete="CASCADE"), index=True
    )
    title: Mapped[str] = mapped_column(String)
    rule_type: Mapped[str] = mapped_column(String)  # sigma | kql | spl | yara | eql
    content: Mapped[str] = mapped_column(Text)
    pyramid_tier: Mapped[str] = mapped_column(String, default="ttp")
    linked_ttp_ids: Mapped[list] = mapped_column(JSON, default=list)
    linked_obs_ids: Mapped[list] = mapped_column(JSON, default=list)
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String, default="draft")  # draft | reviewed | promoted
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    session: Mapped[HuntSession] = relationship(back_populates="detections")
