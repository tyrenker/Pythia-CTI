"""ORM models for dark web forum monitoring."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from pythia.core.db import Base


class DarkWebForumSource(Base):
    __tablename__ = "dark_web_forum_sources"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String, nullable=False)
    onion_url: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    # ransomware | hacking | initial-access | data-leak | malware
    category: Mapped[str] = mapped_column(String, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    auto_ingest: Mapped[bool] = mapped_column(Boolean, default=False)
    poll_interval_h: Mapped[int] = mapped_column(Integer, default=4)
    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    post_count: Mapped[int] = mapped_column(Integer, default=0)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class DarkWebPost(Base):
    __tablename__ = "dark_web_posts"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    source_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    title: Mapped[str | None] = mapped_column(String, nullable=True)
    post_url: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    raw_content: Mapped[str | None] = mapped_column(Text, nullable=True)
    # queued | fetching | fetched | ingesting | done | failed | skipped
    status: Mapped[str] = mapped_column(String, default="queued", index=True)
    report_id: Mapped[str | None] = mapped_column(String, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    # Extracted metadata cached at ingest time
    victim_org: Mapped[str | None] = mapped_column(String, nullable=True)
    victim_sector: Mapped[str | None] = mapped_column(String, nullable=True)
    victim_country: Mapped[str | None] = mapped_column(String, nullable=True)
    threat_actor: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    tlp: Mapped[str] = mapped_column(String, default="WHITE")
    admiralty_code: Mapped[str] = mapped_column(String, default="E3")
