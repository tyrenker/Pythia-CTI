"""Sync log model to track the last run and status of each seed source."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from pythia.core.db import Base


class SyncLog(Base):
    __tablename__ = "sync_logs"

    source: Mapped[str] = mapped_column(String(50), primary_key=True)
    last_run: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="unknown")
