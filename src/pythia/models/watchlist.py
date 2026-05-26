"""Watchlist subscription model for webhook alerting."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from pythia.core.db import Base


class Watchlist(Base):
    __tablename__ = "watchlists"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String, index=True)
    # At least one filter must be set; all non-null filters are ANDed
    filter_actor: Mapped[str | None] = mapped_column(String, nullable=True)   # name substring
    filter_ttp: Mapped[str | None] = mapped_column(String, nullable=True)      # technique ID
    filter_sector: Mapped[str | None] = mapped_column(String, nullable=True)   # sector substring
    webhook_url: Mapped[str] = mapped_column(String)
    webhook_type: Mapped[str] = mapped_column(String, default="slack")  # slack | discord | generic
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
