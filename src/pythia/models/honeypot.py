"""ORM models for honeypot event ingestion, campaign tracking, and SIEM alerts."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from pythia.core.db import Base


class HoneypotEvent(Base):
    __tablename__ = "honeypot_events"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    honeypot_type: Mapped[str] = mapped_column(
        String, index=True
    )  # cowrie | dionaea | honeytrap | mailoney
    attacker_ip: Mapped[str] = mapped_column(String, index=True)
    attacker_asn: Mapped[str | None] = mapped_column(String, nullable=True)
    attacker_country_code: Mapped[str | None] = mapped_column(String, nullable=True)
    attacker_org: Mapped[str | None] = mapped_column(String, nullable=True)
    target_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String, nullable=True)
    event_timestamp: Mapped[datetime] = mapped_column(DateTime)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    tpot_session_id: Mapped[str | None] = mapped_column(String, nullable=True)
    username_attempted: Mapped[str | None] = mapped_column(String, nullable=True)
    password_attempted: Mapped[str | None] = mapped_column(String, nullable=True)
    commands_run: Mapped[list] = mapped_column(JSON, default=list)
    files_downloaded: Mapped[list] = mapped_column(JSON, default=list)
    payload_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    raw_payload: Mapped[dict] = mapped_column(JSON, default=dict)
    ttp_ids: Mapped[list] = mapped_column(JSON, default=list)
    campaign_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    enriched_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    abuseipdb_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    greynoise_classification: Mapped[str | None] = mapped_column(String, nullable=True)
    vt_detections: Mapped[int | None] = mapped_column(Integer, nullable=True)


class HoneypotCampaign(Base):
    __tablename__ = "honeypot_campaigns"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String)  # CAMPAIGN-2026-001
    status: Mapped[str] = mapped_column(String, default="active")  # active | dormant | archived
    first_seen: Mapped[datetime] = mapped_column(DateTime)
    last_seen: Mapped[datetime] = mapped_column(DateTime)
    attacker_ips: Mapped[list] = mapped_column(JSON, default=list)
    asns: Mapped[list] = mapped_column(JSON, default=list)
    ttp_ids: Mapped[list] = mapped_column(JSON, default=list)
    payload_hashes: Mapped[list] = mapped_column(JSON, default=list)
    credential_patterns: Mapped[dict] = mapped_column(JSON, default=dict)
    target_ports: Mapped[list] = mapped_column(JSON, default=list)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    sigma_rule_id: Mapped[str | None] = mapped_column(String, nullable=True)
    report_id: Mapped[str | None] = mapped_column(String, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class SiemAlert(Base):
    __tablename__ = "siem_alerts"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    siem_source: Mapped[str] = mapped_column(String)  # wazuh | splunk | elastic
    external_alert_id: Mapped[str | None] = mapped_column(String, nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String, nullable=True)
    campaign_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    severity: Mapped[str] = mapped_column(String)  # critical | high | medium | low | info
    title: Mapped[str] = mapped_column(String)
    raw_event: Mapped[dict] = mapped_column(JSON, default=dict)
    attacker_ip: Mapped[str | None] = mapped_column(String, nullable=True)
    mitre_techniques: Mapped[list] = mapped_column(JSON, default=list)
    triage_status: Mapped[str] = mapped_column(String, default="new", index=True)
    analyst_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    triaged_by: Mapped[str | None] = mapped_column(String, nullable=True)
    triaged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
