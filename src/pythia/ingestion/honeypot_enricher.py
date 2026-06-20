"""Background enrichment pipeline for HoneypotEvent records."""

from __future__ import annotations

import httpx

from pythia.core.config import get_settings
from pythia.core.db import SessionLocal
from pythia.models.honeypot import HoneypotEvent


def _enrich_geoip(event: HoneypotEvent) -> None:
    settings = get_settings()
    if not settings.maxmind_db_path:
        return
    try:
        import geoip2.database  # type: ignore[import-untyped]

        with geoip2.database.Reader(settings.maxmind_db_path) as reader:
            resp = reader.city(event.attacker_ip)
            event.attacker_country_code = resp.country.iso_code
    except Exception:
        pass


def _enrich_asn(event: HoneypotEvent) -> None:
    settings = get_settings()
    if not settings.maxmind_asn_db_path:
        return
    try:
        import geoip2.database  # type: ignore[import-untyped]

        with geoip2.database.Reader(settings.maxmind_asn_db_path) as reader:
            resp = reader.asn(event.attacker_ip)
            event.attacker_asn = str(resp.autonomous_system_number)
            event.attacker_org = resp.autonomous_system_organization
    except Exception:
        pass


def _enrich_abuseipdb(event: HoneypotEvent) -> None:
    settings = get_settings()
    if not settings.abuseipdb_api_key or event.abuseipdb_score is not None:
        return
    try:
        resp = httpx.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": event.attacker_ip, "maxAgeInDays": 90},
            headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            event.abuseipdb_score = data.get("abuseConfidenceScore")
    except Exception:
        pass


def _enrich_greynoise(event: HoneypotEvent) -> None:
    settings = get_settings()
    if not settings.greynoise_api_key or event.greynoise_classification is not None:
        return
    try:
        resp = httpx.get(
            f"https://api.greynoise.io/v3/community/{event.attacker_ip}",
            headers={"key": settings.greynoise_api_key, "Accept": "application/json"},
            timeout=10,
        )
        if resp.status_code == 200:
            event.greynoise_classification = resp.json().get("classification")
        elif resp.status_code == 404:
            event.greynoise_classification = "unknown"
    except Exception:
        pass


def _enrich_virustotal(event: HoneypotEvent) -> None:
    settings = get_settings()
    if not settings.virustotal_api_key or not event.payload_hash:
        return
    try:
        resp = httpx.get(
            f"https://www.virustotal.com/api/v3/files/{event.payload_hash}",
            headers={"x-apikey": settings.virustotal_api_key},
            timeout=10,
        )
        if resp.status_code == 200:
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            event.vt_detections = stats.get("malicious", 0)
    except Exception:
        pass


def enrich_event(event_id: str) -> None:
    """Run the full enrichment pipeline for one event. Called as a background task."""
    from datetime import datetime

    with SessionLocal() as session:
        event = session.get(HoneypotEvent, event_id)
        if event is None:
            return
        _enrich_geoip(event)
        _enrich_asn(event)
        _enrich_abuseipdb(event)
        _enrich_greynoise(event)
        _enrich_virustotal(event)
        event.enriched_at = datetime.utcnow()
        session.commit()
