"""Honeypot daily summary and campaign CTI report generation."""

from __future__ import annotations

import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session


def generate_daily_honeypot_report(session: Session) -> str:
    """Build a 24h honeypot summary and store as a SourceReport. Returns report ID."""
    from pythia.models.honeypot import HoneypotCampaign, HoneypotEvent
    from pythia.models.report import SourceReport

    now = datetime.now(UTC).replace(tzinfo=None)
    cutoff = now - timedelta(hours=24)

    events = session.query(HoneypotEvent).filter(HoneypotEvent.received_at >= cutoff).all()
    new_campaigns = (
        session.query(HoneypotCampaign).filter(HoneypotCampaign.created_at >= cutoff).all()
    )

    ip_counts: Counter[str] = Counter(e.attacker_ip for e in events)
    port_counts: Counter[int] = Counter(e.target_port for e in events if e.target_port)
    type_counts: Counter[str] = Counter(e.honeypot_type for e in events)
    country_counts: Counter[str] = Counter(
        e.attacker_country_code for e in events if e.attacker_country_code
    )
    cred_counts: Counter[str] = Counter(
        e.username_attempted for e in events if e.username_attempted
    )
    all_payload_hashes = list({e.payload_hash for e in events if e.payload_hash})

    parsed_data: dict[str, Any] = {
        "report_type": "honeypot_daily",
        "generated_at": now.isoformat(),
        "period_hours": 24,
        "event_count": len(events),
        "unique_attackers": len(ip_counts),
        "new_campaigns": len(new_campaigns),
        "new_payload_hashes": len(all_payload_hashes),
        "top_ips": ip_counts.most_common(10),
        "top_ports": [(str(p), c) for p, c in port_counts.most_common(5)],
        "top_countries": country_counts.most_common(10),
        "top_usernames": cred_counts.most_common(10),
        "by_honeypot_type": dict(type_counts),
        "new_campaign_names": [c.name for c in new_campaigns],
        "payload_hashes": all_payload_hashes[:20],
    }

    report = SourceReport(
        id=str(uuid.uuid4()),
        title=f"Honeypot Daily Summary — {now.strftime('%Y-%m-%d')}",
        status="accepted",
        tlp="WHITE",
        parsed_data=parsed_data,
        created_at=now,
    )
    session.add(report)
    session.commit()
    return report.id


def generate_campaign_report(session: Session, campaign_id: str) -> str:
    """Use Claude to write a campaign CTI report. Returns report ID."""
    from pythia.core.config import get_settings
    from pythia.models.honeypot import HoneypotCampaign, HoneypotEvent
    from pythia.models.report import SourceReport

    settings = get_settings()
    campaign = session.get(HoneypotCampaign, campaign_id)
    if campaign is None:
        raise ValueError(f"Campaign {campaign_id} not found")

    # Sample commands observed (Cowrie)
    sample_events = (
        session.query(HoneypotEvent)
        .filter(HoneypotEvent.campaign_id == campaign_id)
        .filter(HoneypotEvent.commands_run != [])
        .limit(20)
        .all()
    )
    all_commands: list[str] = []
    for ev in sample_events:
        all_commands.extend(ev.commands_run or [])

    report_text: str
    if settings.anthropic_api_key:
        import anthropic

        client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
        prompt = (
            f"You are a senior threat intelligence analyst. Write a structured CTI report "
            f"for the following honeypot campaign. Use professional CTI language.\n\n"
            f"Campaign: {campaign.name}\n"
            f"Status: {campaign.status}\n"
            f"First seen: {campaign.first_seen.strftime('%Y-%m-%d')}\n"
            f"Last seen: {campaign.last_seen.strftime('%Y-%m-%d')}\n"
            f"Event count: {campaign.event_count}\n"
            f"Source IPs ({len(campaign.attacker_ips or [])} total): "
            f"{', '.join((campaign.attacker_ips or [])[:10])}\n"
            f"ASNs: {', '.join(campaign.asns or [])}\n"
            f"MITRE ATT&CK techniques: {', '.join(campaign.ttp_ids or [])}\n"
            f"Target ports: {', '.join(str(p) for p in (campaign.target_ports or []))}\n"
            f"Credential patterns — usernames: "
            f"{(campaign.credential_patterns or {}).get('usernames', [])[:5]}\n"
            f"Sample commands observed: {all_commands[:10]}\n\n"
            f"Write a 3-5 page CTI report with these sections:\n"
            f"1. Executive Summary (3 sentences)\n"
            f"2. Infrastructure Analysis (ASNs, hosting patterns, IP ranges)\n"
            f"3. TTP Breakdown (map observed TTPs to MITRE ATT&CK)\n"
            f"4. IOC List (IPs, payload hashes if any)\n"
            f"5. Detection Recommendations\n"
            f"6. Confidence and TLP markings\n"
            f"TLP: WHITE. Confidence: B2 (probably true, source not fully reliable)."
        )
        msg = client.messages.create(
            model=settings.claude_model,
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}],
        )
        report_text = msg.content[0].text if msg.content else _fallback_campaign_report(campaign)
    else:
        report_text = _fallback_campaign_report(campaign)

    parsed_data: dict[str, Any] = {
        "report_type": "campaign_intel",
        "campaign_id": campaign.id,
        "campaign_name": campaign.name,
        "generated_at": datetime.utcnow().isoformat(),
        "summary": report_text[:500],
        "full_report": report_text,
        "ttps": [{"technique_id": t} for t in (campaign.ttp_ids or [])],
        "iocs": [{"type": "ip", "value": ip} for ip in (campaign.attacker_ips or [])[:50]],
        "confidence_admiralty": "B2",
        "event_count": campaign.event_count,
        "attacker_ips": campaign.attacker_ips or [],
        "asns": campaign.asns or [],
    }

    report = SourceReport(
        id=str(uuid.uuid4()),
        title=f"Campaign Intelligence Report — {campaign.name}",
        status="accepted",
        tlp="WHITE",
        parsed_data=parsed_data,
        created_at=datetime.utcnow(),
    )
    session.add(report)
    campaign.report_id = report.id
    session.commit()
    return report.id


def _fallback_campaign_report(campaign: Any) -> str:
    return (
        f"# Campaign Intelligence Report: {campaign.name}\n\n"
        f"**Status:** {campaign.status}\n"
        f"**Period:** {campaign.first_seen.strftime('%Y-%m-%d')} — {campaign.last_seen.strftime('%Y-%m-%d')}\n"
        f"**Events:** {campaign.event_count}\n"
        f"**Unique IPs:** {len(campaign.attacker_ips or [])}\n"
        f"**ASNs:** {', '.join(campaign.asns or []) or 'Unknown'}\n\n"
        f"## TTPs Observed\n" + "\n".join(f"- {t}" for t in (campaign.ttp_ids or [])) + "\n\n"
        "## IOCs\n" + "\n".join(f"- {ip}" for ip in (campaign.attacker_ips or [])[:20]) + "\n\n"
        "**TLP:** WHITE | **Confidence:** B2\n"
    )
