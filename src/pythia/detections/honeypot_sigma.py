"""Auto-generate Sigma detection rules from honeypot campaign data."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy.orm import Session

from pythia.models.honeypot import HoneypotCampaign
from pythia.models.rule import DetectionRule

_SIGMA_TEMPLATE = """\
title: "Honeypot Campaign {name} - Activity"
id: {rule_uuid}
status: experimental
description: |
  First-party detection from Pythia honeypot collection.
  {event_count} events observed, {ip_count} source IPs.
  ASNs: {asns}.
  First seen: {first_seen}. Last seen: {last_seen}.
references:
  - "pythia://campaigns/{campaign_id}"
logsource:
  category: network_connection
detection:
  selection:
    src_ip|contains:{ip_list}
  condition: selection
falsepositives:
  - Legitimate security scanners
level: {severity}
tags:{tag_list}
"""


def _severity_from_count(count: int) -> str:
    if count < 20:
        return "low"
    if count < 100:
        return "medium"
    if count < 500:
        return "high"
    return "critical"


def generate_ip_sigma(campaign: HoneypotCampaign) -> str:
    ips = (campaign.attacker_ips or [])[:30]
    ip_lines = "".join(f'\n      - "{ip}"' for ip in ips)
    ttp_ids = campaign.ttp_ids or []
    tag_lines = (
        "".join(f'\n  - "attack.{t.lower().replace(".", "_")}"' for t in ttp_ids)
        if ttp_ids
        else "\n  - honeypot"
    )
    asns = ", ".join(campaign.asns or []) or "unknown"
    return _SIGMA_TEMPLATE.format(
        name=campaign.name,
        rule_uuid=str(uuid.uuid4()),
        event_count=campaign.event_count,
        ip_count=len(campaign.attacker_ips or []),
        asns=asns,
        first_seen=campaign.first_seen.date(),
        last_seen=campaign.last_seen.date(),
        campaign_id=campaign.id,
        ip_list=ip_lines,
        severity=_severity_from_count(campaign.event_count),
        tag_list=tag_lines,
    )


def generate_behavioral_sigma(campaign: HoneypotCampaign) -> str | None:
    """Use Claude to generate a behavioral Sigma rule. Returns None if no API key."""
    from pythia.core.config import get_settings

    settings = get_settings()
    if not settings.anthropic_api_key:
        return None
    try:
        import anthropic

        client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
        sample_ttps = (campaign.ttp_ids or [])[:10]
        creds = campaign.credential_patterns or {}
        prompt = (
            f"Generate a Sigma detection rule (YAML) for a honeypot campaign with these characteristics:\n"
            f"- MITRE ATT&CK techniques: {sample_ttps}\n"
            f"- Top attempted usernames: {(creds.get('usernames') or [])[:5]}\n"
            f"- Event count: {campaign.event_count}\n"
            f"- Campaign name: {campaign.name}\n\n"
            f"Write a BEHAVIORAL rule targeting process or command-level detection, NOT IP addresses.\n"
            f"Output only valid Sigma YAML."
        )
        msg = client.messages.create(
            model=settings.claude_model,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        return msg.content[0].text if msg.content else None
    except Exception:
        return None


def auto_generate_campaign_sigma(session: Session, campaign: HoneypotCampaign) -> str | None:
    """Generate and save a Sigma rule for a campaign. Returns the DetectionRule ID."""
    if campaign.sigma_rule_id:
        return campaign.sigma_rule_id

    if campaign.event_count >= 50:
        content = generate_behavioral_sigma(campaign) or generate_ip_sigma(campaign)
    else:
        content = generate_ip_sigma(campaign)

    severity = _severity_from_count(campaign.event_count)
    rule = DetectionRule(
        id=str(uuid.uuid4()),
        rule_type="sigma",
        title=f"Honeypot: {campaign.name}",
        content=content,
        technique_ids=campaign.ttp_ids or [],
        severity=severity,
        status="active",
        source="honeypot",
        created_at=datetime.utcnow(),
    )
    session.add(rule)
    campaign.sigma_rule_id = rule.id
    session.commit()
    return rule.id
