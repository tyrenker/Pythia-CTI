"""Campaign clustering job — groups related honeypot attack events."""

from __future__ import annotations

import contextlib
import uuid
from collections import Counter
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from pythia.core.db import SessionLocal
from pythia.models.honeypot import HoneypotCampaign, HoneypotEvent


def _campaign_counter(session: Session) -> int:
    return session.query(HoneypotCampaign).count()


def _next_campaign_name(session: Session) -> str:
    year = datetime.utcnow().year
    n = _campaign_counter(session) + 1
    return f"CAMPAIGN-{year}-{n:03d}"


def _merge_groups(
    groups: list[list[HoneypotEvent]],
) -> list[list[HoneypotEvent]]:
    """Merge groups that share ASN or ≥50% payload hash overlap."""
    merged: list[list[HoneypotEvent]] = []
    used = [False] * len(groups)
    for i, g1 in enumerate(groups):
        if used[i]:
            continue
        combined = list(g1)
        asns1 = {e.attacker_asn for e in g1 if e.attacker_asn}
        hashes1 = {h for e in g1 for h in (e.payload_hash,) if h}
        for j, g2 in enumerate(groups):
            if i == j or used[j]:
                continue
            asns2 = {e.attacker_asn for e in g2 if e.attacker_asn}
            hashes2 = {h for e in g2 for h in (e.payload_hash,) if h}
            creds1 = Counter(e.username_attempted for e in g1 if e.username_attempted)
            creds2 = Counter(e.username_attempted for e in g2 if e.username_attempted)
            top1 = set(k for k, _ in creds1.most_common(5))
            top2 = set(k for k, _ in creds2.most_common(5))
            share_asn = bool(asns1 & asns2)
            hash_overlap = (
                len(hashes1 & hashes2) / max(len(hashes1 | hashes2), 1) >= 0.5
                if hashes1 or hashes2
                else False
            )
            share_creds = bool(top1 & top2) if top1 and top2 else False
            if share_asn or hash_overlap or share_creds:
                combined.extend(g2)
                used[j] = True
        used[i] = True
        merged.append(combined)
    return merged


def detect_campaigns(session: Session) -> int:
    """Cluster uncampaigned events and create/extend campaigns. Returns new campaign count."""
    cutoff = datetime.utcnow() - timedelta(hours=48)
    uncampaigned = (
        session.query(HoneypotEvent)
        .filter(HoneypotEvent.campaign_id.is_(None))
        .filter(HoneypotEvent.event_timestamp >= cutoff)
        .all()
    )
    if not uncampaigned:
        return 0

    by_ip: dict[str, list[HoneypotEvent]] = {}
    for ev in uncampaigned:
        by_ip.setdefault(ev.attacker_ip, []).append(ev)

    # Only IPs with ≥3 events are candidates
    candidate_groups = [evs for evs in by_ip.values() if len(evs) >= 3]
    if not candidate_groups:
        return 0

    merged_groups = _merge_groups(candidate_groups)
    created = 0
    for group in merged_groups:
        if len(group) < 5:
            continue

        all_ips = list({e.attacker_ip for e in group})
        all_asns = list({e.attacker_asn for e in group if e.attacker_asn})
        all_ttps = list({t for e in group for t in (e.ttp_ids or [])})
        all_hashes = list({e.payload_hash for e in group if e.payload_hash})
        all_ports = list({e.target_port for e in group if e.target_port})
        usernames = [e.username_attempted for e in group if e.username_attempted]
        passwords = [e.password_attempted for e in group if e.password_attempted]
        cred_patterns = {
            "usernames": list(set(usernames))[:20],
            "passwords": list(set(passwords))[:20],
        }
        first_seen = min(e.event_timestamp for e in group)
        last_seen = max(e.event_timestamp for e in group)

        # Check if any IP in the group already has a campaign
        existing_campaign_ids = {e.campaign_id for e in group if e.campaign_id}
        if existing_campaign_ids:
            campaign_id = next(iter(existing_campaign_ids))
            campaign = session.get(HoneypotCampaign, campaign_id)
            if campaign:
                existing_ips = set(campaign.attacker_ips or [])
                existing_ips.update(all_ips)
                campaign.attacker_ips = list(existing_ips)
                existing_asns = set(campaign.asns or [])
                existing_asns.update(all_asns)
                campaign.asns = list(existing_asns)
                existing_ttps = set(campaign.ttp_ids or [])
                existing_ttps.update(all_ttps)
                campaign.ttp_ids = list(existing_ttps)
                campaign.last_seen = max(campaign.last_seen, last_seen)
                campaign.event_count += len(group)
                campaign.updated_at = datetime.utcnow()
                for ev in group:
                    ev.campaign_id = campaign.id
                session.commit()
                _post_campaign_actions(session, campaign)
                continue

        campaign = HoneypotCampaign(
            id=str(uuid.uuid4()),
            name=_next_campaign_name(session),
            status="active",
            first_seen=first_seen,
            last_seen=last_seen,
            attacker_ips=all_ips,
            asns=all_asns,
            ttp_ids=all_ttps,
            payload_hashes=all_hashes,
            credential_patterns=cred_patterns,
            target_ports=[int(p) for p in all_ports],
            event_count=len(group),
        )
        session.add(campaign)
        session.flush()
        for ev in group:
            ev.campaign_id = campaign.id
        session.commit()
        _post_campaign_actions(session, campaign)
        created += 1

    return created


def _post_campaign_actions(session: Session, campaign: HoneypotCampaign) -> None:
    """Auto-generate Sigma rule and IOCs for a campaign."""
    with contextlib.suppress(Exception):
        from pythia.detections.honeypot_sigma import auto_generate_campaign_sigma

        auto_generate_campaign_sigma(session, campaign)
    with contextlib.suppress(Exception):
        _auto_create_iocs(session, campaign)


def _auto_create_iocs(session: Session, campaign: HoneypotCampaign) -> None:
    """Add high-confidence attacker IPs as IOC records."""
    import uuid as _uuid

    from pythia.models.ioc import IoC

    high_confidence_ips = (
        session.query(HoneypotEvent.attacker_ip)
        .filter(HoneypotEvent.campaign_id == campaign.id)
        .filter(HoneypotEvent.abuseipdb_score >= 70)
        .distinct()
        .all()
    )
    for (ip,) in high_confidence_ips:
        existing = session.query(IoC).filter_by(value=ip, type="ip").first()
        if existing:
            continue
        ioc = IoC(
            id=str(_uuid.uuid4()),
            type="ip",
            value=ip,
            tlp="WHITE",
            pyramid_tier="ip",
            context=f"honeypot:{campaign.name}",
        )
        session.add(ioc)
    session.commit()


def run_campaign_detection() -> None:
    """Entry point for the scheduler."""
    with SessionLocal() as session:
        detect_campaigns(session)
