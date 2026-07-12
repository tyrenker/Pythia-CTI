"""Find-or-create threat actors during article ingestion and enrich via Claude."""

from __future__ import annotations

import json
import logging
import uuid
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from pythia.models.actor import ActorTTPMapping, ThreatActor

logger = logging.getLogger(__name__)

_ENRICH_PROMPT_PATH = Path(__file__).parent / "prompts" / "enrich_actor_prompt.md"
_ENRICH_SYSTEM_PROMPT = _ENRICH_PROMPT_PATH.read_text()


def _find_existing_actor(name: str, aliases: list[str], session: Session) -> ThreatActor | None:
    """Look up an actor by exact name, case-insensitive name, or alias overlap."""
    # 1. Exact name match (case-insensitive)
    actor = session.query(ThreatActor).filter(ThreatActor.name.ilike(name)).first()
    if actor:
        return actor

    # 2. Check if any provided alias matches an existing actor name
    for alias in aliases:
        actor = session.query(ThreatActor).filter(ThreatActor.name.ilike(alias)).first()
        if actor:
            return actor

    # 3. Check if the name appears in any existing actor's aliases JSON
    all_actors = session.query(ThreatActor).all()
    name_lower = name.lower()
    for actor in all_actors:
        existing_aliases = [a.lower() for a in (actor.aliases or [])]
        if name_lower in existing_aliases:
            return actor
        for alias in aliases:
            if alias.lower() in existing_aliases:
                return actor

    return None


def _enrich_actor_via_claude(
    name: str,
    aliases: list[str],
    parsed_data: dict[str, Any],
) -> dict[str, Any] | None:
    """Call Claude to produce a rich actor profile. Returns None if API key missing or call fails."""
    from pythia.core.config import get_settings

    settings = get_settings()
    if not settings.anthropic_api_key:
        return None

    import anthropic

    # Build context from the parsed article data
    context_parts = []
    if parsed_data.get("title"):
        context_parts.append(f"Article: {parsed_data['title']}")
    if parsed_data.get("summary"):
        context_parts.append(f"Summary: {parsed_data['summary']}")
    business_impact = parsed_data.get("business_impact_draft", {})
    if isinstance(business_impact, dict) and business_impact.get("operational"):
        context_parts.append(f"Impact: {business_impact['operational']}")

    ttps = [t.get("technique_id", "") for t in (parsed_data.get("ttps") or []) if t.get("technique_id")]

    payload = {
        "name": name,
        "aliases": aliases,
        "context": "\n".join(context_parts),
        "ttps": ttps,
        "sectors_targeted": parsed_data.get("sectors_targeted") or [],
        "geographies_targeted": parsed_data.get("geographies_targeted") or [],
    }

    client = anthropic.Anthropic(api_key=settings.anthropic_api_key)

    try:
        message = client.messages.create(
            model=settings.claude_model,
            max_tokens=2048,
            system=_ENRICH_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": json.dumps(payload, indent=2)}],
        )

        raw = message.content[0].text.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
            raw = raw.strip()

        return json.loads(raw)
    except Exception as exc:
        logger.warning("Claude actor enrichment failed for '%s': %s", name, exc)
        return None


def _update_actor_from_enrichment(actor: ThreatActor, enriched: dict[str, Any]) -> None:
    """Apply enriched fields to an actor, only filling in blanks (not overwriting)."""
    if not actor.description and enriched.get("description"):
        actor.description = enriched["description"]
    if not actor.country_code and enriched.get("country_code"):
        actor.country_code = enriched["country_code"]
    if actor.sponsor_type == "unknown" and enriched.get("sponsor_type", "unknown") != "unknown":
        actor.sponsor_type = enriched["sponsor_type"]
    if not actor.motivations and enriched.get("motivations"):
        actor.motivations = enriched["motivations"]
    if not actor.first_observed and enriched.get("first_observed"):
        actor.first_observed = enriched["first_observed"]
    if not actor.infrastructure_patterns and enriched.get("infrastructure_patterns"):
        actor.infrastructure_patterns = enriched["infrastructure_patterns"]
    if not actor.attck_group_id and enriched.get("attck_group_id"):
        actor.attck_group_id = enriched["attck_group_id"]

    # Merge lists (deduplicate)
    if enriched.get("aliases"):
        existing = set(a.lower() for a in (actor.aliases or []))
        merged = list(actor.aliases or [])
        for alias in enriched["aliases"]:
            if alias.lower() not in existing and alias.lower() != actor.name.lower():
                merged.append(alias)
                existing.add(alias.lower())
        actor.aliases = merged

    if enriched.get("sectors_targeted"):
        existing = set(s.lower() for s in (actor.sectors_targeted or []))
        merged = list(actor.sectors_targeted or [])
        for s in enriched["sectors_targeted"]:
            if s.lower() not in existing:
                merged.append(s)
                existing.add(s.lower())
        actor.sectors_targeted = merged

    if enriched.get("geographies_targeted"):
        existing = set(g.lower() for g in (actor.geographies_targeted or []))
        merged = list(actor.geographies_targeted or [])
        for g in enriched["geographies_targeted"]:
            if g.lower() not in existing:
                merged.append(g)
                existing.add(g.lower())
        actor.geographies_targeted = merged

    if enriched.get("references"):
        existing = set(actor.references or [])
        merged = list(actor.references or [])
        for ref in enriched["references"]:
            if ref not in existing:
                merged.append(ref)
                existing.add(ref)
        actor.references = merged


def link_actors_from_report(
    session: Session,
    parsed_data: dict[str, Any],
    *,
    report_url: str | None = None,
) -> list[str]:
    """Find or create ThreatActor entries for each actor in parsed_data.

    For new actors, enriches the profile via Claude and links extracted TTPs.
    Returns a list of actor IDs that were linked.
    """
    from pythia.ingestion.enrichment import rescore_actor

    actors_data = parsed_data.get("actors") or []
    if not actors_data:
        return []

    ttps_data = parsed_data.get("ttps") or []
    linked_ids: list[str] = []

    for actor_entry in actors_data:
        name = actor_entry.get("name", "").strip()
        if not name:
            continue

        aliases = actor_entry.get("aliases") or []

        # Check if actor already exists
        existing = _find_existing_actor(name, aliases, session)

        if existing:
            logger.info("Actor '%s' already exists (id=%s), updating with new intel", name, existing.id)

            # Merge new aliases
            existing_aliases_lower = set(a.lower() for a in (existing.aliases or []))
            merged_aliases = list(existing.aliases or [])
            for alias in aliases:
                if alias.lower() not in existing_aliases_lower and alias.lower() != existing.name.lower():
                    merged_aliases.append(alias)
                    existing_aliases_lower.add(alias.lower())
            if merged_aliases != (existing.aliases or []):
                existing.aliases = merged_aliases

            # Merge sectors from this article
            article_sectors = parsed_data.get("sectors_targeted") or []
            if article_sectors:
                existing_sectors_lower = set(s.lower() for s in (existing.sectors_targeted or []))
                merged_sectors = list(existing.sectors_targeted or [])
                for s in article_sectors:
                    if s.lower() not in existing_sectors_lower:
                        merged_sectors.append(s)
                        existing_sectors_lower.add(s.lower())
                existing.sectors_targeted = merged_sectors

            # Add new TTPs from this article
            existing_ttp_ids = {m.technique_id for m in existing.ttp_mappings}
            for ttp in ttps_data:
                tid = ttp.get("technique_id", "")
                if tid and tid not in existing_ttp_ids:
                    session.add(ActorTTPMapping(
                        actor_id=existing.id,
                        technique_id=tid,
                        use_note=ttp.get("evidence"),
                        source="article-ingestion",
                    ))
                    existing_ttp_ids.add(tid)

            # Add report URL to references if not already there
            if report_url:
                refs = list(existing.references or [])
                if report_url not in refs:
                    refs.append(report_url)
                    existing.references = refs

            session.flush()
            rescore_actor(existing, session)
            linked_ids.append(existing.id)
        else:
            logger.info("Creating new actor: '%s'", name)

            # Create the actor with basic info from the article
            actor = ThreatActor(
                id=str(uuid.uuid4()),
                name=name,
                aliases=aliases,
                sponsor_type="unknown",
                sectors_targeted=parsed_data.get("sectors_targeted") or [],
                geographies_targeted=parsed_data.get("geographies_targeted") or [],
                source="article-ingestion",
                source_url=report_url,
                references=[report_url] if report_url else [],
            )
            session.add(actor)
            session.flush()

            # Link TTPs from the article
            for ttp in ttps_data:
                tid = ttp.get("technique_id", "")
                if tid:
                    session.add(ActorTTPMapping(
                        actor_id=actor.id,
                        technique_id=tid,
                        use_note=ttp.get("evidence"),
                        source="article-ingestion",
                    ))
            session.flush()

            # Enrich via Claude
            enriched = _enrich_actor_via_claude(name, aliases, parsed_data)
            if enriched:
                _update_actor_from_enrichment(actor, enriched)
                session.flush()

            # Score sophistication
            rescore_actor(actor, session)
            linked_ids.append(actor.id)

    return linked_ids
