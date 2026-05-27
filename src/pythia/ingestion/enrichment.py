"""Actor enrichment: heuristic sophistication scoring and Claude-based TTP inference."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

from sqlalchemy import text
from sqlalchemy.orm import Session

if TYPE_CHECKING:
    from pythia.models.actor import ThreatActor

_SPONSOR_BASE: dict[str, int] = {
    "nation-state": 5,
    "financially-motivated": 3,
    "hacktivist": 2,
    "script-kiddie": 1,
    "unknown": 2,
}

_ADVANCED_TACTICS = frozenset(
    {
        "defense-evasion",
        "privilege-escalation",
        "lateral-movement",
        "collection",
        "exfiltration",
        "credential-access",
    }
)

_TECH_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

_INFER_SYSTEM = """\
You are a MITRE ATT&CK analyst. Given a threat actor profile, return the top 10 most
likely ATT&CK Enterprise technique IDs the actor is known or expected to use.

Rules:
- Only return technique IDs that appear in ATT&CK Enterprise (T followed by 4 digits,
  optionally .NNN for sub-techniques).
- Order by confidence descending.
- Return ONLY valid JSON: {"technique_ids": ["T1059.001", ...]}
- No explanations, no markdown fences.
"""


def compute_sophistication(
    sponsor_type: str,
    name: str,
    ttp_count: int,
    covered_tactics: set[str],
) -> int:
    """Return a 1-10 sophistication score from observable actor attributes."""
    score = _SPONSOR_BASE.get(sponsor_type, 2)

    if ttp_count >= 50:
        score += 2
    elif ttp_count >= 20:
        score += 1

    adv_hit = len(covered_tactics & _ADVANCED_TACTICS)
    if adv_hit >= 3:
        score += 2
    elif adv_hit >= 1:
        score += 1

    if len(covered_tactics) >= 7:
        score += 1

    if "apt" in name.lower():
        score += 1

    return max(1, min(10, score))


def rescore_actor(actor: ThreatActor, session: Session) -> int:
    """Compute and persist a fresh sophistication score for a single actor."""
    rows = session.execute(
        text("""
            SELECT at.tactics
            FROM actor_ttp_mappings m
            JOIN attck_techniques at ON at.technique_id = m.technique_id
            WHERE m.actor_id = :actor_id
        """),
        {"actor_id": actor.id},
    ).fetchall()

    covered: set[str] = set()
    for (tactics_val,) in rows:
        if isinstance(tactics_val, list):
            covered.update(tactics_val)
        elif isinstance(tactics_val, str):
            import contextlib
            with contextlib.suppress(Exception):
                covered.update(json.loads(tactics_val))

    score = compute_sophistication(
        sponsor_type=actor.sponsor_type,
        name=actor.name,
        ttp_count=len(actor.ttp_mappings),
        covered_tactics=covered,
    )
    actor.sophistication = score
    return score


def infer_ttps_from_description(actor: ThreatActor, session: Session) -> list[str]:
    """Ask Claude to infer ATT&CK technique IDs for an actor with a known description.

    Returns a list of technique ID strings (e.g. ["T1059", "T1566.001"]).
    Returns an empty list if the Anthropic key is not configured or the actor has
    no description to work from.
    """
    from pythia.core.config import get_settings

    settings = get_settings()
    if not settings.anthropic_api_key:
        return []
    if not actor.description:
        return []

    import anthropic

    profile_parts = [f"Name: {actor.name}"]
    if actor.sponsor_type:
        profile_parts.append(f"Sponsor: {actor.sponsor_type}")
    if actor.country_code:
        profile_parts.append(f"Origin: {actor.country_code}")
    if actor.sectors_targeted:
        profile_parts.append(f"Sectors targeted: {', '.join(actor.sectors_targeted[:10])}")
    profile_parts.append(f"\nDescription:\n{actor.description[:2000]}")

    client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
    try:
        msg = client.messages.create(
            model=settings.claude_model,
            max_tokens=512,
            system=_INFER_SYSTEM,
            messages=[{"role": "user", "content": "\n".join(profile_parts)}],
        )
        raw = msg.content[0].text.strip()  # type: ignore[union-attr]
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
            raw = raw.strip()
        data = json.loads(raw)
        ids: list[str] = data.get("technique_ids", [])
        # Validate format — only keep well-formed IDs
        return [t for t in ids if _TECH_ID_RE.fullmatch(t)]
    except Exception:
        return []
