"""Export Pythia entities to STIX 2.1 JSON bundles.

Implements STIX 2.1 (https://docs.oasis-open.org/cti/stix/v2.1/) without the
stix2 library so we avoid a heavy dependency for a read-only exporter.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import UTC, datetime
from typing import Any


def _now_utc() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _fmt_dt(dt: datetime | None) -> str:
    if dt is None:
        return _now_utc()
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _bundle(*objects: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "bundle",
        "id": f"bundle--{_uuid.uuid4()}",
        "objects": list(objects),
    }


# Maps Pythia sponsor_type → STIX threat-actor-type vocabulary
_SPONSOR_TO_STIX: dict[str, str] = {
    "nation-state": "nation-state",
    "financially-motivated": "crime-syndicate",
    "hacktivist": "activist",
    "script-kiddie": "hacker",
    "unknown": "unknown",
}

# Maps Pythia IoC type → STIX pattern prefix
_IOC_PATTERN: dict[str, str] = {
    "ip": "[ipv4-addr:value = '{value}']",
    "domain": "[domain-name:value = '{value}']",
    "url": "[url:value = '{value}']",
    "md5": "[file:hashes.MD5 = '{value}']",
    "sha1": "[file:hashes.SHA-1 = '{value}']",
    "sha256": "[file:hashes.'SHA-256' = '{value}']",
    "hash": "[file:hashes.'SHA-256' = '{value}']",
    "email": "[email-addr:value = '{value}']",
    "mutex": "[mutex:name = '{value}']",
    "file": "[file:name = '{value}']",
    "registry": "[windows-registry-key:key = '{value}']",
    "cve": "[vulnerability:name = '{value}']",
}


def export_actor(actor: Any) -> dict[str, Any]:
    """Return a STIX 2.1 bundle for a ThreatActor ORM object.

    Includes the threat-actor SDO and one attack-pattern SDO per known TTP.
    """
    stix_actor: dict[str, Any] = {
        "type": "threat-actor",
        "spec_version": "2.1",
        "id": f"threat-actor--{actor.id}",
        "created": _fmt_dt(actor.created_at),
        "modified": _fmt_dt(getattr(actor, "updated_at", None) or actor.created_at),
        "name": actor.name,
        "labels": ["threat-actor"],
    }

    if actor.aliases:
        stix_actor["aliases"] = actor.aliases
    if actor.description:
        stix_actor["description"] = actor.description
    if actor.sponsor_type and actor.sponsor_type != "unknown":
        stix_actor["threat_actor_types"] = [_SPONSOR_TO_STIX.get(actor.sponsor_type, actor.sponsor_type)]
    if actor.motivations:
        stix_actor["primary_motivation"] = actor.motivations[0]
        if len(actor.motivations) > 1:
            stix_actor["secondary_motivations"] = actor.motivations[1:]
    if actor.sophistication:
        levels = {1: "minimal", 2: "intermediate", 3: "advanced", 4: "expert", 5: "innovator"}
        stix_actor["sophistication"] = levels.get(actor.sophistication, "unknown")

    objects: list[dict[str, Any]] = [stix_actor]

    # Emit one attack-pattern SDO per TTP mapping with MITRE ATT&CK external ref
    for mapping in actor.ttp_mappings:
        tech_id: str = mapping.technique_id
        attack_pattern: dict[str, Any] = {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": f"attack-pattern--{_uuid.uuid5(_uuid.NAMESPACE_URL, tech_id)}",
            "created": _now_utc(),
            "modified": _now_utc(),
            "name": tech_id,
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": tech_id,
                    "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}",
                }
            ],
        }
        if mapping.use_note:
            attack_pattern["description"] = mapping.use_note

        # Relationship: threat-actor uses attack-pattern
        rel: dict[str, Any] = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{_uuid.uuid5(_uuid.NAMESPACE_URL, actor.id + tech_id)}",
            "created": _now_utc(),
            "modified": _now_utc(),
            "relationship_type": "uses",
            "source_ref": stix_actor["id"],
            "target_ref": attack_pattern["id"],
        }
        objects.extend([attack_pattern, rel])

    return _bundle(*objects)


def export_ioc(ioc: Any) -> dict[str, Any]:
    """Return a STIX 2.1 bundle for a single IoC ORM object."""
    ioc_type: str = (ioc.type or "").lower()
    pattern_tmpl = _IOC_PATTERN.get(ioc_type, "[artifact:payload_bin = '{value}']")
    pattern = pattern_tmpl.format(value=ioc.value.replace("'", "\\'"))

    indicator: dict[str, Any] = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{ioc.id}",
        "created": _fmt_dt(ioc.created_at),
        "modified": _fmt_dt(ioc.created_at),
        "name": f"{ioc.type}:{ioc.value}",
        "indicator_types": ["malicious-activity"],
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": _fmt_dt(ioc.first_seen or ioc.created_at),
        "labels": [f"tlp:{ioc.tlp.lower()}", f"pyramid-of-pain:{ioc.pyramid_tier}"],
    }

    if ioc.context:
        indicator["description"] = ioc.context

    admiralty = f"{ioc.confidence_source}{ioc.confidence_info}"
    indicator["confidence"] = _admiralty_to_stix_confidence(admiralty)

    return _bundle(indicator)


def export_iocs(iocs: list[Any]) -> dict[str, Any]:
    """Return a STIX 2.1 bundle for a list of IoC ORM objects."""
    objects: list[dict[str, Any]] = []
    for ioc in iocs:
        ioc_type: str = (ioc.type or "").lower()
        pattern_tmpl = _IOC_PATTERN.get(ioc_type, "[artifact:payload_bin = '{value}']")
        pattern = pattern_tmpl.format(value=ioc.value.replace("'", "\\'"))

        indicator: dict[str, Any] = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{ioc.id}",
            "created": _fmt_dt(ioc.created_at),
            "modified": _fmt_dt(ioc.created_at),
            "name": f"{ioc.type}:{ioc.value}",
            "indicator_types": ["malicious-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": _fmt_dt(ioc.first_seen or ioc.created_at),
            "labels": [f"tlp:{ioc.tlp.lower()}", f"pyramid-of-pain:{ioc.pyramid_tier}"],
        }
        if ioc.context:
            indicator["description"] = ioc.context
        indicator["confidence"] = _admiralty_to_stix_confidence(
            f"{ioc.confidence_source}{ioc.confidence_info}"
        )
        objects.append(indicator)

    return _bundle(*objects)


def _admiralty_to_stix_confidence(code: str) -> int:
    """Convert NATO Admiralty Code (A1-F6) to STIX confidence integer (0-100)."""
    # Source reliability A=100 → F=0; info credibility 1=100 → 6=0
    source_score = {"A": 100, "B": 80, "C": 60, "D": 40, "E": 20, "F": 0}
    info_score = {"1": 100, "2": 80, "3": 60, "4": 40, "5": 20, "6": 0}
    if len(code) != 2:
        return 50
    s = source_score.get(code[0].upper(), 50)
    i = info_score.get(code[1], 50)
    return (s + i) // 2
