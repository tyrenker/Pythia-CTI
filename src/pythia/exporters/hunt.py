"""Export hunt sessions to Markdown and STIX 2.1 bundles."""

from __future__ import annotations

import uuid as _uuid
from typing import Any

from pythia.exporters.stix import (
    _IOC_PATTERN,
    _admiralty_to_stix_confidence,
    _bundle,
    _fmt_dt,
    _now_utc,
)

_OBS_TYPE_TO_IOC: dict[str, str] = {
    "ioc_ip": "ip",
    "ioc_domain": "domain",
    "ioc_hash": "hash",
    "ioc_url": "url",
    "ioc_email": "email",
    "ioc_mutex": "mutex",
    "ioc_registry": "registry",
}


def export_hunt_markdown(hunt: Any) -> str:
    """Render a HuntSession ORM object to a Markdown string."""
    lines: list[str] = []

    lines.append(f"# {hunt.name}")
    lines.append("")
    lines.append(f"**Status:** {hunt.status.capitalize()}  ")
    if hunt.analyst:
        lines.append(f"**Analyst:** {hunt.analyst}  ")
    lines.append(f"**Created:** {hunt.created_at.strftime('%Y-%m-%d %H:%M UTC')}  ")
    lines.append(f"**Updated:** {hunt.updated_at.strftime('%Y-%m-%d %H:%M UTC')}  ")
    if hunt.sector_focus:
        lines.append(f"**Sector Focus:** {', '.join(hunt.sector_focus)}  ")
    if hunt.motivation_focus:
        lines.append(f"**Motivation Focus:** {', '.join(hunt.motivation_focus)}  ")
    lines.append("")

    if hunt.hypothesis:
        lines.append("## Hypothesis")
        lines.append("")
        lines.append(hunt.hypothesis)
        lines.append("")

    if hunt.observations:
        lines.append("## Observations")
        lines.append("")
        lines.append("| Type | Value | Confidence | Tier | Notes |")
        lines.append("|------|-------|------------|------|-------|")
        for obs in hunt.observations:
            conf = f"{obs.confidence_source}{obs.confidence_info}"
            tier = obs.pyramid_tier or "—"
            notes = (obs.notes or "").replace("|", "\\|").replace("\n", " ")
            value = obs.value.replace("|", "\\|")
            lines.append(f"| `{obs.obs_type}` | `{value}` | {conf} | {tier} | {notes} |")
        lines.append("")

    if hunt.note and hunt.note.content:
        lines.append("## Analyst Notes")
        lines.append("")
        lines.append(hunt.note.content)
        lines.append("")

    if hunt.detections:
        lines.append("## Draft Detections")
        lines.append("")
        for det in hunt.detections:
            lines.append(f"### {det.title}")
            lines.append("")
            lines.append(f"**Type:** {det.rule_type.upper()}  ")
            lines.append(f"**Status:** {det.status}  ")
            lines.append(f"**Pyramid Tier:** {det.pyramid_tier}  ")
            if det.linked_ttp_ids:
                lines.append(f"**Linked TTPs:** {', '.join(det.linked_ttp_ids)}  ")
            lines.append("")
            if det.rationale:
                lines.append(f"*{det.rationale}*")
                lines.append("")
            lines.append(f"```{det.rule_type}")
            lines.append(det.content)
            lines.append("```")
            lines.append("")

    return "\n".join(lines)


def export_hunt_stix(hunt: Any) -> dict[str, Any]:
    """Return a STIX 2.1 bundle for a HuntSession ORM object."""
    objects: list[dict[str, Any]] = []

    identity_id = f"identity--{_uuid.uuid5(_uuid.NAMESPACE_URL, 'pythia-platform')}"
    identity: dict[str, Any] = {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": _now_utc(),
        "modified": _now_utc(),
        "name": "Pythia Threat Intelligence Platform",
        "identity_class": "system",
    }
    objects.append(identity)

    campaign_id = f"campaign--{hunt.id}"
    campaign: dict[str, Any] = {
        "type": "campaign",
        "spec_version": "2.1",
        "id": campaign_id,
        "created": _fmt_dt(hunt.created_at),
        "modified": _fmt_dt(hunt.updated_at),
        "name": hunt.name,
        "created_by_ref": identity_id,
    }
    if hunt.hypothesis:
        campaign["description"] = hunt.hypothesis
    if hunt.sector_focus:
        campaign["labels"] = [f"sector:{s}" for s in hunt.sector_focus]
    objects.append(campaign)

    seen_attack_patterns: set[str] = set()

    for obs in hunt.observations:
        ioc_type = _OBS_TYPE_TO_IOC.get(obs.obs_type)

        if ioc_type and ioc_type in _IOC_PATTERN:
            pattern_tmpl = _IOC_PATTERN[ioc_type]
            pattern = pattern_tmpl.format(value=obs.value.replace("'", "\\'"))
            indicator_id = f"indicator--{obs.id}"
            confidence = _admiralty_to_stix_confidence(
                f"{obs.confidence_source}{obs.confidence_info}"
            )
            indicator: dict[str, Any] = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": _fmt_dt(obs.created_at),
                "modified": _fmt_dt(obs.created_at),
                "name": f"{obs.obs_type}:{obs.value}",
                "indicator_types": ["malicious-activity"],
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": _fmt_dt(obs.created_at),
                "confidence": confidence,
                "created_by_ref": identity_id,
            }
            if obs.notes:
                indicator["description"] = obs.notes
            objects.append(indicator)

            rel: dict[str, Any] = {
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{_uuid.uuid5(_uuid.NAMESPACE_URL, obs.id + hunt.id)}",
                "created": _now_utc(),
                "modified": _now_utc(),
                "relationship_type": "indicates",
                "source_ref": indicator_id,
                "target_ref": campaign_id,
                "created_by_ref": identity_id,
            }
            objects.append(rel)

        elif obs.obs_type == "ttp":
            tech_id = obs.value.upper()
            ap_id = f"attack-pattern--{_uuid.uuid5(_uuid.NAMESPACE_URL, tech_id)}"
            if ap_id not in seen_attack_patterns:
                seen_attack_patterns.add(ap_id)
                attack_pattern: dict[str, Any] = {
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": ap_id,
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
                if obs.notes:
                    attack_pattern["description"] = obs.notes
                objects.append(attack_pattern)

            ttp_rel: dict[str, Any] = {
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{_uuid.uuid5(_uuid.NAMESPACE_URL, obs.id + hunt.id + 'ttp')}",
                "created": _now_utc(),
                "modified": _now_utc(),
                "relationship_type": "uses",
                "source_ref": campaign_id,
                "target_ref": ap_id,
                "created_by_ref": identity_id,
            }
            objects.append(ttp_rel)

    return _bundle(*objects)
