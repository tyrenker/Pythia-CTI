"""Seed pipeline: download open-source threat intel and populate the Pythia DB.

Sources:
  MISP Galaxy threat-actor cluster → ~750 actor profiles
  MITRE ATT&CK STIX               → techniques + group-TTP mappings
  MITRE ATLAS                      → AI/ML adversarial techniques
  CISA KEV                         → known-exploited CVE snapshot (stored as IoCs)

Run directly:
  python scripts/build_seed.py
  python scripts/build_seed.py --sources attck,atlas   # selective refresh
  python scripts/build_seed.py --dry-run               # count only, no writes
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path
from typing import Any

# Ensure the package is importable when run directly.
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from pythia.core.db import SessionLocal, init_db
from pythia.models.actor import ActorTTPMapping, ThreatActor
from pythia.models.atlas import AtlasTechnique
from pythia.models.attck import AttckTechnique
from pythia.models.ioc import IoC

SOURCES = {
    "misp-galaxy": "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json",
    "attck-enterprise": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-14.1.json",
    "attck-mobile": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack-14.1.json",
    "attck-ics": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack-14.1.json",
    "atlas": "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.json",
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
}

KILL_CHAIN_MAP = {
    "reconnaissance": "reconnaissance",
    "resource-development": "weaponization",
    "initial-access": "delivery",
    "execution": "exploitation",
    "persistence": "installation",
    "privilege-escalation": "installation",
    "defense-evasion": "installation",
    "credential-access": "exploitation",
    "discovery": "exploitation",
    "lateral-movement": "actions-on-objectives",
    "collection": "actions-on-objectives",
    "command-and-control": "command-and-control",
    "exfiltration": "actions-on-objectives",
    "impact": "actions-on-objectives",
}

SPONSOR_KEYWORDS = {
    "nation-state": ["nation-state", "nation state", "government", "apt", "state-sponsored"],
    "financially-motivated": ["financial", "criminal", "ransomware", "cybercriminal", "profit"],
    "hacktivist": ["hacktivist", "activism", "ideolog"],
}


def _fetch(url: str, label: str) -> Any:
    print(f"  Downloading {label} ...", end=" ", flush=True)
    req = urllib.request.Request(url, headers={"User-Agent": "Pythia/0.1 (seed-builder)"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read())
    print("done")
    return data


def _infer_sponsor(description: str | None, motivations: list[str]) -> str:
    text = ((description or "") + " " + " ".join(motivations)).lower()
    for sponsor, keywords in SPONSOR_KEYWORDS.items():
        if any(k in text for k in keywords):
            return sponsor
    return "unknown"


def seed_misp_galaxy(session: Any, dry_run: bool) -> int:
    data = _fetch(SOURCES["misp-galaxy"], "MISP Galaxy threat-actors")
    values = data.get("values", [])
    added = updated = 0

    for entry in values:
        name: str = entry.get("value", "").strip()
        if not name:
            continue
        meta: dict = entry.get("meta", {})
        aliases: list[str] = meta.get("synonyms", []) or meta.get("aliases", [])
        country_codes: list[str] = meta.get("country", [])
        country_code = country_codes[0] if isinstance(country_codes, list) and country_codes else (country_codes if isinstance(country_codes, str) else None)
        refs: list[str] = meta.get("refs", [])
        motivations: list[str] = meta.get("motivation", []) if isinstance(meta.get("motivation"), list) else (
            [meta["motivation"]] if meta.get("motivation") else []
        )
        description: str = entry.get("description", "")
        attck_ids: list[str] = meta.get("mitre-attack-id", []) or []
        attck_group_id = attck_ids[0] if attck_ids else None

        if dry_run:
            added += 1
            continue

        existing = session.query(ThreatActor).filter_by(name=name).first()
        if existing:
            # Merge in richer data from MISP if we have it
            if aliases and not existing.aliases:
                existing.aliases = aliases
            if description and not existing.description:
                existing.description = description
            if country_code and not existing.country_code:
                existing.country_code = country_code
            if refs:
                existing.references = list(set(existing.references + refs))
            if attck_group_id and not existing.attck_group_id:
                existing.attck_group_id = attck_group_id
            updated += 1
        else:
            actor = ThreatActor(
                name=name,
                aliases=aliases,
                description=description or None,
                country_code=country_code,
                sponsor_type=_infer_sponsor(description, motivations),
                motivations=motivations,
                sectors_targeted=[],
                geographies_targeted=[country_code] if country_code else [],
                references=refs,
                tlp="WHITE",
                attck_group_id=attck_group_id,
                source="misp-galaxy",
                source_url=SOURCES["misp-galaxy"],
            )
            session.add(actor)
            added += 1

    if not dry_run:
        session.commit()
    print(f"  MISP Galaxy: {added} added, {updated} updated")
    return added + updated


def seed_attck(session: Any, domain: str, dry_run: bool) -> int:
    key = f"attck-{domain}"
    data = _fetch(SOURCES[key], f"ATT&CK {domain}")
    objects: list[dict] = data.get("objects", [])

    # Index objects by id for relationship lookups.
    by_id: dict[str, dict] = {o["id"]: o for o in objects if "id" in o}

    # ── techniques ──────────────────────────────────────────────────────────
    technique_objects = [
        o for o in objects
        if o.get("type") == "attack-pattern" and not o.get("x_mitre_deprecated", False)
    ]

    for obj in technique_objects:
        ext = obj.get("external_references", [])
        attck_ref = next((r for r in ext if r.get("source_name") == "mitre-attack"), None)
        if not attck_ref:
            continue
        technique_id: str = attck_ref["external_id"]
        name: str = obj.get("name", "")
        description: str = obj.get("description", "")
        tactics = [
            p["phase_name"]
            for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        ]
        is_sub = "." in technique_id
        parent_id = technique_id.split(".")[0] if is_sub else None
        platforms = obj.get("x_mitre_platforms", [])
        data_sources = obj.get("x_mitre_data_sources", [])
        detection = obj.get("x_mitre_detection", None)
        url = attck_ref.get("url")

        if dry_run:
            continue

        existing = session.get(AttckTechnique, technique_id)
        if not existing:
            session.add(AttckTechnique(
                technique_id=technique_id,
                name=name,
                description=description or None,
                tactics=tactics,
                is_subtechnique=is_sub,
                parent_id=parent_id,
                domain=domain,
                detection_note=detection,
                platforms=platforms,
                data_sources=data_sources,
                mitigations=[],
                source_url=url,
            ))

    if not dry_run:
        session.flush()  # ensure techniques exist before group mappings

    # ── groups → actor merge + TTP mappings ─────────────────────────────────
    group_objects = [
        o for o in objects
        if o.get("type") == "intrusion-set" and not o.get("x_mitre_deprecated", False)
    ]

    # uses relationships: source_ref=intrusion-set, target_ref=attack-pattern
    use_rels = [
        o for o in objects
        if o.get("type") == "relationship" and o.get("relationship_type") == "uses"
        and o.get("source_ref", "").startswith("intrusion-set--")
        and o.get("target_ref", "").startswith("attack-pattern--")
    ]
    uses_by_group: dict[str, list[dict]] = {}
    for rel in use_rels:
        uses_by_group.setdefault(rel["source_ref"], []).append(rel)

    mappings_added = 0
    for group in group_objects:
        group_stix_id = group["id"]
        ext = group.get("external_references", [])
        attck_ref = next((r for r in ext if r.get("source_name") == "mitre-attack"), None)
        if not attck_ref:
            continue

        group_attck_id = attck_ref["external_id"]  # e.g. G0001
        group_name = group.get("name", "").strip()
        aliases = group.get("aliases", [])
        # Remove the canonical name from aliases list
        aliases = [a for a in aliases if a != group_name]
        description = group.get("description", "")

        if dry_run:
            continue

        # Find or create actor record (prefer matching by attck_group_id, then name)
        actor = (
            session.query(ThreatActor).filter_by(attck_group_id=group_attck_id).first()
            or session.query(ThreatActor).filter_by(name=group_name).first()
        )
        if actor:
            # Enrich existing (MISP) record with ATT&CK data
            if not actor.attck_group_id:
                actor.attck_group_id = group_attck_id
            if description and not actor.description:
                actor.description = description
            for alias in aliases:
                if alias not in actor.aliases:
                    actor.aliases = actor.aliases + [alias]
        else:
            sectors_raw = [
                r.get("description", "")
                for r in ext
                if r.get("source_name") == "mitre-attack"
            ]
            actor = ThreatActor(
                name=group_name,
                aliases=aliases,
                description=description or None,
                country_code=None,
                sponsor_type="unknown",
                motivations=[],
                sectors_targeted=[],
                geographies_targeted=[],
                references=[attck_ref.get("url", "")] if attck_ref.get("url") else [],
                tlp="WHITE",
                attck_group_id=group_attck_id,
                source="attck",
                source_url=attck_ref.get("url"),
            )
            session.add(actor)
            session.flush()

        # Add TTP mappings for this group
        existing_techs = {m.technique_id for m in actor.ttp_mappings}
        for rel in uses_by_group.get(group_stix_id, []):
            target = by_id.get(rel.get("target_ref", ""))
            if not target:
                continue
            t_ext = target.get("external_references", [])
            t_ref = next((r for r in t_ext if r.get("source_name") == "mitre-attack"), None)
            if not t_ref:
                continue
            tech_id = t_ref["external_id"]
            if tech_id not in existing_techs:
                session.add(ActorTTPMapping(
                    actor_id=actor.id,
                    technique_id=tech_id,
                    use_note=rel.get("description"),
                    source="attck",
                ))
                existing_techs.add(tech_id)
                mappings_added += 1

    if not dry_run:
        session.commit()
    print(f"  ATT&CK {domain}: {len(technique_objects)} techniques, {len(group_objects)} groups, {mappings_added} TTP mappings")
    return len(technique_objects) + len(group_objects)


def seed_atlas(session: Any, dry_run: bool) -> int:
    data = _fetch(SOURCES["atlas"], "MITRE ATLAS")

    # ATLAS JSON structure: {"matrices": [{"techniques": [...], "tactics": [...]}]}
    matrices = data.get("matrices", [])
    added = 0
    for matrix in matrices:
        for tech in matrix.get("techniques", []):
            tech_id = tech.get("id", "")
            if not tech_id:
                continue
            name = tech.get("name", "")
            description = tech.get("description", "")
            tactics = [t.get("id", "") for t in tech.get("tactics", [])]
            sub_ids = [s.get("id", "") for s in tech.get("subtechniques", [])]

            if dry_run:
                added += 1
                continue

            if not session.get(AtlasTechnique, tech_id):
                session.add(AtlasTechnique(
                    technique_id=tech_id,
                    name=name,
                    description=description or None,
                    tactics=tactics,
                    subtechniques=sub_ids,
                    mitigations=[],
                    case_study_refs=[],
                    source_url="https://atlas.mitre.org/techniques/" + tech_id,
                ))
                added += 1

    if not dry_run:
        session.commit()
    print(f"  MITRE ATLAS: {added} techniques")
    return added


def seed_kev(session: Any, dry_run: bool) -> int:
    data = _fetch(SOURCES["kev"], "CISA KEV")
    vulns = data.get("vulnerabilities", [])
    added = 0
    for vuln in vulns:
        cve_id = vuln.get("cveID", "")
        if not cve_id:
            continue
        vendor = vuln.get("vendorProject", "")
        product = vuln.get("product", "")
        description = vuln.get("shortDescription", "")
        date_added = vuln.get("dateAdded", "")
        context = f"{vendor} {product}: {description}".strip()

        if dry_run:
            added += 1
            continue

        existing = session.query(IoC).filter_by(type="cve", value=cve_id).first()
        if not existing:
            session.add(IoC(
                type="cve",
                value=cve_id,
                context=context,
                confidence_source="A",
                confidence_info="1",
                tlp="WHITE",
                pyramid_tier="artifact",
                source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            ))
            added += 1

    if not dry_run:
        session.commit()
    print(f"  CISA KEV: {added} CVEs added")
    return added


def run(sources: list[str] | None = None, dry_run: bool = False) -> None:
    targets = sources or ["misp-galaxy", "attck", "atlas", "kev"]
    print(f"Pythia seed pipeline {'(dry-run) ' if dry_run else ''}— targets: {', '.join(targets)}\n")

    if not dry_run:
        init_db()

    with SessionLocal() as session:
        total = 0

        if "misp-galaxy" in targets:
            total += seed_misp_galaxy(session, dry_run)

        if "attck" in targets or "attck-enterprise" in targets:
            total += seed_attck(session, "enterprise", dry_run)
        if "attck-mobile" in targets:
            total += seed_attck(session, "mobile", dry_run)
        if "attck-ics" in targets:
            total += seed_attck(session, "ics", dry_run)

        if "atlas" in targets:
            total += seed_atlas(session, dry_run)

        if "kev" in targets:
            total += seed_kev(session, dry_run)

    print(f"\nDone. Total records processed: {total}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pythia seed pipeline")
    parser.add_argument(
        "--sources",
        nargs="*",
        default=None,
        help="Sources to load (default: all). Options: misp-galaxy attck attck-mobile attck-ics atlas kev",
    )
    parser.add_argument("--dry-run", action="store_true", help="Count only, no DB writes")
    args = parser.parse_args()
    run(sources=args.sources, dry_run=args.dry_run)
