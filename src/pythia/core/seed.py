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
import csv
import io
import json
import re
import tempfile
import urllib.request
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

from pythia.core.db import SessionLocal, init_db
from pythia.models.actor import ActorTTPMapping, ThreatActor
from pythia.models.atlas import AtlasTechnique
from pythia.models.attck import AttckTechnique
from pythia.models.ioc import IoC
from pythia.models.malware import MalwareFamily
from pythia.models.owasp_llm import OwaspLlmItem
from pythia.models.rule import DetectionRule

def _log_sync_status(session: Any, source: str, status: str, dry_run: bool) -> None:
    if dry_run:
        return
    from datetime import datetime, timezone
    from pythia.models.sync_log import SyncLog
    db_source = source.replace("-", "_")
    try:
        log = session.get(SyncLog, db_source)
        if not log:
            log = SyncLog(source=db_source)
            session.add(log)
        log.last_run = datetime.now(timezone.utc)
        log.status = status
        session.commit()
    except Exception as e:
        print(f"  Warning: failed to write sync log for {source}: {e}")

_DATA_DIR = Path(__file__).resolve().parent.parent.parent.parent / "data"

SOURCES = {
    "misp-galaxy": "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json",
    "attck-enterprise": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-14.1.json",
    "attck-mobile": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack-14.1.json",
    "attck-ics": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack-14.1.json",
    "atlas": "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.json",
    "atlas-alt": "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/atlas-navigator-data.json",
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "apt-sheet": "https://docs.google.com/spreadsheets/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/export?format=csv&gid={gid}",
}

APT_TABS = {
    "China": ("361554658", "CN", "nation-state"),
    "Russia": ("1636225066", "RU", "nation-state"),
    "North Korea": ("1905351590", "KP", "nation-state"),
    "Iran": ("376438690", "IR", "nation-state"),
    "Israel": ("300065512", "IL", "nation-state"),
    "NATO": ("2069598202", None, "nation-state"),
    "Middle East": ("574287636", None, "nation-state"),
    "Others": ("438782970", None, "unknown"),
    "Unknown": ("1121522397", None, "unknown"),
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


def _fetch_optional(urls: list[str], label: str) -> Any | None:
    for url in urls:
        try:
            return _fetch(url, label)
        except Exception:
            continue
    print(f"skipped (unavailable)")
    return None


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
    _log_sync_status(session, "misp_galaxy", "ok", dry_run)
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
    # Parents first so FK constraint is satisfied when subtechniques insert.
    technique_objects = sorted(
        technique_objects,
        key=lambda o: next(
            (r["external_id"] for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"),
            "",
        ),
    )

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
    _log_sync_status(session, "attck", "ok", dry_run)
    return len(technique_objects) + len(group_objects)


def seed_atlas(session: Any, dry_run: bool) -> int:
    data = _fetch_optional(
        [SOURCES["atlas"], SOURCES["atlas-alt"]],
        "MITRE ATLAS",
    )
    if not data:
        return 0

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


def seed_sigma(session: Any, dry_run: bool) -> int:
    """Load curated Sigma rules from data/sigma/*.yml into DetectionRule table."""
    sigma_dir = _DATA_DIR / "sigma"
    rule_files = sorted(sigma_dir.glob("*.yml"))
    if not rule_files:
        print("  Sigma: no .yml files found in data/sigma/ — skipped")
        return 0

    added = 0
    for path in rule_files:
        content = path.read_text(encoding="utf-8")
        # Extract key fields with lightweight regex — avoids pulling in PyYAML as a hard dep
        title_m = re.search(r'^title:\s*(.+)$', content, re.MULTILINE)
        title = title_m.group(1).strip() if title_m else path.stem
        level_m = re.search(r'^level:\s*(\S+)', content, re.MULTILINE)
        level = level_m.group(1).strip() if level_m else None
        status_m = re.search(r'^status:\s*(\S+)', content, re.MULTILINE)
        rule_status = status_m.group(1).strip() if status_m else None
        # Pull ATT&CK technique IDs from tags: attack.tXXXX
        technique_ids = [
            m.upper().replace(".", ".")
            for m in re.findall(r'attack\.(t\d{4}(?:\.\d{3})?)', content, re.IGNORECASE)
        ]
        technique_ids = list(dict.fromkeys(technique_ids))  # dedup, preserve order

        if dry_run:
            added += 1
            continue

        existing = session.query(DetectionRule).filter_by(title=title, rule_type="sigma").first()
        if not existing:
            session.add(DetectionRule(
                rule_type="sigma",
                title=title,
                content=content,
                technique_ids=technique_ids,
                actor_ids=[],
                severity=level,
                status=rule_status,
                source_url="https://github.com/SigmaHQ/sigma",
            ))
            added += 1

    if not dry_run:
        session.commit()
    print(f"  Sigma: {added} rules added from data/sigma/")
    return added


def seed_owasp(session: Any, dry_run: bool) -> int:
    """Load OWASP LLM Top 10 2025 from data/seed/owasp_llm_top10.json."""
    data_file = _DATA_DIR / "seed" / "owasp_llm_top10.json"
    if not data_file.exists():
        print("  OWASP LLM Top 10: seed file not found — skipped")
        return 0

    items: list[dict] = json.loads(data_file.read_text(encoding="utf-8"))
    added = 0
    for item in items:
        if dry_run:
            added += 1
            continue
        if not session.get(OwaspLlmItem, item["item_id"]):
            session.add(OwaspLlmItem(
                item_id=item["item_id"],
                rank=item["rank"],
                name=item["name"],
                description=item.get("description"),
                impact=item.get("impact"),
                detection_notes=item.get("detection_notes"),
                atlas_mappings=item.get("atlas_mappings", []),
                cwe_ids=item.get("cwe_ids", []),
                mitigations=item.get("mitigations", []),
                real_world_examples=item.get("real_world_examples", []),
                references=item.get("references", []),
            ))
            added += 1

    if not dry_run:
        session.commit()
    print(f"  OWASP LLM Top 10: {added} items added")
    return added


def seed_apt_sheet(session: Any, dry_run: bool) -> int:
    """Download and enrich threat actors from the decalage APT Groups Google Sheet."""
    total_added = 0
    total_enriched = 0

    alias_keywords = [
        "name", "alias", "crowdstrike", "irl", "kaspersky", "secureworks", 
        "mandiant", "fireeye", "symantec", "isight", "cisco", "talos", 
        "palo alto", "unit 42", "unit42", "dell secure works", "talos group", "nsa"
    ]

    # In-memory indexes to prevent duplicate objects/unique constraint violations across sheets
    existing_actors_by_name = {}
    existing_actors_by_mitre = {}
    existing_actors_by_alias = {}

    if not dry_run:
        # Load all existing actors from DB to populate our cache
        for a in session.query(ThreatActor).all():
            existing_actors_by_name[a.name.lower()] = a
            if a.attck_group_id:
                existing_actors_by_mitre[a.attck_group_id] = a
            for alias in (a.aliases or []):
                existing_actors_by_alias[alias.lower()] = a

    for tab_name, (gid, country_code, default_sponsor) in APT_TABS.items():
        url = SOURCES["apt-sheet"].format(gid=gid)
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'Pythia/0.1 (seed-builder)'}
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                content = response.read().decode('utf-8')
                csv_file = io.StringIO(content)
                reader = csv.reader(csv_file)
                rows = list(reader)
        except Exception as e:
            print(f"  APT Sheet [{tab_name}]: download failed ({e}) — skipping")
            continue

        if len(rows) < 3:
            continue

        headers = [h.strip() for h in rows[1]]
        data_rows = rows[2:]

        alias_cols = []
        mitre_idx = -1
        targets_idx = -1
        mo_idx = -1
        comment_idx = -1
        link_cols = []

        for idx, h in enumerate(headers):
            h_lower = h.lower()
            if idx == 0:
                continue
            if "mitre" in h_lower:
                mitre_idx = idx
            elif "target" in h_lower:
                targets_idx = idx
            elif "modus" in h_lower or "description" in h_lower:
                mo_idx = idx
            elif "comment" in h_lower:
                comment_idx = idx
            elif "link" in h_lower:
                link_cols.append(idx)
            elif any(kw in h_lower for kw in alias_keywords):
                alias_cols.append(idx)

        for row in data_rows:
            if not row or not row[0].strip() or row[0].strip() == "Common Name":
                continue

            common_name = re.sub(r'\s+Group$', '', row[0].strip()).strip()

            aliases = []
            for col_idx in alias_cols:
                if col_idx < len(row):
                    val = row[col_idx].strip()
                    if val and val.lower() != "n/a" and val.lower() != "none" and val != common_name:
                        parts = [p.strip() for p in re.split(r'[,/]', val)]
                        for p in parts:
                            p_clean = re.sub(r'\s*\([^)]*\)', '', p).strip()
                            if p_clean and p_clean not in aliases and p_clean != common_name:
                                aliases.append(p_clean)

            mitre_id = None
            if mitre_idx != -1 and mitre_idx < len(row):
                mitre_val = row[mitre_idx].strip()
                m = re.search(r'G\d{4}', mitre_val)
                if m:
                    mitre_id = m.group(0)

            mo_val = row[mo_idx].strip() if mo_idx != -1 and mo_idx < len(row) else ""
            comment_val = row[comment_idx].strip() if comment_idx != -1 and comment_idx < len(row) else ""
            desc_parts = []
            if mo_val and mo_val.lower() != "n/a":
                desc_parts.append(mo_val)
            if comment_val and comment_val.lower() != "n/a":
                desc_parts.append(f"Note: {comment_val}")
            description = "\n\n".join(desc_parts) if desc_parts else None

            sectors = []
            if targets_idx != -1 and targets_idx < len(row):
                target_val = row[targets_idx].strip()
                if target_val and target_val.lower() != "n/a":
                    sectors = [t.strip() for t in re.split(r'[,;•\n]', target_val) if t.strip()]

            links = []
            for col_idx in link_cols:
                if col_idx < len(row):
                    val = row[col_idx].strip()
                    if val.startswith("http"):
                        links.append(val)
            for cell in row:
                if cell.strip().startswith("http") and cell.strip() not in links:
                    links.append(cell.strip())

            combined_text = f"{common_name} {' '.join(aliases)} {description or ''} {' '.join(sectors)}"
            sponsor_type = _infer_sponsor(combined_text, default_sponsor)

            if dry_run:
                total_added += 1
                continue

            existing = None
            if mitre_id:
                existing = existing_actors_by_mitre.get(mitre_id)
            if not existing:
                existing = existing_actors_by_name.get(common_name.lower())
            if not existing and aliases:
                for alias in aliases:
                    existing = existing_actors_by_alias.get(alias.lower())
                    if existing:
                        break

            if existing:
                existing_aliases = set(existing.aliases or [])
                for alias in aliases:
                    existing_aliases.add(alias)
                existing.aliases = list(existing_aliases)

                if description and description not in (existing.description or ""):
                    existing.description = f"{existing.description}\n\n{description}" if existing.description else description

                existing_sectors = set(existing.sectors_targeted or [])
                for s in sectors:
                    if len(s) < 50 and not any(c.lower() in s.lower() for c in ["korea", "china", "vietnam", "russia", "usa", "europe", "japan"]):
                        existing_sectors.add(s)
                existing.sectors_targeted = list(existing_sectors)

                existing_refs = set(existing.references or [])
                for link in links:
                    existing_refs.add(link)
                existing.references = list(existing_refs)

                if country_code and not existing.country_code:
                    existing.country_code = country_code
                if not existing.attck_group_id and mitre_id:
                    existing.attck_group_id = mitre_id
                if existing.sponsor_type == "unknown" and sponsor_type != "unknown":
                    existing.sponsor_type = sponsor_type

                total_enriched += 1
            else:
                clean_sectors = [s for s in sectors if len(s) < 50 and not any(c.lower() in s.lower() for c in ["korea", "china", "vietnam", "russia", "usa", "europe", "japan"])]
                actor = ThreatActor(
                    name=common_name,
                    aliases=aliases,
                    description=description,
                    country_code=country_code,
                    sponsor_type=sponsor_type,
                    motivations=[],
                    sectors_targeted=clean_sectors,
                    geographies_targeted=[country_code] if country_code else [],
                    references=links,
                    tlp="WHITE",
                    attck_group_id=mitre_id,
                    source="apt-spreadsheet",
                    source_url=url,
                )
                session.add(actor)
                total_added += 1

                # Update in-memory index immediately to prevent UNIQUE constraint failures in subsequent rows/sheets
                existing_actors_by_name[common_name.lower()] = actor
                if mitre_id:
                    existing_actors_by_mitre[mitre_id] = actor
                for alias in aliases:
                    existing_actors_by_alias[alias.lower()] = actor

    if not dry_run:
        session.commit()
    print(f"  APT Spreadsheet: {total_added} added, {total_enriched} enriched")
    _log_sync_status(session, "apt_sheet", "ok", dry_run)
    return total_added + total_enriched


def seed_abuse_ch(session: Any, dry_run: bool) -> int:
    """Download recent indicators from abuse.ch ThreatFox public keyless CSV feeds."""
    feeds = {
        "ip": "https://threatfox.abuse.ch/export/csv/ip-port/recent/",
        "url": "https://threatfox.abuse.ch/export/csv/urls/recent/",
        "hash": "https://threatfox.abuse.ch/export/csv/sha256/recent/",
    }
    
    total_added = 0

    for ioc_type, url in feeds.items():
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Pythia/0.1 (seed-builder)"}
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                content = response.read().decode('utf-8')
        except Exception as e:
            print(f"  abuse.ch ThreatFox [{ioc_type}]: download failed ({e}) — skipping")
            continue

        csv_lines = [line for line in content.splitlines() if not line.startswith('#')]
        csv_file = io.StringIO("\n".join(csv_lines))
        reader = csv.reader(csv_file)
        rows = list(reader)

        added = 0
        for row in rows:
            if len(row) < 15:
                continue

            first_seen_str = row[0].strip().strip('"')
            ioc_val = row[2].strip().strip('"')
            type_str = row[3].strip().strip('"')
            threat_type = row[4].strip().strip('"')
            malware_printable = row[7].strip().strip('"')
            confidence_level_str = row[9].strip().strip('"')
            reference = row[11].strip().strip('"')

            mapped_type = "ip"
            pyramid_tier = "ip"
            if "port" in type_str:
                ioc_val = ioc_val.split(":")[0]
                mapped_type = "ip"
                pyramid_tier = "ip"
            elif type_str == "url":
                mapped_type = "url"
                pyramid_tier = "domain"
            elif "hash" in type_str:
                mapped_type = "hash"
                pyramid_tier = "hash"
            elif type_str == "domain":
                mapped_type = "domain"
                pyramid_tier = "domain"

            first_seen = None
            try:
                first_seen = datetime.strptime(first_seen_str, "%Y-%m-%d %H:%M:%S")
            except Exception:
                pass

            try:
                conf_val = int(confidence_level_str)
            except ValueError:
                conf_val = 75

            confidence_source = "B"
            if conf_val >= 90:
                confidence_source = "A"
            elif conf_val >= 70:
                confidence_source = "B"
            elif conf_val >= 50:
                confidence_source = "C"

            context = f"ThreatFox indicators of {malware_printable} ({threat_type})."
            source_url = reference if reference and reference.lower() != "none" else "https://threatfox.abuse.ch"

            if dry_run:
                added += 1
                continue

            existing = session.query(IoC).filter_by(type=mapped_type, value=ioc_val).first()
            if not existing:
                session.add(IoC(
                    type=mapped_type,
                    value=ioc_val,
                    first_seen=first_seen,
                    last_seen=first_seen,
                    confidence_source=confidence_source,
                    confidence_info="2",
                    tlp="WHITE",
                    pyramid_tier=pyramid_tier,
                    context=context,
                    source_url=source_url,
                ))
                added += 1
        if not dry_run:
            session.commit()
        print(f"  abuse.ch ThreatFox [{ioc_type}]: {added} indicators added")
        total_added += added

    _log_sync_status(session, "abuse_ch", "ok", dry_run)
    return total_added


def run(sources: list[str] | None = None, dry_run: bool = False) -> None:
    targets = sources or ["misp-galaxy", "attck", "atlas", "kev", "sigma", "owasp", "apt-sheet"]
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

        if "sigma" in targets:
            total += seed_sigma(session, dry_run)

        if "owasp" in targets or "owasp-llm" in targets:
            total += seed_owasp(session, dry_run)

        if "apt-sheet" in targets:
            total += seed_apt_sheet(session, dry_run)

        if "abuse-ch" in targets:
            total += seed_abuse_ch(session, dry_run)

        if "ipsum" in targets:
            total += seed_ipsum(session, dry_run)

        if "phishtank" in targets:
            total += seed_phishtank(session, dry_run)

        if "malpedia" in targets:
            total += seed_malpedia(session, dry_run)

        if "sigma-full" in targets:
            total += seed_sigma_full(session, dry_run)

        if "yara-rules" in targets or "yara-full" in targets:
            total += seed_yara_rules(session, dry_run)

        if "icewater" in targets:
            total += seed_icewater(session, dry_run)

        if "signature-base" in targets:
            total += seed_signature_base(session, dry_run)

    print(f"\nDone. Total records processed: {total}")


def _download_zip(url: str, label: str) -> Path | None:
    """Download a zip archive to a temp file. Returns Path on success, None on failure."""
    print(f"  Downloading {label} (large download, please wait)...", end=" ", flush=True)
    tmp = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Pythia/0.1 (seed-builder)"})
        with urllib.request.urlopen(req, timeout=300) as resp:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                tmp.write(chunk)
        tmp.close()
        print("done")
        return Path(tmp.name)
    except Exception as exc:
        tmp.close()
        Path(tmp.name).unlink(missing_ok=True)
        print(f"failed ({exc})")
        return None


def _extract_yara_title(content: str, filename: str) -> str:
    """Extract the first rule name from YARA content, falling back to filename stem."""
    m = re.search(r'^rule\s+(\w+)', content, re.MULTILINE)
    return m.group(1) if m else Path(filename).stem


def _extract_yara_technique_ids(content: str) -> list[str]:
    """Extract ATT&CK technique IDs referenced in a YARA rule's meta section."""
    ids = re.findall(r'\b(T\d{4}(?:\.\d{3})?)\b', content)
    return list(dict.fromkeys(t.upper() for t in ids))


def seed_ipsum(session: Any, dry_run: bool) -> int:
    """Ingest IP threat list from stamparm/ipsum (aggregated blocklist with confidence scores)."""
    url = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
    print("  Downloading ipsum IP list...", end=" ", flush=True)
    req = urllib.request.Request(url, headers={"User-Agent": "Pythia/0.1 (seed-builder)"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            content = resp.read().decode("utf-8")
    except Exception as exc:
        print(f"failed ({exc}) — skipping")
        return 0
    print("done")

    added = 0
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        ip_val = parts[0].strip()
        try:
            score = int(parts[1].strip())
        except ValueError:
            score = 1

        # Map score (1-10+) to admiralty confidence source (A-F)
        if score >= 8:
            conf_source = "A"
        elif score >= 5:
            conf_source = "B"
        elif score >= 3:
            conf_source = "C"
        else:
            conf_source = "D"

        if dry_run:
            added += 1
            continue

        existing = session.query(IoC).filter_by(type="ip", value=ip_val).first()
        if not existing:
            session.add(IoC(
                type="ip",
                value=ip_val,
                confidence_source=conf_source,
                confidence_info="2",
                tlp="WHITE",
                pyramid_tier="network",
                context=f"IPsum aggregated blocklist — flagged by {score} source(s).",
                source_url=url,
            ))
            added += 1

    if not dry_run:
        session.commit()
    print(f"  IPsum: {added} IPs added")
    _log_sync_status(session, "ipsum", "ok", dry_run)
    return added


def seed_phishtank(session: Any, dry_run: bool) -> int:
    """Ingest verified phishing URLs from PhishTank. Requires PHISHTANK_API_KEY."""
    from pythia.core.config import get_settings
    settings = get_settings()
    api_key = settings.phishtank_api_key
    if not api_key:
        print("  PhishTank: no PHISHTANK_API_KEY set — skipping")
        _log_sync_status(session, "phishtank", "no_key", dry_run)
        return 0

    url = f"http://data.phishtank.com/data/{api_key}/online-valid.json"
    print("  Downloading PhishTank feed...", end=" ", flush=True)
    req = urllib.request.Request(url, headers={"User-Agent": "pythia-bot/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            entries: list[dict[str, Any]] = json.loads(resp.read())
    except Exception as exc:
        print(f"failed ({exc}) — skipping")
        return 0
    print("done")

    added = 0
    for entry in entries:
        phish_url = (entry.get("url") or "").strip()
        if not phish_url:
            continue
        verified = entry.get("verified") == "yes"

        if dry_run:
            added += 1
            continue

        existing = session.query(IoC).filter_by(type="url", value=phish_url).first()
        if not existing:
            session.add(IoC(
                type="url",
                value=phish_url,
                confidence_source="A" if verified else "C",
                confidence_info="2",
                tlp="WHITE",
                pyramid_tier="artifact",
                context="PhishTank community-verified phishing URL.",
                source_url="https://www.phishtank.com/",
            ))
            added += 1

    if not dry_run:
        session.commit()
    print(f"  PhishTank: {added} phishing URLs added")
    _log_sync_status(session, "phishtank", "ok", dry_run)
    return added


def seed_malpedia(session: Any, dry_run: bool) -> int:
    """Ingest malware family records from Malpedia. Uses API key if MALPEDIA_API_KEY is set."""
    from pythia.core.config import get_settings
    settings = get_settings()
    api_key = settings.malpedia_api_key

    base_url = "https://malpedia.caad.fkie.fraunhofer.de"
    headers: dict[str, str] = {"User-Agent": "Pythia/0.1 (seed-builder)"}
    if api_key:
        headers["Authorization"] = f"apitoken {api_key}"

    print("  Fetching Malpedia family list...", end=" ", flush=True)
    req = urllib.request.Request(f"{base_url}/api/list/families", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw: Any = json.loads(resp.read())
    except Exception as exc:
        print(f"failed ({exc}) — skipping")
        return 0
    print("done")

    # API returns dict {slug: {type, updated, ...}} or a list of slugs
    if isinstance(raw, list):
        families_data: dict[str, dict[str, Any]] = {slug: {} for slug in raw}
    elif isinstance(raw, dict):
        families_data = raw
    else:
        print("  Malpedia: unexpected response format — skipping")
        return 0

    added = 0
    # Track names inserted this run so platform variants (win.X, apk.X) don't collide
    seen_names: set[str] = set()

    for slug, meta in families_data.items():
        # Slugs follow the pattern "platform.family_name"
        parts = slug.split(".", 1)
        name_raw = parts[1] if len(parts) == 2 else slug
        # Convert underscores to spaces and title-case
        name = name_raw.replace("_", " ").title()
        family_type = meta.get("type") or None

        if dry_run:
            added += 1
            continue

        if name in seen_names:
            continue

        existing = (
            session.query(MalwareFamily).filter_by(malpedia_slug=slug).first()
            or session.query(MalwareFamily).filter_by(name=name).first()
        )
        if existing:
            if family_type and not existing.family_type:
                existing.family_type = family_type
            if not existing.malpedia_slug:
                existing.malpedia_slug = slug
            seen_names.add(name)
        else:
            session.add(MalwareFamily(
                name=name,
                aliases=[],
                family_type=family_type,
                actor_ids=[],
                rule_ids=[],
                references=[],
                source="malpedia",
                source_url=f"{base_url}/families/{slug}",
                malpedia_slug=slug,
            ))
            seen_names.add(name)
            added += 1

    if not dry_run:
        session.commit()
    print(f"  Malpedia: {added} malware families added")
    _log_sync_status(session, "malpedia", "ok", dry_run)
    return added


def seed_sigma_full(session: Any, dry_run: bool) -> int:
    """Download and import the full SigmaHQ ruleset from GitHub master zip."""
    zip_url = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"
    tmp_path = _download_zip(zip_url, "SigmaHQ full ruleset")
    if tmp_path is None:
        return 0

    added = 0
    try:
        with zipfile.ZipFile(tmp_path) as zf:
            rule_paths = [
                name for name in zf.namelist()
                if "/rules/" in name and name.endswith(".yml")
            ]
            for zpath in rule_paths:
                try:
                    content = zf.read(zpath).decode("utf-8", errors="replace")
                except Exception:
                    continue

                title_m = re.search(r'^title:\s*(.+)$', content, re.MULTILINE)
                title = title_m.group(1).strip() if title_m else Path(zpath).stem
                level_m = re.search(r'^level:\s*(\S+)', content, re.MULTILINE)
                level = level_m.group(1).strip() if level_m else None
                status_m = re.search(r'^status:\s*(\S+)', content, re.MULTILINE)
                rule_status = status_m.group(1).strip() if status_m else None
                technique_ids = list(dict.fromkeys(
                    m.upper()
                    for m in re.findall(r'attack\.(t\d{4}(?:\.\d{3})?)', content, re.IGNORECASE)
                ))

                if dry_run:
                    added += 1
                    continue

                if not session.query(DetectionRule).filter_by(title=title, rule_type="sigma").first():
                    session.add(DetectionRule(
                        rule_type="sigma",
                        title=title,
                        content=content,
                        technique_ids=technique_ids,
                        actor_ids=[],
                        severity=level,
                        status=rule_status,
                        source_url="https://github.com/SigmaHQ/sigma",
                    ))
                    added += 1

        if not dry_run:
            session.commit()
    finally:
        tmp_path.unlink(missing_ok=True)

    print(f"  SigmaHQ full: {added} rules added")
    return added


def seed_yara_rules(session: Any, dry_run: bool) -> int:
    """Download and import YARA rules from the Yara-Rules/rules GitHub repository."""
    zip_url = "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip"
    tmp_path = _download_zip(zip_url, "Yara-Rules repository")
    if tmp_path is None:
        return 0

    added = 0
    try:
        with zipfile.ZipFile(tmp_path) as zf:
            yara_paths = [
                name for name in zf.namelist()
                if name.endswith((".yar", ".yara")) and not name.endswith("/")
            ]
            for zpath in yara_paths:
                try:
                    content = zf.read(zpath).decode("utf-8", errors="replace")
                except Exception:
                    continue
                if not content.strip():
                    continue

                title = _extract_yara_title(content, zpath)
                technique_ids = _extract_yara_technique_ids(content)

                if dry_run:
                    added += 1
                    continue

                if not session.query(DetectionRule).filter_by(title=title, rule_type="yara").first():
                    session.add(DetectionRule(
                        rule_type="yara",
                        title=title,
                        content=content,
                        technique_ids=technique_ids,
                        actor_ids=[],
                        severity=None,
                        status="stable",
                        source_url="https://github.com/Yara-Rules/rules",
                    ))
                    added += 1

        if not dry_run:
            session.commit()
    finally:
        tmp_path.unlink(missing_ok=True)

    print(f"  Yara-Rules: {added} rules added")
    _log_sync_status(session, "yara_rules", "ok", dry_run)
    return added


def seed_icewater(session: Any, dry_run: bool) -> int:
    """Download and import YARA rules from the SupportIntelligence/Icewater repository."""
    zip_url = "https://github.com/SupportIntelligence/Icewater/archive/refs/heads/master.zip"
    tmp_path = _download_zip(zip_url, "Icewater YARA rules")
    if tmp_path is None:
        return 0

    added = 0
    try:
        with zipfile.ZipFile(tmp_path) as zf:
            yara_paths = [
                name for name in zf.namelist()
                if name.endswith((".yar", ".yara")) and not name.endswith("/")
            ]
            for zpath in yara_paths:
                try:
                    content = zf.read(zpath).decode("utf-8", errors="replace")
                except Exception:
                    continue
                if not content.strip():
                    continue

                title = _extract_yara_title(content, zpath)
                technique_ids = _extract_yara_technique_ids(content)

                if dry_run:
                    added += 1
                    continue

                if not session.query(DetectionRule).filter_by(title=title, rule_type="yara").first():
                    session.add(DetectionRule(
                        rule_type="yara",
                        title=title,
                        content=content,
                        technique_ids=technique_ids,
                        actor_ids=[],
                        severity=None,
                        status="stable",
                        source_url="https://github.com/SupportIntelligence/Icewater",
                    ))
                    added += 1

        if not dry_run:
            session.commit()
    finally:
        tmp_path.unlink(missing_ok=True)

    print(f"  Icewater: {added} rules added")
    _log_sync_status(session, "icewater", "ok", dry_run)
    return added


def seed_signature_base(session: Any, dry_run: bool) -> int:
    """Download and import YARA and Sigma rules from Neo23x0/signature-base."""
    zip_url = "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip"
    tmp_path = _download_zip(zip_url, "signature-base (Neo23x0)")
    if tmp_path is None:
        return 0

    added = 0
    try:
        with zipfile.ZipFile(tmp_path) as zf:
            for zpath in zf.namelist():
                if zpath.endswith("/"):
                    continue

                is_yara = zpath.endswith((".yar", ".yara")) and "/yara/" in zpath
                is_sigma = zpath.endswith(".yml") and "/sigma/" in zpath
                if not (is_yara or is_sigma):
                    continue

                try:
                    content = zf.read(zpath).decode("utf-8", errors="replace")
                except Exception:
                    continue
                if not content.strip():
                    continue

                if is_yara:
                    rule_type = "yara"
                    title = _extract_yara_title(content, zpath)
                    technique_ids = _extract_yara_technique_ids(content)
                    severity: str | None = None
                    status: str | None = "stable"
                else:
                    rule_type = "sigma"
                    title_m = re.search(r'^title:\s*(.+)$', content, re.MULTILINE)
                    title = title_m.group(1).strip() if title_m else Path(zpath).stem
                    level_m = re.search(r'^level:\s*(\S+)', content, re.MULTILINE)
                    severity = level_m.group(1).strip() if level_m else None
                    status_m = re.search(r'^status:\s*(\S+)', content, re.MULTILINE)
                    status = status_m.group(1).strip() if status_m else None
                    technique_ids = list(dict.fromkeys(
                        m.upper()
                        for m in re.findall(r'attack\.(t\d{4}(?:\.\d{3})?)', content, re.IGNORECASE)
                    ))

                if dry_run:
                    added += 1
                    continue

                if not session.query(DetectionRule).filter_by(title=title, rule_type=rule_type).first():
                    session.add(DetectionRule(
                        rule_type=rule_type,
                        title=title,
                        content=content,
                        technique_ids=technique_ids,
                        actor_ids=[],
                        severity=severity,
                        status=status,
                        source_url="https://github.com/Neo23x0/signature-base",
                    ))
                    added += 1

        if not dry_run:
            session.commit()
    finally:
        tmp_path.unlink(missing_ok=True)

    print(f"  signature-base: {added} rules added")
    _log_sync_status(session, "signature_base", "ok", dry_run)
    return added


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pythia seed pipeline")
    parser.add_argument(
        "--sources",
        nargs="*",
        default=None,
        help=(
            "Sources to load (default: all). "
            "Options: misp-galaxy attck attck-mobile attck-ics atlas kev sigma owasp apt-sheet "
            "abuse-ch ipsum phishtank malpedia sigma-full yara-rules icewater signature-base"
        ),
    )
    parser.add_argument("--dry-run", action="store_true", help="Count only, no DB writes")
    args = parser.parse_args()
    run(sources=args.sources, dry_run=args.dry_run)
