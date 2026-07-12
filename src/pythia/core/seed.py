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
from datetime import UTC, datetime
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
    from datetime import datetime

    from pythia.models.sync_log import SyncLog

    db_source = source.replace("-", "_")
    try:
        log = session.get(SyncLog, db_source)
        if not log:
            log = SyncLog(source=db_source)
            session.add(log)
        log.last_run = datetime.now(UTC)
        log.status = status
        session.commit()
    except Exception as e:
        print(f"  Warning: failed to write sync log for {source}: {e}")


_DATA_DIR = Path(__file__).resolve().parent.parent.parent.parent / "data"

SOURCES = {
    "misp-galaxy": "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json",
    "misp-malpedia": "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/malpedia.json",
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
    print("skipped (unavailable)")
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
        country_code = (
            country_codes[0]
            if isinstance(country_codes, list) and country_codes
            else (country_codes if isinstance(country_codes, str) else None)
        )
        refs: list[str] = meta.get("refs", [])
        motivations: list[str] = (
            meta.get("motivation", [])
            if isinstance(meta.get("motivation"), list)
            else ([meta["motivation"]] if meta.get("motivation") else [])
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
        o
        for o in objects
        if o.get("type") == "attack-pattern" and not o.get("x_mitre_deprecated", False)
    ]
    # Parents first so FK constraint is satisfied when subtechniques insert.
    technique_objects = sorted(
        technique_objects,
        key=lambda o: next(
            (
                r["external_id"]
                for r in o.get("external_references", [])
                if r.get("source_name") == "mitre-attack"
            ),
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
            session.add(
                AttckTechnique(
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
                )
            )

    if not dry_run:
        session.flush()  # ensure techniques exist before group mappings

    # ── groups → actor merge + TTP mappings ─────────────────────────────────
    group_objects = [
        o
        for o in objects
        if o.get("type") == "intrusion-set" and not o.get("x_mitre_deprecated", False)
    ]

    # uses relationships: source_ref=intrusion-set, target_ref=attack-pattern
    use_rels = [
        o
        for o in objects
        if o.get("type") == "relationship"
        and o.get("relationship_type") == "uses"
        and o.get("source_ref", "").startswith("intrusion-set--")
        and o.get("target_ref", "").startswith("attack-pattern--")
    ]
    uses_by_group: dict[str, list[dict]] = {}
    for rel in use_rels:
        uses_by_group.setdefault(rel["source_ref"], []).append(rel)

    # Build in-memory indexes so alias lookups don't require per-group DB queries.
    actors_by_name: dict[str, ThreatActor] = {}
    actors_by_alias: dict[str, ThreatActor] = {}
    if not dry_run:
        for _a in session.query(ThreatActor).all():
            actors_by_name[_a.name.lower()] = _a
            for _al in _a.aliases or []:
                actors_by_alias[_al.lower()] = _a

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

        # Match: ATT&CK ID → canonical name → group name in actor aliases → ATT&CK aliases
        actor: ThreatActor | None = (
            session.query(ThreatActor).filter_by(attck_group_id=group_attck_id).first()
            or actors_by_name.get(group_name.lower())
            or actors_by_alias.get(group_name.lower())
        )
        if not actor:
            for _alias in aliases:
                actor = actors_by_name.get(_alias.lower()) or actors_by_alias.get(_alias.lower())
                if actor:
                    break

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
            actors_by_name[actor.name.lower()] = actor
            for _al in actor.aliases or []:
                actors_by_alias[_al.lower()] = actor

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
                session.add(
                    ActorTTPMapping(
                        actor_id=actor.id,
                        technique_id=tech_id,
                        use_note=rel.get("description"),
                        source="attck",
                    )
                )
                existing_techs.add(tech_id)
                mappings_added += 1

    if not dry_run:
        session.commit()
    print(
        f"  ATT&CK {domain}: {len(technique_objects)} techniques, {len(group_objects)} groups, {mappings_added} TTP mappings"
    )
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
                session.add(
                    AtlasTechnique(
                        technique_id=tech_id,
                        name=name,
                        description=description or None,
                        tactics=tactics,
                        subtechniques=sub_ids,
                        mitigations=[],
                        case_study_refs=[],
                        source_url="https://atlas.mitre.org/techniques/" + tech_id,
                    )
                )
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
            session.add(
                IoC(
                    type="cve",
                    value=cve_id,
                    context=context,
                    confidence_source="A",
                    confidence_info="1",
                    tlp="WHITE",
                    pyramid_tier="artifact",
                    source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                )
            )
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
        title_m = re.search(r"^title:\s*(.+)$", content, re.MULTILINE)
        title = title_m.group(1).strip() if title_m else path.stem
        level_m = re.search(r"^level:\s*(\S+)", content, re.MULTILINE)
        level = level_m.group(1).strip() if level_m else None
        status_m = re.search(r"^status:\s*(\S+)", content, re.MULTILINE)
        rule_status = status_m.group(1).strip() if status_m else None
        # Pull ATT&CK technique IDs from tags: attack.tXXXX
        technique_ids = [
            m.upper().replace(".", ".")
            for m in re.findall(r"attack\.(t\d{4}(?:\.\d{3})?)", content, re.IGNORECASE)
        ]
        technique_ids = list(dict.fromkeys(technique_ids))  # dedup, preserve order

        if dry_run:
            added += 1
            continue

        existing = session.query(DetectionRule).filter_by(title=title, rule_type="sigma").first()
        if not existing:
            session.add(
                DetectionRule(
                    rule_type="sigma",
                    title=title,
                    content=content,
                    technique_ids=technique_ids,
                    actor_ids=[],
                    severity=level,
                    status=rule_status,
                    source="sigma-local",
                    source_url="https://github.com/SigmaHQ/sigma",
                )
            )
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
            session.add(
                OwaspLlmItem(
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
                )
            )
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
        "name",
        "alias",
        "crowdstrike",
        "irl",
        "kaspersky",
        "secureworks",
        "mandiant",
        "fireeye",
        "symantec",
        "isight",
        "cisco",
        "talos",
        "palo alto",
        "unit 42",
        "unit42",
        "dell secure works",
        "talos group",
        "nsa",
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
            for alias in a.aliases or []:
                existing_actors_by_alias[alias.lower()] = a

    for tab_name, (gid, country_code, default_sponsor) in APT_TABS.items():
        url = SOURCES["apt-sheet"].format(gid=gid)
        req = urllib.request.Request(url, headers={"User-Agent": "Pythia/0.1 (seed-builder)"})
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                content = response.read().decode("utf-8")
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

            common_name = re.sub(r"\s+Group$", "", row[0].strip()).strip()

            aliases = []
            for col_idx in alias_cols:
                if col_idx < len(row):
                    val = row[col_idx].strip()
                    if (
                        val
                        and val.lower() != "n/a"
                        and val.lower() != "none"
                        and val != common_name
                    ):
                        parts = [p.strip() for p in re.split(r"[,/]", val)]
                        for p in parts:
                            p_clean = re.sub(r"\s*\([^)]*\)", "", p).strip()
                            if p_clean and p_clean not in aliases and p_clean != common_name:
                                aliases.append(p_clean)

            mitre_id = None
            if mitre_idx != -1 and mitre_idx < len(row):
                mitre_val = row[mitre_idx].strip()
                m = re.search(r"G\d{4}", mitre_val)
                if m:
                    mitre_id = m.group(0)

            mo_val = row[mo_idx].strip() if mo_idx != -1 and mo_idx < len(row) else ""
            comment_val = (
                row[comment_idx].strip() if comment_idx != -1 and comment_idx < len(row) else ""
            )
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
                    sectors = [t.strip() for t in re.split(r"[,;•\n]", target_val) if t.strip()]

            links = []
            for col_idx in link_cols:
                if col_idx < len(row):
                    val = row[col_idx].strip()
                    if val.startswith("http"):
                        links.append(val)
            for cell in row:
                if cell.strip().startswith("http") and cell.strip() not in links:
                    links.append(cell.strip())

            combined_text = (
                f"{common_name} {' '.join(aliases)} {description or ''} {' '.join(sectors)}"
            )
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
                    existing.description = (
                        f"{existing.description}\n\n{description}"
                        if existing.description
                        else description
                    )

                existing_sectors = set(existing.sectors_targeted or [])
                for s in sectors:
                    if len(s) < 50 and not any(
                        c.lower() in s.lower()
                        for c in ["korea", "china", "vietnam", "russia", "usa", "europe", "japan"]
                    ):
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
                clean_sectors = [
                    s
                    for s in sectors
                    if len(s) < 50
                    and not any(
                        c.lower() in s.lower()
                        for c in ["korea", "china", "vietnam", "russia", "usa", "europe", "japan"]
                    )
                ]
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
        req = urllib.request.Request(url, headers={"User-Agent": "Pythia/0.1 (seed-builder)"})
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                content = response.read().decode("utf-8")
        except Exception as e:
            print(f"  abuse.ch ThreatFox [{ioc_type}]: download failed ({e}) — skipping")
            continue

        csv_lines = [line for line in content.splitlines() if not line.startswith("#")]
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
            source_url = (
                reference
                if reference and reference.lower() != "none"
                else "https://threatfox.abuse.ch"
            )

            if dry_run:
                added += 1
                continue

            existing = session.query(IoC).filter_by(type=mapped_type, value=ioc_val).first()
            if not existing:
                session.add(
                    IoC(
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
                    )
                )
                added += 1
        if not dry_run:
            session.commit()
        print(f"  abuse.ch ThreatFox [{ioc_type}]: {added} indicators added")
        total_added += added

    _log_sync_status(session, "abuse_ch", "ok", dry_run)
    return total_added


def seed_intel_feeds(session: Any, dry_run: bool) -> int:
    """Populate intel_feed_sources from data/seed/intel_feeds.json (upsert by URL)."""
    from pythia.models.intel_feed import IntelFeedSource

    feeds_path = _DATA_DIR / "seed" / "intel_feeds.json"
    if not feeds_path.exists():
        print("  intel-feeds: data/seed/intel_feeds.json not found — skipping")
        return 0

    with feeds_path.open() as f:
        feeds: list[dict[str, Any]] = json.load(f)

    added = 0
    for entry in feeds:
        url = entry["url"]
        if dry_run:
            added += 1
            continue
        existing = session.query(IntelFeedSource).filter_by(url=url).first()
        if not existing:
            session.add(IntelFeedSource(
                name=entry["name"],
                vendor=entry["vendor"],
                url=url,
            ))
            added += 1

    if not dry_run:
        session.commit()
    print(f"  intel-feeds: {added} sources added")
    _log_sync_status(session, "intel_feeds", "ok", dry_run)
    return added


def seed_sophistication(session: Any, dry_run: bool) -> int:
    """Compute and persist heuristic sophistication scores for all threat actors.

    Uses TTP count, tactic breadth, sponsor type, and name signals.  Safe to
    re-run; only writes when the computed score differs from what is stored.
    """
    from sqlalchemy import text

    from pythia.ingestion.enrichment import compute_sophistication

    # Single join to fetch all actor→tactics data efficiently
    rows = session.execute(text("""
        SELECT m.actor_id, at.tactics
        FROM actor_ttp_mappings m
        LEFT JOIN attck_techniques at ON at.technique_id = m.technique_id
    """)).fetchall()

    actor_tactics: dict[str, set[str]] = {}
    for actor_id, tactics_val in rows:
        if tactics_val:
            tactics = (
                tactics_val
                if isinstance(tactics_val, list)
                else json.loads(tactics_val)
            )
            actor_tactics.setdefault(actor_id, set()).update(tactics)

    # Pre-compute TTP counts to avoid N queries
    count_rows = session.execute(text(
        "SELECT actor_id, COUNT(*) FROM actor_ttp_mappings GROUP BY actor_id"
    )).fetchall()
    ttp_counts: dict[str, int] = {r[0]: r[1] for r in count_rows}

    updated = 0
    actors = session.query(ThreatActor).all()
    for actor in actors:
        score = compute_sophistication(
            sponsor_type=actor.sponsor_type,
            name=actor.name,
            ttp_count=ttp_counts.get(actor.id, 0),
            covered_tactics=actor_tactics.get(actor.id, set()),
        )
        if actor.sophistication != score:
            if not dry_run:
                actor.sophistication = score
            updated += 1

    if not dry_run:
        session.commit()
    print(f"  Sophistication scoring: {updated}/{len(actors)} actors scored/updated")
    _log_sync_status(session, "sophistication", "ok", dry_run)
    return updated


def seed_otx_actors(session: Any, dry_run: bool) -> int:
    """Fetch ATT&CK technique mappings from AlienVault OTX adversary-tagged pulses.

    Requires OTX_API_KEY.  For each OTX pulse that names a known adversary and
    includes MITRE ATT&CK tags, TTP mappings are added to the matching actor.
    """
    from pythia.core.config import get_settings
    settings = get_settings()
    api_key = settings.otx_api_key
    if not api_key:
        print("  OTX: no OTX_API_KEY set — skipping")
        _log_sync_status(session, "otx", "no_key", dry_run)
        return 0

    base = "https://otx.alienvault.com/api/v1"
    headers = {"X-OTX-API-KEY": api_key, "User-Agent": "Pythia/0.1 (seed-builder)"}
    tech_re = re.compile(r"^T\d{4}(?:\.\d{3})?$")

    # Build actor lookup: name (lower) → ThreatActor
    actors_by_name: dict[str, ThreatActor] = {}
    actors_by_alias: dict[str, ThreatActor] = {}
    if not dry_run:
        for a in session.query(ThreatActor).all():
            actors_by_name[a.name.lower()] = a
            for al in (a.aliases or []):
                actors_by_alias[al.lower()] = a

    def _find_actor(name: str) -> ThreatActor | None:
        n = name.lower()
        return actors_by_name.get(n) or actors_by_alias.get(n)

    def _get_json(url: str) -> Any | None:
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except Exception as exc:
            print(f"  OTX request failed ({exc})")
            return None

    # Paginate through subscribed pulses
    page_url = f"{base}/pulses/subscribed?limit=100&include_referenced=false"
    total_mappings = 0
    pages_fetched = 0
    max_pages = 20  # cap to avoid rate limiting on initial seed

    print("  OTX: fetching adversary-tagged pulses...", end=" ", flush=True)
    while page_url and pages_fetched < max_pages:
        data = _get_json(page_url)
        if not data:
            break
        results = data.get("results", [])
        pages_fetched += 1

        for pulse in results:
            adversary: str = (pulse.get("adversary") or "").strip()
            if not adversary:
                continue

            # Extract ATT&CK technique IDs from pulse tags
            tags: list[str] = pulse.get("tags", []) or []
            attack_ids: list[str] = pulse.get("attack_ids", []) or []
            tech_ids = [
                t for t in attack_ids + tags if tech_re.match(t.strip())
            ]
            if not tech_ids:
                continue

            if dry_run:
                total_mappings += len(tech_ids)
                continue

            actor = _find_actor(adversary)
            if not actor:
                continue

            existing = {m.technique_id for m in actor.ttp_mappings}
            for tid in tech_ids:
                tid = tid.strip()
                if tid not in existing:
                    session.add(ActorTTPMapping(
                        actor_id=actor.id,
                        technique_id=tid,
                        use_note=None,
                        source="otx",
                    ))
                    existing.add(tid)
                    total_mappings += 1

        next_url = data.get("next")
        page_url = next_url if next_url else None

    if not dry_run:
        session.commit()
    print(f"done — {total_mappings} TTP mappings added across {pages_fetched} pages")
    _log_sync_status(session, "otx", "ok", dry_run)
    return total_mappings


def seed_claude_ttp_inference(session: Any, dry_run: bool) -> int:
    """Use Claude to infer ATT&CK technique IDs for actors with descriptions but no TTPs.

    Requires ANTHROPIC_API_KEY.  Processes up to 50 actors per run to stay within
    API cost limits.  Only targets actors with a description and zero existing TTP
    mappings (excluding those with attck_group_id already covered by the ATT&CK seed).
    """
    from pythia.core.config import get_settings
    from pythia.ingestion.enrichment import infer_ttps_from_description
    settings = get_settings()
    if not settings.anthropic_api_key:
        print("  Claude TTP inference: no ANTHROPIC_API_KEY set — skipping")
        _log_sync_status(session, "claude_ttp", "no_key", dry_run)
        return 0

    # Actors with a description but no TTP mappings and no ATT&CK group coverage
    candidates = (
        session.query(ThreatActor)
        .filter(ThreatActor.description.isnot(None))
        .filter(ThreatActor.attck_group_id.is_(None))
        .filter(~ThreatActor.ttp_mappings.any())
        .limit(50)
        .all()
    )

    if not candidates:
        print("  Claude TTP inference: no eligible actors found — skipping")
        return 0

    print(f"  Claude TTP inference: inferring TTPs for {len(candidates)} actors...", end=" ", flush=True)
    total_added = 0
    for actor in candidates:
        if dry_run:
            total_added += 5  # rough estimate
            continue
        tech_ids = infer_ttps_from_description(actor, session)
        for tid in tech_ids:
            session.add(ActorTTPMapping(
                actor_id=actor.id,
                technique_id=tid,
                use_note="inferred by Claude from actor description",
                source="claude-inference",
            ))
            total_added += 1
        if tech_ids:
            session.flush()

    if not dry_run:
        session.commit()
    print(f"done — {total_added} inferred TTP mappings added")
    _log_sync_status(session, "claude_ttp", "ok", dry_run)
    return total_added


def dedup_attck_actors(session: Any, dry_run: bool) -> int:
    """Merge ATT&CK-sourced duplicate actors into their richer MISP counterparts.

    When seed_attck ran before the alias-matching fix it created thin actors like
    "Threat Group-3390" for groups whose canonical ATT&CK name didn't match any
    existing actor by name.  Those duplicates hold the TTP mappings while the real
    MISP record (APT27, APT10, …) has aliases, country codes, and sector data.

    This function detects each (attck_dup, primary) pair — where primary.aliases
    contains attck_dup.attck_group_id — and merges them: TTPs transfer to primary,
    the duplicate is deleted.
    """
    attck_actors = session.query(ThreatActor).filter_by(source="attck").all()

    merged = 0
    for dup in attck_actors:
        if not dup.attck_group_id:
            continue
        gid = dup.attck_group_id

        # Find a non-attck actor whose aliases JSON contains this G-ID
        primary: ThreatActor | None = None
        for candidate in (
            session.query(ThreatActor)
            .filter(
                ThreatActor.id != dup.id,
                ThreatActor.source != "attck",
            )
            .all()
        ):
            if gid in (candidate.aliases or []):
                primary = candidate
                break

        if not primary:
            continue

        if dry_run:
            print(f"    would merge '{dup.name}' ({gid}) → '{primary.name}'")
            merged += 1
            continue

        # Transfer TTP mappings via raw SQL to avoid cascade-delete wiping them.
        # We move rows that don't already exist on primary, drop the rest.
        from sqlalchemy import text

        session.execute(
            text("""
            UPDATE actor_ttp_mappings
            SET actor_id = :primary_id
            WHERE actor_id = :dup_id
              AND technique_id NOT IN (
                  SELECT technique_id FROM actor_ttp_mappings WHERE actor_id = :primary_id
              )
        """),
            {"primary_id": primary.id, "dup_id": dup.id},
        )

        # Copy enrichment fields that primary lacks
        if not primary.attck_group_id:
            primary.attck_group_id = gid
        if dup.description and not primary.description:
            primary.description = dup.description
        for alias in dup.aliases or []:
            if alias not in (primary.aliases or []):
                primary.aliases = (primary.aliases or []) + [alias]
        for ref in dup.references or []:
            if ref not in (primary.references or []):
                primary.references = (primary.references or []) + [ref]
        if dup.source_url and not primary.source_url:
            primary.source_url = dup.source_url

        # Expire the ORM cache so the delete cascade sees no remaining mappings
        session.expire(dup)
        session.flush()
        session.delete(dup)
        merged += 1

    if not dry_run:
        session.commit()
    print(f"  ATT&CK dedup: {merged} duplicate actors merged")
    return merged


def run(sources: list[str] | None = None, dry_run: bool = False) -> None:
    targets = sources or [
        "misp-galaxy", "attck", "atlas", "kev", "sigma", "owasp", "apt-sheet",
        "sigma-full", "signature-base",
    ]
    print(
        f"Pythia seed pipeline {'(dry-run) ' if dry_run else ''}— targets: {', '.join(targets)}\n"
    )

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

        if any(
            t in targets
            for t in ("attck", "attck-enterprise", "attck-mobile", "attck-ics", "dedup")
        ):
            total += dedup_attck_actors(session, dry_run)

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

        if "mitre-malware" in targets:
            total += seed_mitre_malware(session, dry_run)

        if "misp-malware" in targets:
            total += seed_misp_malware(session, dry_run)

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

        if "intel-feeds" in targets:
            total += seed_intel_feeds(session, dry_run)

        if "otx" in targets:
            total += seed_otx_actors(session, dry_run)

        if "claude-ttp" in targets:
            total += seed_claude_ttp_inference(session, dry_run)

        # Sophistication scoring runs after all TTP data is in place
        if "sophistication" in targets or not sources:
            total += seed_sophistication(session, dry_run)

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
    m = re.search(r"^rule\s+(\w+)", content, re.MULTILINE)
    return m.group(1) if m else Path(filename).stem


def _extract_yara_technique_ids(content: str) -> list[str]:
    """Extract ATT&CK technique IDs referenced in a YARA rule's meta section."""
    ids = re.findall(r"\b(T\d{4}(?:\.\d{3})?)\b", content)
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
            session.add(
                IoC(
                    type="ip",
                    value=ip_val,
                    confidence_source=conf_source,
                    confidence_info="2",
                    tlp="WHITE",
                    pyramid_tier="network",
                    context=f"IPsum aggregated blocklist — flagged by {score} source(s).",
                    source_url=url,
                )
            )
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
            session.add(
                IoC(
                    type="url",
                    value=phish_url,
                    confidence_source="A" if verified else "C",
                    confidence_info="2",
                    tlp="WHITE",
                    pyramid_tier="artifact",
                    context="PhishTank community-verified phishing URL.",
                    source_url="https://www.phishtank.com/",
                )
            )
            added += 1

    if not dry_run:
        session.commit()
    print(f"  PhishTank: {added} phishing URLs added")
    _log_sync_status(session, "phishtank", "ok", dry_run)
    return added


_FAMILY_TYPE_KEYWORDS: list[tuple[str, str]] = [
    ("ransomware", "ransomware"),
    ("wiper", "ransomware"),
    ("remote access trojan", "trojan"),
    (" rat ", "trojan"),
    ("remote administration tool", "trojan"),
    ("banking trojan", "trojan"),
    ("trojan", "trojan"),
    ("backdoor", "backdoor"),
    ("rootkit", "backdoor"),
    ("worm", "worm"),
    ("loader", "loader"),
    ("downloader", "loader"),
    ("dropper", "loader"),
    ("infostealer", "stealer"),
    ("info-stealer", "stealer"),
    ("credential stealer", "stealer"),
    ("keylogger", "stealer"),
    ("stealer", "stealer"),
    ("botnet", "botnet"),
    (" bot ", "botnet"),
]

_MISP_TYPE_MAP: dict[str, str] = {
    "ransomware": "ransomware",
    "rat": "trojan",
    "remote access trojan": "trojan",
    "banking trojan": "trojan",
    "trojan": "trojan",
    "backdoor": "backdoor",
    "rootkit": "backdoor",
    "worm": "worm",
    "loader": "loader",
    "dropper": "loader",
    "downloader": "loader",
    "stealer": "stealer",
    "infostealer": "stealer",
    "keylogger": "stealer",
    "botnet": "botnet",
    "bot": "botnet",
}


def _derive_family_type(text: str) -> str | None:
    lower = text.lower()
    for keyword, ftype in _FAMILY_TYPE_KEYWORDS:
        if keyword in lower:
            return ftype
    return None


def _ensure_mitre_id_column(session: Any) -> None:
    """Add mitre_id column to malware_families if it doesn't exist (idempotent)."""
    from sqlalchemy import text

    try:
        session.execute(text("ALTER TABLE malware_families ADD COLUMN mitre_id VARCHAR"))
        session.commit()
    except Exception:
        session.rollback()


def seed_mitre_malware(session: Any, dry_run: bool) -> int:
    """Ingest malware/tool software objects from the MITRE ATT&CK STIX bundle."""
    data = _fetch(SOURCES["attck-enterprise"], "MITRE ATT&CK software")
    if not data:
        return 0

    if not dry_run:
        _ensure_mitre_id_column(session)

    objects: list[dict[str, Any]] = data.get("objects", [])
    sw_objects = [o for o in objects if o.get("type") in ("malware", "tool")]

    added = 0
    seen_names: set[str] = set()
    seen_mitre_ids: set[str] = set()

    for obj in sw_objects:
        name: str = (obj.get("name") or "").strip()
        if not name:
            continue

        description: str = obj.get("description") or ""
        aliases_raw: list[str] = obj.get("x_mitre_aliases") or []
        aliases = [a for a in aliases_raw if a != name]

        ext_refs: list[dict[str, Any]] = obj.get("external_references") or []
        mitre_ref = next((r for r in ext_refs if r.get("source_name") == "mitre-attack"), None)
        if not mitre_ref:
            continue
        mitre_id: str = mitre_ref.get("external_id") or ""
        if not mitre_id:
            continue

        if mitre_id in seen_mitre_ids or name in seen_names:
            continue

        source_url = f"https://attack.mitre.org/software/{mitre_id}/"
        other_refs = [r["url"] for r in ext_refs if r.get("source_name") != "mitre-attack" and r.get("url")]
        family_type = _derive_family_type(description + " " + name)

        if dry_run:
            added += 1
            seen_names.add(name)
            seen_mitre_ids.add(mitre_id)
            continue

        try:
            existing = (
                session.query(MalwareFamily).filter_by(mitre_id=mitre_id).first()
                or session.query(MalwareFamily).filter_by(name=name).first()
            )
            if existing:
                if not existing.mitre_id:
                    existing.mitre_id = mitre_id
                if description and not existing.description:
                    existing.description = description
                if family_type and not existing.family_type:
                    existing.family_type = family_type
                if aliases and not existing.aliases:
                    existing.aliases = aliases
            else:
                session.add(
                    MalwareFamily(
                        name=name,
                        aliases=aliases,
                        description=description,
                        family_type=family_type,
                        actor_ids=[],
                        rule_ids=[],
                        references=other_refs,
                        source="mitre-attack",
                        source_url=source_url,
                        mitre_id=mitre_id,
                    )
                )
                added += 1
            session.flush()
            seen_names.add(name)
            seen_mitre_ids.add(mitre_id)
        except Exception:
            session.rollback()

    if not dry_run:
        session.commit()
    print(f"  MITRE ATT&CK malware: {added} families added/updated")
    _log_sync_status(session, "mitre_malware", "ok", dry_run)
    return added


def seed_misp_malware(session: Any, dry_run: bool) -> int:
    """Ingest malware families from the MISP Galaxy Malpedia cluster."""
    data = _fetch(SOURCES["misp-malpedia"], "MISP Galaxy malpedia cluster")
    if not data:
        return 0

    if not dry_run:
        _ensure_mitre_id_column(session)

    values: list[dict[str, Any]] = data.get("values", [])
    added = 0
    seen_names: set[str] = set()

    for entry in values:
        raw_name: str = (entry.get("value") or "").strip()
        if not raw_name:
            continue
        name = raw_name

        if name in seen_names:
            continue

        description: str = entry.get("description") or ""
        meta: dict[str, Any] = entry.get("meta") or {}
        synonyms: list[str] = meta.get("synonyms") or []
        refs: list[str] = [r for r in (meta.get("refs") or []) if r]

        raw_types: list[str] = meta.get("type") or []
        family_type: str | None = None
        for t in raw_types:
            mapped = _MISP_TYPE_MAP.get(t.lower().strip())
            if mapped:
                family_type = mapped
                break
        if not family_type:
            family_type = _derive_family_type(description + " " + name)

        if dry_run:
            added += 1
            seen_names.add(name)
            continue

        try:
            existing = session.query(MalwareFamily).filter_by(name=name).first()
            if existing:
                if family_type and not existing.family_type:
                    existing.family_type = family_type
                if description and not existing.description:
                    existing.description = description
                if synonyms and not existing.aliases:
                    existing.aliases = synonyms
            else:
                session.add(
                    MalwareFamily(
                        name=name,
                        aliases=synonyms,
                        description=description,
                        family_type=family_type,
                        actor_ids=[],
                        rule_ids=[],
                        references=refs,
                        source="misp-galaxy",
                        source_url=SOURCES["misp-malpedia"],
                    )
                )
                added += 1
            session.flush()
            seen_names.add(name)
        except Exception:
            session.rollback()

    if not dry_run:
        session.commit()
    print(f"  MISP Galaxy malpedia: {added} families added/updated")
    _log_sync_status(session, "misp_malware", "ok", dry_run)
    return added


def seed_malpedia(session: Any, dry_run: bool) -> int:
    """Ingest malware family records from Malpedia (anonymous public access only)."""
    base_url = "https://malpedia.caad.fkie.fraunhofer.de"
    headers: dict[str, str] = {"User-Agent": "Pythia/0.1 (seed-builder)"}

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
            session.add(
                MalwareFamily(
                    name=name,
                    aliases=[],
                    family_type=family_type,
                    actor_ids=[],
                    rule_ids=[],
                    references=[],
                    source="malpedia",
                    source_url=f"{base_url}/families/{slug}",
                    malpedia_slug=slug,
                )
            )
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
                name for name in zf.namelist() if "/rules/" in name and name.endswith(".yml")
            ]
            for zpath in rule_paths:
                try:
                    content = zf.read(zpath).decode("utf-8", errors="replace")
                except Exception:
                    continue

                title_m = re.search(r"^title:\s*(.+)$", content, re.MULTILINE)
                title = title_m.group(1).strip() if title_m else Path(zpath).stem
                level_m = re.search(r"^level:\s*(\S+)", content, re.MULTILINE)
                level = level_m.group(1).strip() if level_m else None
                status_m = re.search(r"^status:\s*(\S+)", content, re.MULTILINE)
                rule_status = status_m.group(1).strip() if status_m else None
                technique_ids = list(
                    dict.fromkeys(
                        m.upper()
                        for m in re.findall(r"attack\.(t\d{4}(?:\.\d{3})?)", content, re.IGNORECASE)
                    )
                )

                if dry_run:
                    added += 1
                    continue

                if (
                    not session.query(DetectionRule)
                    .filter_by(title=title, rule_type="sigma")
                    .first()
                ):
                    session.add(
                        DetectionRule(
                            rule_type="sigma",
                            title=title,
                            content=content,
                            technique_ids=technique_ids,
                            actor_ids=[],
                            severity=level,
                            status=rule_status,
                            source="sigma-full",
                            source_url="https://github.com/SigmaHQ/sigma",
                        )
                    )
                    added += 1

        if not dry_run:
            session.commit()
    finally:
        tmp_path.unlink(missing_ok=True)

    print(f"  SigmaHQ full: {added} rules added")
    _log_sync_status(session, "sigma_full", "ok", dry_run)
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
                name
                for name in zf.namelist()
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

                if (
                    not session.query(DetectionRule)
                    .filter_by(title=title, rule_type="yara")
                    .first()
                ):
                    session.add(
                        DetectionRule(
                            rule_type="yara",
                            title=title,
                            content=content,
                            technique_ids=technique_ids,
                            actor_ids=[],
                            severity=None,
                            status="stable",
                            source="yara-rules",
                            source_url="https://github.com/Yara-Rules/rules",
                        )
                    )
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
                name
                for name in zf.namelist()
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

                if (
                    not session.query(DetectionRule)
                    .filter_by(title=title, rule_type="yara")
                    .first()
                ):
                    session.add(
                        DetectionRule(
                            rule_type="yara",
                            title=title,
                            content=content,
                            technique_ids=technique_ids,
                            actor_ids=[],
                            severity=None,
                            status="stable",
                            source="icewater",
                            source_url="https://github.com/SupportIntelligence/Icewater",
                        )
                    )
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
                    title_m = re.search(r"^title:\s*(.+)$", content, re.MULTILINE)
                    title = title_m.group(1).strip() if title_m else Path(zpath).stem
                    level_m = re.search(r"^level:\s*(\S+)", content, re.MULTILINE)
                    severity = level_m.group(1).strip() if level_m else None
                    status_m = re.search(r"^status:\s*(\S+)", content, re.MULTILINE)
                    status = status_m.group(1).strip() if status_m else None
                    technique_ids = list(
                        dict.fromkeys(
                            m.upper()
                            for m in re.findall(
                                r"attack\.(t\d{4}(?:\.\d{3})?)", content, re.IGNORECASE
                            )
                        )
                    )

                if dry_run:
                    added += 1
                    continue

                if (
                    not session.query(DetectionRule)
                    .filter_by(title=title, rule_type=rule_type)
                    .first()
                ):
                    session.add(
                        DetectionRule(
                            rule_type=rule_type,
                            title=title,
                            content=content,
                            technique_ids=technique_ids,
                            actor_ids=[],
                            severity=severity,
                            status=status,
                            source="signature-base",
                            source_url="https://github.com/Neo23x0/signature-base",
                        )
                    )
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
            "sigma-full signature-base abuse-ch ipsum phishtank malpedia yara-rules icewater "
            "otx claude-ttp sophistication dedup"
        ),
    )
    parser.add_argument("--dry-run", action="store_true", help="Count only, no DB writes")
    args = parser.parse_args()
    run(sources=args.sources, dry_run=args.dry_run)
