#!/usr/bin/env python3
"""Load synthetic CTI data into the Pythia database for demo and testing.

Usage:
    PYTHONPATH=src python3 scripts/load_synthetic_data.py [--reset] [--dry-run]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Ensure the package is importable when run directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from pythia.core.db import SessionLocal, init_db
from pythia.models.actor import ActorTTPMapping, ThreatActor
from pythia.models.atlas import AtlasTechnique
from pythia.models.attck import AttckTechnique
from pythia.models.ioc import IoC
from pythia.models.owasp_llm import OwaspLlmItem
from pythia.models.report import BusinessImpactBrief, SourceReport
from pythia.models.rule import DetectionRule
from pythia.models.watchlist import Watchlist


def synthetic_id(namespace: str, key: str) -> str:
    """Stable UUID derived from namespace + key — same input always yields same UUID."""
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"pythia.synthetic.{namespace}.{key}"))


def ok(msg: str) -> None:
    print(f"  \033[32m✓\033[0m {msg}")


def skip(msg: str) -> None:
    print(f"  \033[33m–\033[0m {msg} (already exists, skipping)")


# ── SECTION 1: ATT&CK Techniques ──────────────────────────────────────────

def load_attck_techniques(session: SessionLocal, dry_run: bool) -> None:
    techniques = [
        # Enterprise Tactics
        {"technique_id": "T1566", "name": "Phishing", "tactics": ["initial-access"], "is_sub": False, "parent": None, "domain": "enterprise"},
        {"technique_id": "T1566.001", "name": "Spearphishing Attachment", "tactics": ["initial-access"], "is_sub": True, "parent": "T1566", "domain": "enterprise"},
        {"technique_id": "T1566.002", "name": "Spearphishing Link", "tactics": ["initial-access"], "is_sub": True, "parent": "T1566", "domain": "enterprise"},
        
        {"technique_id": "T1059", "name": "Command and Scripting Interpreter", "tactics": ["execution"], "is_sub": False, "parent": None, "domain": "enterprise"},
        {"technique_id": "T1059.001", "name": "PowerShell", "tactics": ["execution"], "is_sub": True, "parent": "T1059", "domain": "enterprise"},
        {"technique_id": "T1059.003", "name": "Windows Command Shell", "tactics": ["execution"], "is_sub": True, "parent": "T1059", "domain": "enterprise"},
        {"technique_id": "T1059.006", "name": "Python", "tactics": ["execution"], "is_sub": True, "parent": "T1059", "domain": "enterprise"},
        
        {"technique_id": "T1027", "name": "Obfuscated Files or Information", "tactics": ["defense-evasion"], "is_sub": False, "parent": None, "domain": "enterprise"},
        {"technique_id": "T1078", "name": "Valid Accounts", "tactics": ["initial-access", "persistence", "privilege-escalation"], "is_sub": False, "parent": None, "domain": "enterprise"},
        
        {"technique_id": "T1071", "name": "Application Layer Protocol", "tactics": ["command-and-control"], "is_sub": False, "parent": None, "domain": "enterprise"},
        {"technique_id": "T1071.001", "name": "Web Protocols", "tactics": ["command-and-control"], "is_sub": True, "parent": "T1071", "domain": "enterprise"},
        
        {"technique_id": "T1486", "name": "Data Encrypted for Impact", "tactics": ["impact"], "is_sub": False, "parent": None, "domain": "enterprise"},
        {"technique_id": "T1490", "name": "Inhibit System Recovery", "tactics": ["impact"], "is_sub": False, "parent": None, "domain": "enterprise"},
        
        {"technique_id": "T1053", "name": "Scheduled Task/Job", "tactics": ["persistence", "privilege-escalation", "execution"], "is_sub": False, "parent": None, "domain": "enterprise"},
        {"technique_id": "T1053.005", "name": "Scheduled Task", "tactics": ["persistence", "execution"], "is_sub": True, "parent": "T1053", "domain": "enterprise"},
        
        {"technique_id": "T1547", "name": "Boot or Logon Autostart Execution", "tactics": ["persistence", "privilege-escalation"], "is_sub": False, "parent": None, "domain": "enterprise"},
        {"technique_id": "T1105", "name": "Ingress Tool Transfer", "tactics": ["command-and-control"], "is_sub": False, "parent": None, "domain": "enterprise"},
        {"technique_id": "T1190", "name": "Exploit Public-Facing Application", "tactics": ["initial-access"], "is_sub": False, "parent": None, "domain": "enterprise"},
        
        {"technique_id": "T1595", "name": "Active Scanning", "tactics": ["reconnaissance"], "is_sub": False, "parent": None, "domain": "enterprise"},
        {"technique_id": "T1595.002", "name": "Vulnerability Scanning", "tactics": ["reconnaissance"], "is_sub": True, "parent": "T1595", "domain": "enterprise"},
        {"technique_id": "T1589", "name": "Gather Victim Identity Information", "tactics": ["reconnaissance"], "is_sub": False, "parent": None, "domain": "enterprise"},
        {"technique_id": "T1588", "name": "Obtain Capabilities", "tactics": ["resource-development"], "is_sub": False, "parent": None, "domain": "enterprise"},
        {"technique_id": "T1583", "name": "Acquire Infrastructure", "tactics": ["resource-development"], "is_sub": False, "parent": None, "domain": "enterprise"},
        
        {"technique_id": "T1091", "name": "Replication Through Removable Media", "tactics": ["initial-access", "lateral-movement"], "is_sub": False, "parent": None, "domain": "enterprise"},
        {"technique_id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactics": ["privilege-escalation", "defense-evasion"], "is_sub": False, "parent": None, "domain": "enterprise"},
        {"technique_id": "T1055", "name": "Process Injection", "tactics": ["defense-evasion", "privilege-escalation"], "is_sub": False, "parent": None, "domain": "enterprise"},
        {"technique_id": "T1003", "name": "OS Credential Dumping", "tactics": ["credential-access"], "is_sub": False, "parent": None, "domain": "enterprise"},
        {"technique_id": "T1082", "name": "System Information Discovery", "tactics": ["discovery"], "is_sub": False, "parent": None, "domain": "enterprise"},
        {"technique_id": "T1021", "name": "Remote Services", "tactics": ["lateral-movement"], "is_sub": False, "parent": None, "domain": "enterprise"},
        {"technique_id": "T1560", "name": "Archive Collected Data", "tactics": ["collection"], "is_sub": False, "parent": None, "domain": "enterprise"},
        {"technique_id": "T1041", "name": "Exfiltration Over C2 Channel", "tactics": ["exfiltration"], "is_sub": False, "parent": None, "domain": "enterprise"},
        {"technique_id": "T1485", "name": "Data Destruction", "tactics": ["impact"], "is_sub": False, "parent": None, "domain": "enterprise"},
        {"technique_id": "T1046", "name": "Network Service Discovery", "tactics": ["discovery"], "is_sub": False, "parent": None, "domain": "enterprise"},
        {"technique_id": "T1113", "name": "Screen Capture", "tactics": ["collection"], "is_sub": False, "parent": None, "domain": "enterprise"},
        {"technique_id": "T1195", "name": "Supply Chain Compromise", "tactics": ["initial-access"], "is_sub": False, "parent": None, "domain": "enterprise"},

        # Mobile Tactics
        {"technique_id": "T1566_mob", "name": "Phishing (Mobile)", "tactics": ["initial-access"], "is_sub": False, "parent": None, "domain": "mobile"},
        {"technique_id": "T1471", "name": "Data Encrypted for Impact", "tactics": ["impact"], "is_sub": False, "parent": None, "domain": "mobile"},

        # ICS Tactics
        {"technique_id": "T0853", "name": "Scripting", "tactics": ["execution"], "is_sub": False, "parent": None, "domain": "ics"},
        {"technique_id": "T0882", "name": "Theft of Operational Information", "tactics": ["collection"], "is_sub": False, "parent": None, "domain": "ics"},
    ]

    added = 0
    added_ids = set()
    for t in techniques:
        tech_id = t["technique_id"]
        # Standardise the mobile phishing ID to represent it nicely
        db_id = "T1566" if tech_id == "T1566_mob" else tech_id
        
        if db_id in added_ids:
            continue
        added_ids.add(db_id)
        
        # Check existing
        existing = session.get(AttckTechnique, db_id)
        if existing:
            continue

        desc = f"Synthetic demonstration data for {t['name']} ({db_id}). This MITRE ATT&CK technique enables realistic correlation of threat actor playbooks."
        det = f"Monitor system logs, process execution structures, and network flows for patterns matching standard {t['name']} behavior."

        tech = AttckTechnique(
            technique_id=db_id,
            name=t["name"],
            description=desc,
            tactics=t["tactics"],
            is_subtechnique=t["is_sub"],
            parent_id=t["parent"],
            domain=t["domain"],
            detection_note=det,
            platforms=["Windows", "Linux", "macOS"] if t["domain"] == "enterprise" else ["Android", "iOS"] if t["domain"] == "mobile" else ["Engineering Workstation"],
            data_sources=["Process", "Network Traffic", "File"],
            mitigations=[{"id": "M1001", "name": "User Training", "desc": "Train users to identify malicious behavior."}],
            source_url=f"https://attack.mitre.org/techniques/{db_id.replace('.', '/')}/",
        )
        if not dry_run:
            session.add(tech)
        added += 1

    if not dry_run:
        session.commit()
    ok(f"Loaded {added} ATT&CK Techniques.")


# ── SECTION 2: ATLAS Techniques ──────────────────────────────────────────

def load_atlas_techniques(session: SessionLocal, dry_run: bool) -> None:
    techniques = [
        {"technique_id": "AML.T0000", "name": "ML Model Access", "tactics": ["ML Model Access"]},
        {"technique_id": "AML.T0006", "name": "Active Learning", "tactics": ["ML Attack Staging"]},
        {"technique_id": "AML.T0020", "name": "Poison Training Data", "tactics": ["ML Attack Staging"], "subtechniques": ["AML.T0020.000", "AML.T0020.001"]},
        {"technique_id": "AML.T0043", "name": "Craft Adversarial Data", "tactics": ["ML Attack Staging"]},
        {"technique_id": "AML.T0048", "name": "Backdoor ML Model", "tactics": ["ML Attack Staging"]},
        {"technique_id": "AML.T0051", "name": "LLM Prompt Injection", "tactics": ["Initial Access", "ML Attack Staging"]},
        {"technique_id": "AML.T0054", "name": "LLM Jailbreak", "tactics": ["ML Attack Staging"]},
        {"technique_id": "AML.T0040", "name": "ML Model Inference API Access", "tactics": ["ML Model Access"]},
        {"technique_id": "AML.T0031", "name": "Erode ML Model Integrity", "tactics": ["Impact"]},
        {"technique_id": "AML.T0044", "name": "Full ML Model Access", "tactics": ["ML Model Access"]},
        {"technique_id": "AML.T0005", "name": "Create Proxy ML Model", "tactics": ["ML Attack Staging"]},
        {"technique_id": "AML.T0047", "name": "ML-Enabled Product or Service", "tactics": ["Reconnaissance"]},
    ]

    added = 0
    for t in techniques:
        tech_id = t["technique_id"]
        existing = session.get(AtlasTechnique, tech_id)
        if existing:
            continue

        desc = f"Synthetic adversary technique for MITRE ATLAS: {t['name']} ({tech_id}). Leveraged in testing AI vulnerability shielding mechanisms."
        
        tech = AtlasTechnique(
            technique_id=tech_id,
            name=t["name"],
            description=desc,
            tactics=t["tactics"],
            subtechniques=[{"id": sub, "name": f"{t['name']} - Variant"} for sub in t.get("subtechniques", [])],
            mitigations=[{"id": "AML.M1001", "name": "Input Scannings", "desc": "Scan inputs for adversarial strings."}],
            case_study_refs=["Adversarial LLM Prompts 2024"],
            source_url=f"https://atlas.mitre.org/techniques/{tech_id}",
        )
        if not dry_run:
            session.add(tech)
        added += 1

    if not dry_run:
        session.commit()
    ok(f"Loaded {added} ATLAS Techniques.")


# ── SECTION 3: OWASP LLM Top 10 ──────────────────────────────────────────

def load_owasp_llm(session: SessionLocal, dry_run: bool) -> None:
    items = [
        {"item_id": "LLM01:2025", "rank": 1, "name": "Prompt Injection", "atlas": ["AML.T0051", "AML.T0054"], "cwes": ["CWE-20", "CWE-116"], "mitigations": ["Input validation", "Sandboxing", "Least privilege"]},
        {"item_id": "LLM02:2025", "rank": 2, "name": "Sensitive Information Disclosure", "atlas": ["AML.T0048", "AML.T0043"], "cwes": ["CWE-200", "CWE-209"], "mitigations": ["Output filtering", "Data classification", "Access control"]},
        {"item_id": "LLM03:2025", "rank": 3, "name": "Supply Chain Vulnerabilities", "atlas": ["AML.T0048"], "cwes": ["CWE-494", "CWE-829"], "mitigations": ["Model provenance", "SBOM", "Code signing"]},
        {"item_id": "LLM04:2025", "rank": 4, "name": "Data and Model Poisoning", "atlas": ["AML.T0020"], "cwes": ["CWE-345", "CWE-346"], "mitigations": ["Training data auditing", "Anomaly detection", "Provenance tracking"]},
        {"item_id": "LLM05:2025", "rank": 5, "name": "Improper Output Handling", "atlas": ["AML.T0043"], "cwes": ["CWE-116", "CWE-838"], "mitigations": ["Output escaping", "Content security policy", "Schema validation"]},
        {"item_id": "LLM06:2025", "rank": 6, "name": "Excessive Agency", "atlas": ["AML.T0051"], "cwes": ["CWE-284", "CWE-732"], "mitigations": ["Minimal permissions", "Human-in-the-loop", "Action allow-lists"]},
        {"item_id": "LLM07:2025", "rank": 7, "name": "System Prompt Leakage", "atlas": ["AML.T0051", "AML.T0054"], "cwes": ["CWE-200", "CWE-522"], "mitigations": ["Prompt hardening", "Separate system context", "Monitor outputs"]},
        {"item_id": "LLM08:2025", "rank": 8, "name": "Vector and Embedding Weaknesses", "atlas": ["AML.T0020", "AML.T0043"], "cwes": ["CWE-345"], "mitigations": ["Embedding validation", "RAG access control", "Chunking integrity"]},
        {"item_id": "LLM09:2025", "rank": 9, "name": "Misinformation", "atlas": ["AML.T0031"], "cwes": ["CWE-1021"], "mitigations": ["Grounding techniques", "Citation enforcement", "Human review"]},
        {"item_id": "LLM10:2025", "rank": 10, "name": "Unbounded Consumption", "atlas": ["AML.T0040"], "cwes": ["CWE-770", "CWE-400"], "mitigations": ["Rate limiting", "Resource quotas", "Timeout enforcement"]},
    ]

    added = 0
    for item in items:
        item_id = item["item_id"]
        existing = session.get(OwaspLlmItem, item_id)
        if existing:
            continue

        desc = f"OWASP LLM Top 10 category for {item['name']} ({item_id}). Represents key architectural and security considerations for Large Language Model deployments."
        imp = f"Exploitation of {item['name']} leads to unauthorized execution, logic bypasses, data exfiltration, or denial-of-service in downstream components."
        det = f"Audit application telemetry, prompt audit logs, semantic sanitizers, and token usage counts to spot anomalies representing {item['name']} conditions."

        owasp = OwaspLlmItem(
            item_id=item_id,
            rank=item["rank"],
            name=item["name"],
            description=desc,
            impact=imp,
            detection_notes=det,
            atlas_mappings=item["atlas"],
            cwe_ids=item["cwes"],
            mitigations=item["mitigations"],
            real_world_examples=[f"Example of {item['name']} in production agent."],
            references=[f"https://owasp.org/www-project-machine-learning-security-top-10/"],
        )
        if not dry_run:
            session.add(owasp)
        added += 1

    if not dry_run:
        session.commit()
    ok(f"Loaded {added} OWASP LLM Items.")


# ── SECTION 4: Threat Actors & Mappings ───────────────────────────────────

def load_actors(session: SessionLocal, dry_run: bool) -> None:
    actors = [
        {"name": "APT28", "country": "RU", "sponsor": "nation-state", "soph": 5, "sectors": ["Government", "Defense", "Energy"], "g_id": "G0007", "aliases": ["Fancy Bear", "Sofacy", "Pawn Storm", "STRONTIUM"], "ttps": ["T1595", "T1589", "T1566", "T1566.001", "T1059.001", "T1027", "T1078", "T1071.001", "T1041", "T1486"]},
        {"name": "Lazarus Group", "country": "KP", "sponsor": "nation-state", "soph": 5, "sectors": ["Finance", "Cryptocurrency", "Defense"], "g_id": "G0032", "aliases": ["Hidden Cobra", "Guardians of Peace", "ZINC", "NICKEL ACADEMY"], "ttps": ["T1566", "T1566.002", "T1059.001", "T1059.003", "T1027", "T1053.005", "T1547", "T1105", "T1071.001", "T1486", "T1490", "T1041"]},
        {"name": "Scattered Spider", "country": "US", "sponsor": "financially-motivated", "soph": 3, "sectors": ["Technology", "Telecommunications", "Finance"], "g_id": "G1015", "aliases": [], "ttps": ["T1566.002", "T1078", "T1059.001", "T1027", "T1055", "T1082", "T1113", "T1041"]},
        {"name": "BlackCat/ALPHV", "country": "RU", "sponsor": "financially-motivated", "soph": 4, "sectors": ["Healthcare", "Manufacturing", "Finance"], "g_id": "G1016", "aliases": [], "ttps": ["T1566", "T1078", "T1059.001", "T1486", "T1490", "T1485", "T1027", "T1041", "T1560"]},
        {"name": "Sandworm", "country": "RU", "sponsor": "nation-state", "soph": 5, "sectors": ["Energy", "Government", "Critical Infrastructure"], "g_id": "G0034", "aliases": ["Voodoo Bear", "BlackEnergy", "IRIDIUM", "Telebots"], "ttps": ["T1595", "T1190", "T1059", "T1027", "T1053", "T1547", "T1485", "T1490", "T1486", "T1071", "T1041"]},
        {"name": "APT41", "country": "CN", "sponsor": "nation-state", "soph": 5, "sectors": ["Technology", "Healthcare", "Telecommunications"], "g_id": "G0096", "aliases": ["Winnti", "Barium", "Double Dragon", "Bronze Atlas"], "ttps": ["T1566", "T1190", "T1059.001", "T1059.006", "T1027", "T1055", "T1078", "T1053.005", "T1105", "T1071.001", "T1560", "T1041"]},
        {"name": "FIN7", "country": "UA", "sponsor": "financially-motivated", "soph": 4, "sectors": ["Retail", "Hospitality", "Finance"], "g_id": "G0046", "aliases": ["Carbanak", "Carbon Spider", "ELBRUS"], "ttps": ["T1566.001", "T1059.001", "T1027", "T1547", "T1055", "T1082", "T1113", "T1041"]},
        {"name": "Kimsuky", "country": "KP", "sponsor": "nation-state", "soph": 3, "sectors": ["Government", "Think Tanks", "Defense"], "g_id": "G0094", "aliases": ["Velvet Chollima", "Black Banshee", "Thallium"], "ttps": ["T1566.001", "T1059.001", "T1027", "T1547", "T1071.001", "T1560", "T1041"]},
        {"name": "Turla", "country": "RU", "sponsor": "nation-state", "soph": 5, "sectors": ["Government", "Embassies", "Military"], "g_id": "G0010", "aliases": ["Snake", "Venomous Bear", "Waterbug", "KRYPTON"], "ttps": ["T1595", "T1589", "T1566", "T1059.001", "T1027", "T1055", "T1078", "T1071.001", "T1560", "T1041"]},
        {"name": "Anonymous Sudan", "country": "SD", "sponsor": "hacktivist", "soph": 2, "sectors": ["Government", "Media", "Finance"], "g_id": None, "aliases": [], "ttps": ["T1595.002", "T1190", "T1046", "T1485", "T1041"]},
        {"name": "SiegedSec", "country": "US", "sponsor": "hacktivist", "soph": 2, "sectors": ["Government", "Technology"], "g_id": None, "aliases": [], "ttps": ["T1190", "T1078", "T1082", "T1485"]},
        {"name": "TA505", "country": None, "sponsor": "financially-motivated", "soph": 3, "sectors": ["Finance", "Healthcare", "Retail"], "g_id": "G0092", "aliases": [], "ttps": ["T1566.001", "T1059.001", "T1027", "T1053.005", "T1547", "T1105", "T1071.001", "T1486", "T1041"]},
    ]

    added = 0
    mappings_count = 0
    for a in actors:
        existing = session.query(ThreatActor).filter_by(name=a["name"]).first()
        
        if existing:
            actor = existing
        else:
            actor_id = synthetic_id("actor", a["name"])
            desc = f"Synthetic representation of {a['name']}. This nationwide simulated threat profile operates with sophisticated cyber intelligence payloads."
            actor = ThreatActor(
                id=actor_id,
                name=a["name"],
                aliases=a["aliases"],
                description=desc,
                first_observed="2018",
                country_code=a["country"],
                sponsor_type=a["sponsor"],
                motivations=["financial" if a["sponsor"] == "financially-motivated" else "espionage"],
                sophistication=a["soph"],
                sectors_targeted=a["sectors"],
                geographies_targeted=[a["country"]] if a["country"] else [],
                infrastructure_patterns="Dynamic domain-fronting, bulletproof hosting, proxy relays.",
                references=[f"https://attack.mitre.org/groups/{a['g_id']}" if a["g_id"] else "https://wikipedia.org"],
                tlp="WHITE",
                attck_group_id=a["g_id"],
                source="synthetic",
                source_url="https://pythia.internal/synthetic",
            )
            if not dry_run:
                session.add(actor)
            added += 1

        # Mappings
        if not dry_run:
            # Ensure techniques exist, then add mappings if not present
            session.flush()
            for tech_id in a["ttps"]:
                existing_map = session.query(ActorTTPMapping).filter_by(actor_id=actor.id, technique_id=tech_id).first()
                if not existing_map:
                    mapping = ActorTTPMapping(
                        actor_id=actor.id,
                        technique_id=tech_id,
                        use_note=f"Adversary {a['name']} leverages {tech_id} to maintain persistent delivery objectives.",
                        source="synthetic_map"
                    )
                    session.add(mapping)
                    mappings_count += 1

    if not dry_run:
        session.commit()
    ok(f"Loaded {added} Threat Actors and {mappings_count} TTP mappings.")


# ── SECTION 5: Indicators of Compromise ───────────────────────────────────

def load_iocs(session: SessionLocal, dry_run: bool) -> None:
    # Fictional documentation ranges and real identifiers
    ips = ["192.0.2.14", "192.0.2.88", "192.0.2.133", "198.51.100.7", "198.51.100.42", "198.51.100.199", "203.0.113.5", "203.0.113.88", "203.0.113.241", "10.20.30.40", "172.16.99.1", "45.142.212.100"]
    domains = ["update-service.net", "cdn-analytics.org", "telemetry-beacon.com", "auth-portal.xyz", "secure-login.biz", "api-gateway.info", "download-manager.net", "license-check.com", "report-sender.org", "payload-host.ru", "c2-relay.top", "dropper-cdn.cc"]
    urls = [f"http://{d}/payload/installer.exe" for d in domains[:4]] + [f"https://{d}/api/v1/beacon" for d in domains[4:8]]
    emails = ["admin@update-service.net", "billing@secure-login.biz", "hr@secure-login.biz", "support@telemetry-beacon.com", "support@report-sender.org", "it@auth-portal.xyz"]
    cves = ["CVE-2023-23397", "CVE-2023-44487", "CVE-2024-1234", "CVE-2022-30190", "CVE-2021-44228", "CVE-2023-20198", "CVE-2024-21762", "CVE-2023-4966"]
    md5s = ["5d41402abc4b2a76b9719d911017c592", "7d793037a0760186574b0282f2f435e7", "fc5e038d38a57032085441e7fe7010b0", "098f6bcd4621d373cade4e832627b4f6"]
    
    # Deterministic generation of 10 SHA-256
    sha256s = []
    for i in range(10):
        h = hashlib.sha256(f"synthetic-hash-content-{i}".encode()).hexdigest()
        sha256s.append(h)

    # Get threat actors to link programmatically
    actors = session.query(ThreatActor).filter_by(source="synthetic").all()
    actor_ids = [a.id for a in actors] if actors else [None]

    # Target distribution structure
    targets = [
        {"type": "ip", "values": ips, "pyramid": "ip"},
        {"type": "domain", "values": domains, "pyramid": "domain"},
        {"type": "sha256", "values": sha256s, "pyramid": "hash"},
        {"type": "url", "values": urls, "pyramid": "artifact"},
        {"type": "email", "values": emails, "pyramid": "artifact"},
        {"type": "cve", "values": cves, "pyramid": "ttp"},
        {"type": "md5", "values": md5s, "pyramid": "hash"},
    ]

    added = 0
    # Seed random with fixed state for determinism
    rng = random.Random(1337)

    for spec in targets:
        ioc_type = spec["type"]
        for val in spec["values"]:
            ioc_id = synthetic_id("ioc", f"{ioc_type}:{val}")
            
            existing = session.get(IoC, ioc_id)
            if existing:
                continue

            # Deterministic distributions
            rand_val = rng.random()
            if rand_val < 0.50:
                tlp = "WHITE"
            elif rand_val < 0.75:
                tlp = "GREEN"
            elif rand_val < 0.95:
                tlp = "AMBER"
            else:
                tlp = "RED"

            link_actor = rng.random() < 0.40
            linked_actor_id = rng.choice(actor_ids) if link_actor and actor_ids[0] is not None else None

            confidence_src = rng.choice(["A", "B", "C"]) if rng.random() < 0.80 else rng.choice(["D", "E", "F"])
            confidence_inf = rng.choice(["1", "2", "3"]) if rng.random() < 0.80 else rng.choice(["4", "5", "6"])

            # Map technique IDs
            tids = []
            if ioc_type == "cve":
                tids = ["T1190"]
            elif ioc_type == "ip" or ioc_type == "domain":
                tids = ["T1071.001"]

            ioc = IoC(
                id=ioc_id,
                type=ioc_type,
                value=val,
                first_seen=datetime(2023, 1, 15, tzinfo=timezone.utc),
                last_seen=datetime(2024, 11, 20, tzinfo=timezone.utc),
                confidence_source=confidence_src,
                confidence_info=confidence_inf,
                tlp=tlp,
                pyramid_tier=spec["pyramid"],
                context=f"Synthetic test indicator associated with threat intelligence pipeline validating {ioc_type.upper()} mapping logic.",
                source_url="https://pythia.internal/synthetic-ioc",
                technique_ids=tids,
                actor_id=linked_actor_id,
            )
            if not dry_run:
                session.add(ioc)
            added += 1

    if not dry_run:
        session.commit()
    ok(f"Loaded {added} Indicators of Compromise (IoCs).")


# ── SECTION 6: Source Reports & Business Impact Briefs ────────────────────

def load_reports(session: SessionLocal, dry_run: bool) -> None:
    # 8 reports
    reports = [
        {
            "num": 1,
            "title": "APT28 Spearphishing Campaign Targeting NATO Entities",
            "tlp": "AMBER",
            "status": "accepted",
            "actor_names": ["APT28"],
            "ttps": ["T1566.001", "T1059.001", "T1027"],
            "financial_low": 500000,
            "financial_high": 5000000,
            "operational": "Severe operational disruption, forcing quarantine of active networks and desktop terminals.",
            "regulatory": "NIS2 notification protocols triggered; mandatory disclosure within 24 hours.",
            "actions": ["Patch CVE-2023-23397 immediately", "Enforce MFA across internal boundaries", "Re-authenticate administrative credentials"],
            "so_what": "NATO administrative compromise exposes critical intelligence sharing nodes.",
        },
        {
            "num": 2,
            "title": "Lazarus Group Cryptocurrency Exchange Heist TTPs",
            "tlp": "RED",
            "status": "accepted",
            "actor_names": ["Lazarus Group"],
            "ttps": ["T1566.002", "T1059.001", "T1486", "T1490"],
            "financial_low": 15000000,
            "financial_high": 75000000,
            "operational": "Complete cryptocurrency wallet drain, suspension of trading APIs, and cold storage migration.",
            "regulatory": "FinCEN regulations violated; heavy financial audits and regulatory enforcement expected.",
            "actions": ["Isolate cold storage keys from internet", "Audit all smart contract endpoints", "Deploy hardware security tokens"],
            "so_what": "Lazarus targets liquid digital assets to bypass global economic sanctions.",
        },
        {
            "num": 3,
            "title": "BlackCat Ransomware Affiliate Playbook",
            "tlp": "AMBER",
            "status": "accepted",
            "actor_names": ["BlackCat/ALPHV"],
            "ttps": ["T1078", "T1486", "T1490", "T1485"],
            "financial_low": 2000000,
            "financial_high": 8000000,
            "operational": "Encryption of central active directories and hypervisors, causing full operational backup recovery.",
            "regulatory": "GDPR data leakage exposure requires immediate legal counsel and victim alert services.",
            "actions": ["Verify offline backups integrity", "Restrict administrative credential reuse", "Implement endpoint protection rules"],
            "so_what": "Ransomware groups utilize dual-encryption strategies to compound victim distress.",
        },
        {
            "num": 4,
            "title": "Sandworm ICS Attack on European Energy Grid",
            "tlp": "RED",
            "status": "accepted",
            "actor_names": ["Sandworm"],
            "ttps": ["T1190", "T1485", "T1490"],
            "financial_low": 12000000,
            "financial_high": 40000000,
            "operational": "Substation telemetry disconnect, circuit breaker manipulation, and logic controller wipes.",
            "regulatory": "Critical Infrastructure NIS2 violations, national security agency active intervention.",
            "actions": ["Audit OT/IT boundary firewall configurations", "Rotate all substation service accounts", "Deploy out-of-band monitoring channels"],
            "so_what": "Nation-state elements demonstrate capability to disrupt power infrastructure during diplomatic tensions.",
        },
        {
            "num": 5,
            "title": "FIN7 Point-of-Sale Malware Evolution",
            "tlp": "GREEN",
            "status": "accepted",
            "actor_names": ["FIN7"],
            "ttps": ["T1566.001", "T1027", "T1547"],
            "financial_low": 3000000,
            "financial_high": 12000000,
            "operational": "Merchant POS memory scraping, point-of-sale server latency, and transaction delays.",
            "regulatory": "PCI-DSS non-compliance penalties, mandatory merchant processor investigations.",
            "actions": ["Enforce POS terminal memory protections", "Deploy end-to-end transaction encryption", "Isolate POS server network segment"],
            "so_what": "FIN7 maintains continuous persistence in financial networks via modular memory scrapers.",
        },
        {
            "num": 6,
            "title": "APT41 Supply Chain Compromise of Software Vendor",
            "tlp": "AMBER",
            "status": "pending_review",
            "actor_names": ["APT41"],
            "ttps": ["T1195", "T1059.006", "T1105"],
            "financial_low": 8000000,
            "financial_high": 25000000,
            "operational": "Compromised code pipeline injecting malicious scripts into trusted client updates.",
            "regulatory": "SBOM authenticity issues, massive corporate third-party liability exposure.",
            "actions": ["Verify build environment integrity", "Sign all release artifacts with HSM tokens", "Perform extensive external code audit"],
            "so_what": "Supply chain compromise bypasses standard perimeter defenses via trusted updates.",
        },
        {
            "num": 7,
            "title": "Anonymous Sudan DDoS Campaign Analysis",
            "tlp": "WHITE",
            "status": "accepted",
            "actor_names": ["Anonymous Sudan"],
            "ttps": ["T1595.002", "T1190"],
            "financial_low": 200000,
            "financial_high": 1000000,
            "operational": "External portal downtime, web server overload, and customer login service timeouts.",
            "regulatory": "SLA breaches with enterprise clients requiring direct financial rebates.",
            "actions": ["Configure cloud DDoS shield rules", "Enable rate limiting on API portals", "Deploy geo-blocking firewall policies"],
            "so_what": "Hacktivist elements weaponize commercial proxy networks to amplify HTTP flood waves.",
        },
        {
            "num": 8,
            "title": "Scattered Spider Social Engineering Techniques",
            "tlp": "GREEN",
            "status": "accepted",
            "actor_names": ["Scattered Spider"],
            "ttps": ["T1566.002", "T1078", "T1082"],
            "financial_low": 4000000,
            "financial_high": 15000000,
            "operational": "SaaS login compromises, directory exports, and internal communications interception.",
            "regulatory": "Identity registry leakage requiring immediate regulatory breach reports.",
            "actions": ["Migrate to phishing-resistant FIDO2 keys", "Audit SaaS access token lifetimes", "Enforce strict IT helpdesk verification"],
            "so_what": "Scattered Spider targets human operators at helpdesks to bypass MFA protections.",
        },
    ]

    added = 0
    briefs_added = 0
    for r in reports:
        report_id = synthetic_id("report", r["title"])
        existing = session.get(SourceReport, report_id)
        if existing:
            continue

        # Get actual actor objects
        db_actors = []
        for name in r["actor_names"]:
            act = session.query(ThreatActor).filter_by(name=name).first()
            if act:
                db_actors.append({"name": act.name, "confidence": "high"})

        # Build parsed_data exactly matching the backend and PDF generator expectation
        parsed_data = {
            "summary": f"Synthetic intelligence report discussing details of the campaign '{r['title']}'. Analysis targets tactics, techniques, and impacts.",
            "business_impact": r["operational"],
            "actors": db_actors,
            "ttps": [{"technique_id": tid, "tactic": "execution", "confidence": "high"} for tid in r["ttps"]],
            "iocs": [{"type": "ip", "value": "192.0.2.14", "pyramid_tier": "ip"}],
            "cves": [{"id": "CVE-2023-23397", "context": "Exploited in this campaign."}],
            "sectors_targeted": ["Government", "Defense", "Energy"],
            "geographies_targeted": ["United States", "Germany", "Poland"],
            "killchain_phases": ["initial-access", "execution", "command-and-control"],
            
            # CRITICAL MATCH: PDF engine reads "business_impact_draft" dictionary
            "business_impact_draft": {
                "financial_range_usd": [r["financial_low"], r["financial_high"]],
                "operational": r["operational"],
                "regulatory": r["regulatory"],
                "recommended_board_actions": r["actions"],
            }
        }

        report = SourceReport(
            id=report_id,
            title=r["title"],
            url="https://pythia.internal/intel/reports/" + str(r["num"]),
            raw_text=f"Raw text summary for campaign: {r['title']}. Target scope details listed in parsed intelligence block.",
            publication_date="2024-05-15",
            status=r["status"],
            parsed_data=parsed_data,
            tlp=r["tlp"],
        )
        if not dry_run:
            session.add(report)
            session.flush()  # get report.id for FK brief

        # BusinessImpactBrief insertion (Database Integrity)
        brief_id = synthetic_id("brief", r["title"])
        existing_brief = session.get(BusinessImpactBrief, brief_id)
        if not existing_brief:
            brief = BusinessImpactBrief(
                id=brief_id,
                report_id=report_id,
                so_what=r["so_what"],
                financial_low_usd=r["financial_low"],
                financial_high_usd=r["financial_high"],
                operational_impact=r["operational"],
                regulatory_impact=r["regulatory"],
                board_actions=r["actions"],
                risk_score="Critical" if r["financial_high"] >= 15000000 else "High" if r["financial_high"] >= 4000000 else "Medium",
            )
            if not dry_run:
                session.add(brief)
            briefs_added += 1

        added += 1

    if not dry_run:
        session.commit()
    ok(f"Loaded {added} Source Reports and {briefs_added} Business Impact Briefs.")


# ── SECTION 7: Detection Rules ────────────────────────────────────────────

def load_detection_rules(session: SessionLocal, dry_run: bool) -> None:
    sigma_rules = [
        {"title": "Suspicious PowerShell Encoded Command", "severity": "high", "techs": ["T1059.001"], "category": "process_creation"},
        {"title": "Scheduled Task Creation via schtasks.exe", "severity": "medium", "techs": ["T1053.005"], "category": "process_creation"},
        {"title": "Credential Dumping via LSASS Access", "severity": "critical", "techs": ["T1003"], "category": "process_access"},
        {"title": "Suspicious Outbound HTTPS to Rare TLD", "severity": "high", "techs": ["T1071.001"], "category": "dns"},
        {"title": "Phishing Document Macro Execution", "severity": "high", "techs": ["T1566.001"], "category": "process_creation"},
        {"title": "Registry Run Key Persistence", "severity": "medium", "techs": ["T1547"], "category": "registry_set"},
        {"title": "Lateral Movement via PsExec", "severity": "high", "techs": ["T1021"], "category": "process_creation"},
        {"title": "Data Exfiltration via DNS Tunneling", "severity": "critical", "techs": ["T1041"], "category": "dns"},
        {"title": "Process Injection via CreateRemoteThread", "severity": "high", "techs": ["T1055"], "category": "process_access"},
        {"title": "Volume Shadow Copy Deletion", "severity": "critical", "techs": ["T1490"], "category": "process_creation"},
    ]

    yara_rules = [
        {"title": "Lazarus RAT Strings", "severity": "high", "techs": ["T1059.001", "T1105"], "strings": ["lazarus_core", "hidden_cobra_beacon"]},
        {"title": "BlackCat/ALPHV Ransomware", "severity": "critical", "techs": ["T1486"], "strings": ["alphv_main", "blackcat_encryptor"]},
        {"title": "Generic Ransomware Behaviour", "severity": "high", "techs": ["T1486", "T1490"], "strings": ["shadow_copy_del", "entropy_calc"]},
        {"title": "LNK File Dropper", "severity": "medium", "techs": ["T1547"], "strings": ["dropper_lnk", "cmd_exec_payload"]},
    ]

    added = 0
    
    # Templates
    sigma_template = """title: {title}
id: {uuid}
status: stable
description: Detects command patterns representing {title}.
references:
    - https://attack.mitre.org/techniques/{tech_id}/
author: Pythia Synthetic Data
date: 2024-01-15
tags:
    - attack.execution
    - attack.{tech_id_lower}
logsource:
    category: {category}
    product: windows
detection:
    selection:
        CommandLine|contains: 'encodedcommand'
    condition: selection
falsepositives:
    - Legitimate administrative activity
level: {severity}
"""

    yara_template = """rule {rule_name} {{
    meta:
        description = "Detects strings matching {title}"
        author = "Pythia Synthetic Data"
        date = "2024-01-15"
        severity = "{severity}"
        technique = "{tech_id}"
    strings:
        $s1 = "{string1}" nocase
        $s2 = "{string2}" nocase
    condition:
        2 of them
}}
"""

    for r in sigma_rules:
        rule_id = synthetic_id("rule", r["title"])
        existing = session.get(DetectionRule, rule_id)
        if existing:
            continue

        tid = r["techs"][0] if r["techs"] else "T1059"
        content = sigma_template.format(
            title=r["title"],
            uuid=rule_id,
            tech_id=tid,
            tech_id_lower=tid.lower().replace(".", ""),
            category=r["category"],
            severity=r["severity"],
        )

        rule = DetectionRule(
            id=rule_id,
            rule_type="sigma",
            title=r["title"],
            content=content,
            technique_ids=r["techs"],
            actor_ids=[],
            severity=r["severity"],
            status="stable",
            source_url="https://pythia.internal/rules/sigma/" + rule_id,
        )
        if not dry_run:
            session.add(rule)
        added += 1

    for r in yara_rules:
        rule_id = synthetic_id("rule", r["title"])
        existing = session.get(DetectionRule, rule_id)
        if existing:
            continue

        rule_name = r["title"].replace(" ", "").replace("/", "")
        content = yara_template.format(
            rule_name=rule_name,
            title=r["title"],
            severity=r["severity"],
            tech_id=r["techs"][0],
            string1=r["strings"][0],
            string2=r["strings"][1],
        )

        rule = DetectionRule(
            id=rule_id,
            rule_type="yara",
            title=r["title"],
            content=content,
            technique_ids=r["techs"],
            actor_ids=[],
            severity=r["severity"],
            status="stable",
            source_url="https://pythia.internal/rules/yara/" + rule_id,
        )
        if not dry_run:
            session.add(rule)
        added += 1

    if not dry_run:
        session.commit()
    ok(f"Loaded {added} Detection Rules (Sigma + YARA).")


# ── SECTION 8: Watchlist Subscriptions ────────────────────────────────────

def load_watchlist(session: SessionLocal, dry_run: bool) -> None:
    subscriptions = [
        {"name": "Lazarus Alert", "actor": "lazarus", "ttp": None, "sector": None, "type": "slack", "url": "https://hooks.slack.com/services/SYNTHETIC/T00000001"},
        {"name": "Ransomware TTP Watch", "actor": None, "ttp": "T1486", "sector": None, "type": "slack", "url": "https://hooks.slack.com/services/SYNTHETIC/T00000002"},
        {"name": "Finance Sector Monitor", "actor": None, "ttp": None, "sector": "Finance", "type": "discord", "url": "https://discord.com/api/webhooks/000000001/synthetic"},
        {"name": "APT28 Watch", "actor": "apt28", "ttp": None, "sector": None, "type": "generic", "url": "https://webhook.site/synthetic-pythia-001"},
        {"name": "Critical Infrastructure Alert", "actor": None, "ttp": "T1490", "sector": None, "type": "generic", "url": "https://webhook.site/synthetic-pythia-002"},
    ]

    added = 0
    for sub in subscriptions:
        watchlist_id = synthetic_id("watchlist", sub["name"])
        existing = session.get(Watchlist, watchlist_id)
        if existing:
            continue

        watchlist = Watchlist(
            id=watchlist_id,
            name=sub["name"],
            filter_actor=sub["actor"],
            filter_ttp=sub["ttp"],
            filter_sector=sub["sector"],
            webhook_url=sub["url"],
            webhook_type=sub["type"],
            enabled=True,
        )
        if not dry_run:
            session.add(watchlist)
        added += 1

    if not dry_run:
        session.commit()
    ok(f"Loaded {added} Watchlist Subscriptions.")


# ── MAIN CLEANUP & ORCHESTRATION ──────────────────────────────────────────

def perform_reset(session: SessionLocal) -> None:
    """Safe cleanup of synthetic data based on known namespaces and IDs."""
    print("Wiping all existing synthetic data...")
    
    # 1. Models with source column
    actors_deleted = session.query(ThreatActor).filter(ThreatActor.source == "synthetic").delete()
    session.query(ActorTTPMapping).filter(ActorTTPMapping.source == "synthetic_map").delete()
    
    # 2. Watchlist cleanup using deterministic UUID checks
    subscriptions = [
        "Lazarus Alert", "Ransomware TTP Watch", "Finance Sector Monitor", 
        "APT28 Watch", "Critical Infrastructure Alert"
    ]
    watchlist_ids = [synthetic_id("watchlist", name) for name in subscriptions]
    watchlists_deleted = session.query(Watchlist).filter(Watchlist.id.in_(watchlist_ids)).delete(synchronize_session=False)

    # 3. Detection rules
    sigma_titles = [
        "Suspicious PowerShell Encoded Command", "Scheduled Task Creation via schtasks.exe",
        "Credential Dumping via LSASS Access", "Suspicious Outbound HTTPS to Rare TLD",
        "Phishing Document Macro Execution", "Registry Run Key Persistence",
        "Lateral Movement via PsExec", "Data Exfiltration via DNS Tunneling",
        "Process Injection via CreateRemoteThread", "Volume Shadow Copy Deletion"
    ]
    yara_titles = ["Lazarus RAT Strings", "BlackCat/ALPHV Ransomware", "Generic Ransomware Behaviour", "LNK File Dropper"]
    rule_ids = [synthetic_id("rule", title) for title in sigma_titles + yara_titles]
    rules_deleted = session.query(DetectionRule).filter(DetectionRule.id.in_(rule_ids)).delete(synchronize_session=False)

    # 4. Source reports and Business impact briefs
    report_titles = [
        "APT28 Spearphishing Campaign Targeting NATO Entities",
        "Lazarus Group Cryptocurrency Exchange Heist TTPs",
        "BlackCat Ransomware Affiliate Playbook",
        "Sandworm ICS Attack on European Energy Grid",
        "FIN7 Point-of-Sale Malware Evolution",
        "APT41 Supply Chain Compromise of Software Vendor",
        "Anonymous Sudan DDoS Campaign Analysis",
        "Scattered Spider Social Engineering Techniques"
    ]
    report_ids = [synthetic_id("report", title) for title in report_titles]
    brief_ids = [synthetic_id("brief", title) for title in report_titles]
    
    briefs_deleted = session.query(BusinessImpactBrief).filter(BusinessImpactBrief.id.in_(brief_ids)).delete(synchronize_session=False)
    reports_deleted = session.query(SourceReport).filter(SourceReport.id.in_(report_ids)).delete(synchronize_session=False)

    # 5. Techniques and OWASP items (can be reset safely if desired, though normally static)
    # We delete specifically our synthetic keys so real seeds aren't impacted.
    tech_ids = [
        "T1566", "T1566.001", "T1566.002", "T1059", "T1059.001", "T1059.003", "T1059.006",
        "T1027", "T1078", "T1071", "T1071.001", "T1486", "T1490", "T1053", "T1053.005",
        "T1547", "T1105", "T1190", "T1595", "T1595.002", "T1589", "T1588", "T1583",
        "T1091", "T1548", "T1055", "T1003", "T1082", "T1021", "T1560", "T1041", "T1485",
        "T1046", "T1113", "T1195", "T1471", "T0853", "T0882"
    ]
    session.query(AttckTechnique).filter(AttckTechnique.technique_id.in_(tech_ids)).delete(synchronize_session=False)

    atlas_ids = [
        "AML.T0000", "AML.T0006", "AML.T0020", "AML.T0043", "AML.T0048", "AML.T0051",
        "AML.T0054", "AML.T0040", "AML.T0031", "AML.T0044", "AML.T0005", "AML.T0047"
    ]
    session.query(AtlasTechnique).filter(AtlasTechnique.technique_id.in_(atlas_ids)).delete(synchronize_session=False)

    owasp_ids = [f"LLM{i:02d}:2025" for i in range(1, 11)]
    session.query(OwaspLlmItem).filter(OwaspLlmItem.item_id.in_(owasp_ids)).delete(synchronize_session=False)

    # 6. Indicators of Compromise (IoC)
    ips = ["192.0.2.14", "192.0.2.88", "192.0.2.133", "198.51.100.7", "198.51.100.42", "198.51.100.199", "203.0.113.5", "203.0.113.88", "203.0.113.241", "10.20.30.40", "172.16.99.1", "45.142.212.100"]
    domains = ["update-service.net", "cdn-analytics.org", "telemetry-beacon.com", "auth-portal.xyz", "secure-login.biz", "api-gateway.info", "download-manager.net", "license-check.com", "report-sender.org", "payload-host.ru", "c2-relay.top", "dropper-cdn.cc"]
    urls = [f"http://{d}/payload/installer.exe" for d in domains[:4]] + [f"https://{d}/api/v1/beacon" for d in domains[4:8]]
    emails = ["admin@update-service.net", "billing@secure-login.biz", "hr@secure-login.biz", "support@telemetry-beacon.com", "support@report-sender.org", "it@auth-portal.xyz"]
    cves = ["CVE-2023-23397", "CVE-2023-44487", "CVE-2024-1234", "CVE-2022-30190", "CVE-2021-44228", "CVE-2023-20198", "CVE-2024-21762", "CVE-2023-4966"]
    md5s = ["5d41402abc4b2a76b9719d911017c592", "7d793037a0760186574b0282f2f435e7", "fc5e038d38a57032085441e7fe7010b0", "098f6bcd4621d373cade4e832627b4f6"]
    sha256s = [hashlib.sha256(f"synthetic-hash-content-{i}".encode()).hexdigest() for i in range(10)]
    
    ioc_ids = []
    for ioc_t, vals in [("ip", ips), ("domain", domains), ("url", urls), ("email", emails), ("cve", cves), ("md5", md5s), ("sha256", sha256s)]:
        for v in vals:
            ioc_ids.append(synthetic_id("ioc", f"{ioc_t}:{v}"))
    session.query(IoC).filter(IoC.id.in_(ioc_ids)).delete(synchronize_session=False)

    session.commit()
    print("[RESET] Cleaned up existing synthetic data records.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Populate the Pythia database with realistic synthetic CTI data.")
    parser.add_argument("--reset", action="store_true", help="Wipe all synthetic records before populating.")
    parser.add_argument("--dry-run", action="store_true", help="Print loaded counts without writing to database.")
    args = parser.parse_args()

    init_db()
    session = SessionLocal()

    try:
        if args.reset:
            if args.dry_run:
                print("[DRY-RUN] Would reset synthetic records.")
            else:
                perform_reset(session)

        print("Populating synthetic database rows...")
        load_attck_techniques(session, args.dry_run)
        load_atlas_techniques(session, args.dry_run)
        load_owasp_llm(session, args.dry_run)
        load_detection_rules(session, args.dry_run)
        load_actors(session, args.dry_run)
        load_iocs(session, args.dry_run)
        load_reports(session, args.dry_run)
        load_watchlist(session, args.dry_run)

        print("\033[32mSuccess! Synthetic data pipeline run finished.\033[0m")
    finally:
        session.close()


if __name__ == "__main__":
    main()
