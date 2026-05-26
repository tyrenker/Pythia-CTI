# Seed Data Sources

Pythia ships with pre-extracted threat intelligence so a fresh clone is immediately useful. This file documents where every seed file came from, its license, and the attribution required.

> **TL;DR for license compatibility:** Pythia's *code* is MIT. The *data* in this directory carries each source's upstream license — primarily CC-BY-SA 4.0 (MISP, OWASP), CC-BY 4.0 (MITRE ATLAS), the MITRE ATT&CK Terms of Use, the Detection Rule License 1.1 (Sigma), and public-domain US Government data (CISA, NIST). Mixing in any source noted as CC-BY-SA means **derivative datasets must also be CC-BY-SA** if redistributed.

---

## Bundled by default (built into `pythia sync`)

### MITRE ATT&CK
- **Upstream:** https://github.com/mitre-attack/attack-stix-data
- **Format:** STIX 2.1 JSON
- **License:** [ATT&CK Terms of Use](https://attack.mitre.org/resources/terms-of-use/) — free to use with attribution; "© 2024 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."
- **What we extract:** Techniques + sub-techniques (Enterprise, Mobile, ICS), mitigations, and **intrusion-set objects** (threat actor groups → technique mappings).
- **Output files:** `data/seed/attck/enterprise.json`, `mobile.json`, `ics.json`, `groups.json`.

### MITRE ATLAS
- **Upstream:** https://github.com/mitre-atlas/atlas-data
- **Format:** YAML
- **License:** CC-BY 4.0
- **What we extract:** Adversarial ML techniques (`AML.Txxxx`) and case studies of real-world attacks on ML systems.
- **Output files:** `data/seed/atlas/atlas.yaml`, `case_studies.yaml`.

### MISP Galaxy — `threat-actor` cluster
- **Upstream:** https://github.com/MISP/misp-galaxy/blob/main/clusters/threat-actor.json
- **Format:** JSON
- **License:** CC-BY-SA 4.0
- **What we extract:** ~750 threat actor profiles with aliases, suspected country, motivation, MITRE refs, and external references.
- **Output files:** `data/seed/actors/misp_threat_actors.json`.
- **Attribution:** The MISP Project, https://www.misp-project.org/

### CISA Known Exploited Vulnerabilities (KEV)
- **Upstream:** https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- **Format:** JSON
- **License:** Public domain (US Federal Government work)
- **What we extract:** Full KEV catalog snapshot.
- **Output files:** `data/seed/cves/kev.json`.

### NIST CWE (top-25 subset)
- **Upstream:** https://cwe.mitre.org/data/downloads.html
- **Format:** XML → converted to JSON
- **License:** Public domain
- **What we extract:** CWE Top 25 entries with descriptions and consequences.
- **Output files:** `data/seed/cwe/top25.json`.

### OWASP LLM Top 10 (2025)
- **Upstream:** https://genai.owasp.org/llm-top-10/
- **Format:** Hand-maintained YAML in this repo
- **License:** CC-BY-SA 4.0
- **What we extract:** 10 categories with descriptions, example attacks, and mitigations.
- **Output files:** `data/seed/owasp_llm_top10.yaml`.

### SigmaHQ rules (curated subset)
- **Upstream:** https://github.com/SigmaHQ/sigma
- **Format:** YAML
- **License:** [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License) — commercial use permitted with attribution and license preservation.
- **What we extract:** ~50 hand-picked rules covering the most common techniques (credential dumping, lateral movement, persistence, etc.). The full ruleset is available via `pythia sync sigma-full`.
- **Output files:** `data/sigma/curated/*.yml`.

---

## Optional pulls (off by default — pass explicitly to `pythia sync`)

### SigmaHQ full ruleset (`pythia sync sigma-full`)
- **Upstream:** https://github.com/SigmaHQ/sigma
- **License:** DRL 1.1
- **Size:** Thousands of rules; ~50 MB cloned.

### Yara-Rules (`pythia sync yara-full`)
- **Upstream:** https://github.com/Yara-Rules/rules
- **License:** GPL-3.0
- **Size:** ~3000 rules; ~20 MB cloned.
- **GPL note:** Distributing Pythia together with these rules would obligate the bundle under GPL-3.0. We only pull them on-demand into `data/yara/` — they're not redistributed by Pythia itself.

### abuse.ch feeds (`pythia sync abuse-ch`)
- **Upstreams:**
  - ThreatFox — https://threatfox.abuse.ch/
  - MalwareBazaar — https://bazaar.abuse.ch/
  - URLhaus — https://urlhaus.abuse.ch/
- **License:** CC0 (public domain) on the data feeds.
- **What we pull:** Recent IoCs (configurable window — default 30 days).

### AlienVault OTX (`pythia sync otx`)
- **Upstream:** https://otx.alienvault.com/api
- **License:** Subject to OTX Terms of Service (free account required).
- **Requires:** `OTX_API_KEY` in `.env`.

---

## How seed data is built

The `scripts/build_seed.py` script in the repo root:
1. Fetches each upstream source.
2. Normalizes records into Pythia's canonical entity shape.
3. Preserves source URL + license tag on every record for downstream attribution.
4. Writes the result to `data/seed/`.

The committed contents of `data/seed/` are the **output** of that script as of the last release. Re-running `pythia sync` regenerates them against the current upstream state.
