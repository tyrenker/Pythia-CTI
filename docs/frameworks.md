# Frameworks Reference

Pythia normalizes every record against eight industry frameworks. This page explains each one and how Pythia uses it.

---

## MITRE ATT&CK

**What it is:** A globally accessible knowledge base of adversary tactics, techniques, and sub-techniques based on real-world observations.

**Matrices:** Enterprise (Windows/Linux/macOS/Cloud), Mobile (Android/iOS), ICS (Industrial Control Systems)

**Structure:**
- **Tactics** (14 in Enterprise) — the adversary's goal: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact, Reconnaissance, Resource Development
- **Techniques** (T####) — *how* the goal is achieved
- **Sub-techniques** (T####.###) — more specific variants

**How Pythia uses it:**
- 756+ techniques seeded from ATT&CK v14
- 3,567+ actor → TTP mappings
- Every parsed report maps extracted behaviors to technique IDs
- Coverage gap report (`/v1/analytics/coverage`) cross-references observed techniques with Sigma rule coverage
- Hunt queries (`/v1/ttps/{id}/hunt-queries`) convert Sigma rules to Splunk/Elastic/Sentinel KQL per technique

```bash
curl http://localhost:8000/v1/ttps?tactic=initial-access
curl http://localhost:8000/v1/ttps/T1566.001   # Spearphishing Attachment
```

---

## MITRE ATLAS

**What it is:** Adversarial Threat Landscape for Artificial-Intelligence Systems — MITRE's ATT&CK-style knowledge base for attacks targeting ML systems.

**Technique IDs:** `AML.T####` format

**Key techniques:**
| ID | Name |
|---|---|
| AML.T0043 | Craft Adversarial Data |
| AML.T0048 | Backdoor ML Model |
| AML.T0051 | LLM Prompt Injection |
| AML.T0054 | LLM Jailbreak |
| AML.T0020 | Poison Training Data |

**How Pythia uses it:**
- ATLAS techniques seeded on `pythia sync atlas`
- 8 curated real-world AI incidents mapped to ATLAS + OWASP LLM IDs
- AI threats overview at `/v1/ai-threats/atlas`

```bash
curl http://localhost:8000/v1/ai-threats/atlas
curl "http://localhost:8000/v1/ai-threats/incidents?atlas_id=AML.T0051"
```

---

## OWASP LLM Top 10 (2025)

**What it is:** The Open Web Application Security Project's ranked list of the ten most critical security risks for Large Language Model applications.

**Categories:**

| ID | Name |
|---|---|
| LLM01:2025 | Prompt Injection |
| LLM02:2025 | Sensitive Information Disclosure |
| LLM03:2025 | Supply Chain |
| LLM04:2025 | Data and Model Poisoning |
| LLM05:2025 | Improper Output Handling |
| LLM06:2025 | Excessive Agency |
| LLM07:2025 | System Prompt Leakage |
| LLM08:2025 | Vector and Embedding Weaknesses |
| LLM09:2025 | Misinformation |
| LLM10:2025 | Unbounded Consumption |

**How Pythia uses it:**
- All 10 items seeded with ATLAS mappings, CWE IDs, mitigations, and real-world examples
- Each item cross-referenced to ATLAS techniques
- AI incidents filtered by OWASP ID

```bash
curl http://localhost:8000/v1/ai-threats/owasp-llm
curl http://localhost:8000/v1/ai-threats/owasp-llm/LLM01
```

---

## Lockheed Martin Kill Chain

**What it is:** A seven-phase model describing the stages of a cyber attack, from initial reconnaissance through the adversary's final objective.

**Phases:**

| Phase | Description |
|---|---|
| 1. Reconnaissance | Target research, OSINT gathering |
| 2. Weaponization | Building the exploit/payload |
| 3. Delivery | Phishing, watering hole, USB drop |
| 4. Exploitation | Triggering the vulnerability |
| 5. Installation | Malware persistence |
| 6. C2 | Command-and-control channel |
| 7. Actions on Objectives | Data theft, ransomware, destruction |

**How Pythia uses it:**
- Actor TTPs automatically mapped to Kill Chain phases via ATT&CK tactic → phase translation
- Kill Chain view available per actor: `/v1/actors/{id}/killchain`
- Useful for understanding attacker progression and prioritizing defensive investment

```bash
curl http://localhost:8000/v1/actors/apt28/killchain | jq .phases
```

---

## Diamond Model

**What it is:** An intrusion analysis model that represents every event as four features of an adversary operation, forming a diamond.

**Four vertices:**

| Vertex | Definition |
|---|---|
| **Adversary** | The threat actor (group, individual, nation-state) |
| **Capability** | Malware, exploits, TTPs used |
| **Infrastructure** | IPs, domains, C2 servers |
| **Victim** | Target organization or sector |

**Meta-features:** Timestamp, phase (Kill Chain), result, direction, methodology, resources

**How Pythia uses it:**
- Diamond view surfaced per actor: `/v1/actors/{id}/diamond`
- Maps actor metadata → adversary vertex; TTPs → capability; IoC IPs/domains → infrastructure; sectors_targeted → victim

```bash
curl http://localhost:8000/v1/actors/lazarus-group/diamond
```

---

## Pyramid of Pain

**What it is:** David Bianco's model ranking IoC types by how much pain it causes the adversary when defenders detect and respond to them.

**Tiers (bottom to top = harder for attacker to change):**

| Tier | IoC Type | Pain |
|---|---|---|
| Hash values | MD5/SHA file hashes | Trivial — recompile |
| IP addresses | C2 IPs | Easy — change host |
| Domain names | C2 domains | Simple — rereg |
| Network artifacts | URI patterns, HTTP headers | Annoying |
| Host artifacts | Registry keys, file paths | Challenging |
| Tools | Malware families, utilities | Significant |
| TTPs | Behaviors and techniques | Tough — requires retraining |

**How Pythia uses it:**
- Every IoC tagged with `pyramid_tier`: `hash`, `ip`, `domain`, `artifact`, `tool`, `ttp`
- API filter: `?pyramid_tier=domain` to focus on higher-value indicators
- Guides prioritization: detecting TTPs (Pyramid apex) provides durable, evasion-resistant detection

```bash
curl "http://localhost:8000/v1/iocs?pyramid_tier=tool&limit=10"
```

---

## Admiralty Code

**What it is:** A NATO/intelligence-community standard (also called the NATO System) for grading the reliability of a source and the credibility of the information it provides. Used in military, law enforcement, and CTI contexts.

**Two-dimensional rating:**

| Letter | Source Reliability |
|---|---|
| A | Completely reliable |
| B | Usually reliable |
| C | Fairly reliable |
| D | Not usually reliable |
| E | Unreliable |
| F | Reliability cannot be judged |

| Number | Information Credibility |
|---|---|
| 1 | Confirmed by other sources |
| 2 | Probably true |
| 3 | Possibly true |
| 4 | Doubtful |
| 5 | Improbable |
| 6 | Truth cannot be judged |

**Examples:** A1 = gold-standard (confirmed, completely reliable); C3 = possibly true from a fairly reliable source; F6 = unknown reliability and credibility

**How Pythia uses it:**
- Every IoC stores an `admiralty_code` string (e.g. `"B2"`)
- Mapped to STIX 2.1 `confidence` (0-100) on export: A1=100, F6=0
- Claude assigns an initial Admiralty code during parsing based on source type and corroboration

```bash
curl "http://localhost:8000/v1/iocs?tlp=WHITE" | jq '.[].admiralty_code'
```

---

## Traffic Light Protocol (TLP)

**What it is:** A standard for controlling the sharing of sensitive information. Originally from UK NISCC, now formalized by FIRST as TLP 2.0.

**Markings:**

| Color | Sharing Scope |
|---|---|
| `TLP:CLEAR` (formerly WHITE) | No restrictions — public |
| `TLP:GREEN` | Community — not public |
| `TLP:AMBER` | Organization + need-to-know |
| `TLP:AMBER+STRICT` | Recipients only, no re-sharing |
| `TLP:RED` | Named recipients only |

**How Pythia uses it:**
- Every SourceReport and IoC carries a `tlp` field
- API filters: `?tlp=WHITE`, `?tlp=GREEN`, etc.
- Claude assigns TLP based on source type during parsing (public blogs → WHITE, vendor advisories → AMBER by default)
- STIX exports include TLP marking definitions as `marking-definition` objects

```bash
curl "http://localhost:8000/v1/threats?tlp=WHITE"
curl "http://localhost:8000/v1/iocs?tlp=AMBER"
```

---

## STIX 2.1

**What it is:** Structured Threat Information eXpression — a standardized language for representing CTI as JSON objects, enabling machine-readable sharing between tools (MISP, OpenCTI, Splunk TAXII).

**Key object types (SDOs):**

| Type | Represents |
|---|---|
| `threat-actor` | APT group or individual |
| `attack-pattern` | ATT&CK technique |
| `indicator` | IoC with STIX pattern |
| `vulnerability` | CVE |
| `relationship` | Links two SDOs (e.g. actor *uses* technique) |
| `bundle` | Container for multiple STIX objects |

**STIX patterns** define the logic of an indicator:
```
[ipv4-addr:value = '198.51.100.42']
[domain-name:value = 'evil.example.com']
[file:hashes.'SHA-256' = 'abc123...']
```

**How Pythia uses it:**
- Actors export as STIX 2.1 bundle: threat-actor + attack-patterns + relationships
- IoCs export as indicator bundles with auto-generated STIX patterns
- Consumable by MISP, OpenCTI, Splunk TAXII ingestion

```bash
curl http://localhost:8000/v1/actors/apt28/stix | jq .type
curl http://localhost:8000/v1/iocs/stix/bundle | jq .objects[0].type
```
