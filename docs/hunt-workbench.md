# Threat Hunt Workbench

The **Threat Hunt Workbench** is a specialized workspace in Pythia designed for proactive threat hunters and security analysts. It acts as a collaborative, AI-assisted scratchpad for organizing threat hypotheses, logging forensic observations, maintaining interactive notes, and drafting high-fidelity detection rules.

---

## Conceptual Overview

When conducting a threat hunt, analysts typically pivot between disparate data sources, threat reports, and SIEM logs. The Hunt Workbench unifies this process:

```
                  ┌───────────────────────────────┐
                  │      Threat Hunt Session      │
                  │   - Hypothesis Tracking       │
                  │   - Target Sector/Motivation  │
                  └───────────────┬───────────────┘
                                  │
         ┌────────────────────────┼────────────────────────┐
         ▼                        ▼                        ▼
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│  Observations   │      │  Analyst Notes  │      │Draft Detections │
│ - IoCs / TTPs   │      │ - Rich Markdown │      │ - Sigma / Yara  │
│ - Admiralty     │      │ - Timeline      │      │ - Splunk / KQL  │
│ - Pyramid Tier  │      │ - Evidence      │      │ - Rule promotion│
└────────┬────────┘      └────────┬────────┘      └────────┬────────┘
         │                        │                        │
         └───────────┬────────────┘                        │
                     ▼                                     │
           ┌───────────────────┐                           │
           │   Claude AI Core  ├───────────────────────────┘
           │ - Refine Hypoth.  │
           │ - Suggest Actors  │
           └───────────────────┘
```

---

## Core Features

### 1. Collaborative Hunt Sessions
A hunt session represents a single threat-hunting initiative centered around a specific hypothesis (e.g., *"APT29 is utilizing trusted relationship abuse to pivot from third-party vendor systems"*). 
*   **Hypothesis Tracking:** Clearly define the objective of the hunt.
*   **Scoped Targets:** Define targeting scopes such as **Sector Focus** (e.g., *finance*, *healthcare*, *critical infrastructure*) and **Motivation Focus** (e.g., *espionage*, *financial-gain*).
*   **Session Lifecycle:** Track sessions as `active`, `archived`, or `closed`.

### 2. Admiralty-Enriched Observations
Observations are the tactical facts uncovered during your hunt. You can log techniques, IP addresses, domains, malware names, and threat actors:
*   **Pyramid of Pain Mapping:** Every logged observation is automatically categorized onto the **Pyramid of Pain** (e.g., Hashing → Easy; TTPs → Tough) to assess the threat actor's mitigation cost.
*   **Admiralty Code Ratings:** Track the confidence and credibility of each observation using the **NATO Admiralty Code**:
    *   **Source Reliability (A–F):** A (Completely reliable) to F (Reliability cannot be judged).
    *   **Information Credibility (1–6):** 1 (Confirmed by other sources) to 6 (Truth cannot be judged).
*   **Database Auto-Linking:** The workbench automatically matches logged observation values against Pythia's bundled database of 1,180+ threat actors, 759 ATT&CK techniques, and existing IoCs, linking them directly to interactive detail cards.

### 3. Rich Markdown Analyst Notes
Document your investigative thread, dump raw logs, paste terminal traces, and build timelines in a rich Markdown editor. 
*   Markdown notes are rendered dynamically in real-time.
*   Acts as contextual fuel for the Claude AI engine to evaluate hypotheses and suggest threat groups.

### 4. Claude-Powered AI Intelligence
The Hunt Workbench integrates three deep, context-aware LLM operations:
*   **Suggest Threat Actors (`/suggest-actors`):** Scans the session observations, sector focuses, and analyst notes, cross-references them with Pythia's nation-state and cybercrime database, and suggests matching threat actors with a confidence score, rationale, indicators of gap coverage, and alternative attribution hypotheses.
*   **Refine Hypothesis (`/refine-hypothesis`):** Evaluates the logical strength of the current hunt hypothesis against the logged observations and notes. Highlights supporting evidence, contradicting evidence, information gaps, and recommends logical pivots.
*   **Draft Detection Rules (`/draft-detection`):** Automatically drafts production-ready detection signatures (Sigma, YARA, Splunk SPL, Elastic KQL, Microsoft Sentinel KQL, Splunk SPL) based on selected observations and contextual analyst notes.

### 5. Detection Promotion & Engineering
Once a detection rule is generated and polished, promote it with a single click. Promoting a rule copies it directly into Pythia's main `detection_rules` table as a `pending_review` rule, making it instantly searchable and trackable across your environment.

---

## CLI & API Usage

### API Endpoints Summary

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/v1/hunts` | Create a new threat hunt session *(auth)* |
| `GET` | `/v1/hunts` | List threat hunt sessions (`?status=active\|archived\|closed`) |
| `GET` | `/v1/hunts/{id}` | Retrieve detailed session metadata and observations |
| `PUT` | `/v1/hunts/{id}` | Update session metadata (status, sector focus, etc.) *(auth)* |
| `DELETE` | `/v1/hunts/{id}` | Archive a hunt session *(auth)* |
| `POST` | `/v1/hunts/{id}/observations` | Log an observation *(auth)* |
| `DELETE` | `/v1/hunts/{id}/observations/{obs_id}` | Remove an observation *(auth)* |
| `GET`| `/v1/hunts/{id}/notes` | Retrieve session notes |
| `PUT` | `/v1/hunts/{id}/notes` | Save session notes *(auth)* |
| `POST` | `/v1/hunts/{id}/suggest-actors` | Run Claude AI threat actor attribution recommendations *(auth)* |
| `POST` | `/v1/hunts/{id}/refine-hypothesis` | Run Claude AI hypothesis refinement review *(auth)* |
| `POST` | `/v1/hunts/{id}/draft-detection` | Generate a code-level detection rule based on observations *(auth)* |
| `GET` | `/v1/hunts/{id}/detections` | List drafted detection rules |
| `PUT` | `/v1/hunts/{id}/detections/{det_id}` | Edit a drafted detection rule *(auth)* |
| `POST` | `/v1/hunts/{id}/detections/{det_id}/promote` | Promote a draft rule to Pythia's main signature database *(auth)* |

---

## REST API Walkthrough

### 1. Initialize a Hunt Session
```bash
curl -X POST http://localhost:8000/v1/hunts \
  -H "X-API-Key: $PYTHIA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Finance sector DLL hijacking hunt",
    "hypothesis": "Threat actor is utilizing unsigned DLL side-loading to bypass EDR in financial systems.",
    "analyst": "Alex",
    "sector_focus": ["finance"],
    "motivation_focus": ["financial-gain"]
  }'
```

### 2. Log Observations
```bash
curl -X POST http://localhost:8000/v1/hunts/<session_id>/observations \
  -H "X-API-Key: $PYTHIA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "obs_type": "ttp",
    "value": "T1574.002",
    "confidence_source": "B",
    "confidence_info": "2",
    "notes": "Observed loading of rogue native DLL in legitimate Microsoft executable directory"
  }'
```

### 3. Generate Actor Suggestions
```bash
curl -X POST http://localhost:8000/v1/hunts/<session_id>/suggest-actors \
  -H "X-API-Key: $PYTHIA_API_KEY"
```

### 4. Automatically Draft a Sigma Detection Rule
```bash
curl -X POST http://localhost:8000/v1/hunts/<session_id>/draft-detection \
  -H "X-API-Key: $PYTHIA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "obs_ids": ["<observation_id>"],
    "rule_type": "sigma"
  }'
```

### 5. Promote Draft to Main Rules Table
```bash
curl -X POST http://localhost:8000/v1/hunts/<session_id>/detections/<detection_id>/promote \
  -H "X-API-Key: $PYTHIA_API_KEY"
```
