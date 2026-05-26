# Demo Script

A guided walkthrough for interview demos and portfolio presentations. Takes ~12 minutes end-to-end.

---

## Setup (before the call)

```bash
# Ensure server is running and seeded
docker compose up -d
curl http://localhost:8000/v1/health
# {"status":"ok","version":"0.1.0"}
```

---

## Act 1 — Ingest a Real Threat Report (2 min)

**Talking point:** *"Most CTI tools expect you to manually tag and categorize intel. Pythia uses Claude to do that automatically from any URL."*

```bash
# Ingest a real blog post — Claude extracts everything
pythia ingest https://www.huntress.com/blog/the-gentlemen-ransomware-defense-evasion-ttps
```

While it runs: *"Claude is extracting threat actors, ATT&CK techniques, IoCs, targeted sectors, and business impact — and generating draft Sigma detection rules."*

```bash
# See what landed
curl http://localhost:8000/v1/threats | jq '.[0] | {title, actor_names, ttp_ids, tlp}'
```

Show the parsed_data block: `actor_names`, `ttp_ids`, `ioc_values`, `sectors_targeted`, `business_impact`.

---

## Act 2 — Actor Profiles (2 min)

**Talking point:** *"1,067 threat actor profiles seeded from MISP Galaxy and MITRE ATT&CK. Smart lookup by name, slug, or substring."*

```bash
# Smart lookup — slug, name, substring all work
curl http://localhost:8000/v1/actors/apt28 | jq '{name, country_code, sponsor_type, ttp_count: (.ttps | length)}'
curl http://localhost:8000/v1/actors/scattered | jq .name   # finds "Scattered Spider"
```

Show the Kill Chain view:

```bash
curl http://localhost:8000/v1/actors/apt28/killchain | jq '.phases | keys'
# ["actions_on_objectives", "command_and_control", "delivery", ...]
```

**Talking point:** *"Every actor's TTPs are automatically placed on the Kill Chain — you can see at which stages they're most active."*

Show the Diamond Model:

```bash
curl http://localhost:8000/v1/actors/lazarus-group/diamond | jq .
```

---

## Act 3 — AI Threat Coverage (2 min)

**Talking point:** *"One of the few open-source CTI platforms with dedicated AI/ML threat coverage — both MITRE ATLAS and OWASP LLM Top 10."*

```bash
# Coverage overview
curl http://localhost:8000/v1/ai-threats | jq .

# Prompt injection — the #1 LLM risk
curl http://localhost:8000/v1/ai-threats/owasp-llm/LLM01 | jq '{name, impact, atlas_mappings}'

# Real-world incidents
curl http://localhost:8000/v1/ai-threats/incidents | jq '.[].title'
# Samsung ChatGPT leak, Morris II AI worm, Slack AI RAG exfil...

# Filter by ATLAS technique
curl "http://localhost:8000/v1/ai-threats/incidents?atlas_id=AML.T0051" | jq '.[].title'
```

**Talking point:** *"These are real incidents — Samsung's ChatGPT source code leak, the Morris II self-replicating AI worm, Slack's RAG exfiltration bug — all mapped to both ATLAS techniques and OWASP LLM categories so defenders can build detections."*

---

## Act 4 — Detection Engineering (2 min)

**Talking point:** *"Pythia generates multi-platform hunt queries from Sigma rules — one query per SIEM, no rewriting."*

```bash
# Hunt queries for PowerShell execution (T1059.001)
curl http://localhost:8000/v1/ttps/T1059.001/hunt-queries | jq '.rules[0] | {title, severity}'

# Show the three formats
curl http://localhost:8000/v1/ttps/T1059.001/hunt-queries | jq '.rules[0].splunk_spl'
curl http://localhost:8000/v1/ttps/T1059.001/hunt-queries | jq '.rules[0].elastic_kql'
curl http://localhost:8000/v1/ttps/T1059.001/hunt-queries | jq '.rules[0].sentinel_kql'
```

Coverage gap report:

```bash
curl http://localhost:8000/v1/analytics/coverage | jq '{coverage_pct, uncovered_count, top_uncovered: .top_uncovered[:3]}'
```

**Talking point:** *"The coverage gap report cross-references every observed TTP with existing Sigma rules. It tells you exactly which attacker techniques you can't detect yet — so you build rules for the right things."*

---

## Act 5 — STIX 2.1 Export (1 min)

**Talking point:** *"Every actor and IoC exports as a standards-compliant STIX 2.1 bundle — plug it into MISP, OpenCTI, or any TAXII-aware SIEM."*

```bash
curl http://localhost:8000/v1/actors/apt28/stix | jq '{type, objects: (.objects | length)}'
# {"type":"bundle","objects":187}

curl http://localhost:8000/v1/iocs/stix/bundle | jq '.objects[0] | {type, pattern}'
```

---

## Act 6 — Executive PDF Report (1 min)

**Talking point:** *"Analysts know TTPs, but executives need to understand business risk. Pythia generates CFO-readable briefs automatically."*

```bash
# Get a report ID from the threats list
REPORT_ID=$(curl -s http://localhost:8000/v1/threats | jq -r '.[0].id')

# Download executive brief
curl "http://localhost:8000/v1/reports/$REPORT_ID/pdf?template=executive" -o brief.pdf
open brief.pdf
```

Point to the financial impact range, operational risk paragraph, and three board-level recommended actions.

---

## Act 7 — Alerting + Feed (1 min)

```bash
# Set up a Slack alert for any Lazarus Group intel
curl -X POST http://localhost:8000/v1/watchlist \
  -H "X-API-Key: $PYTHIA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"Lazarus Watch","filter_actor":"lazarus","webhook_url":"https://hooks.slack.com/...","webhook_type":"slack"}'

# Subscribe to the Atom feed in any RSS reader
curl http://localhost:8000/v1/feed.atom | head -30
```

---

## Architecture Callouts (for technical interviewers)

| Question | Answer |
|---|---|
| "Why FastAPI?" | Auto-generates OpenAPI docs (the only UI), async-ready, Pydantic v2 validation |
| "Why SQLite?" | Zero-ops, single-file backup, plenty for a personal/team CTI store. Swap to PostgreSQL with one URL change |
| "Why not pysigma?" | Heavy dependency chain. Custom PyYAML converter covers the 16 curated rules with no extra deps |
| "How does authentication work?" | Single API key in `X-API-Key` header for write endpoints. Read endpoints open by design — it runs on your machine |
| "How do STIX IDs stay stable?" | `uuid5(NAMESPACE_URL, technique_id)` — deterministic, reproducible, no ID churn on resync |
| "How does Claude know what to extract?" | Structured prompt with JSON schema enforcement; Claude returns validated TypedDict; fields map directly to ORM columns |

---

## Numbers to Know

| Stat | Value |
|---|---|
| Threat actor profiles | 1,067+ |
| ATT&CK techniques | 756+ (Enterprise + Mobile + ICS) |
| Actor → TTP mappings | 3,567+ |
| CISA KEV CVEs | 1,602+ |
| Curated Sigma rules | 16+ |
| OWASP LLM Top 10 items | 10 (hand-maintained, 2025) |
| Real-world AI incidents | 8 (hand-curated with ATLAS + OWASP mapping) |
| API endpoints | 30+ |
| Lines of Python | ~2,500 |
| Setup time | ~2 min (docker compose up + auto-seed) |
