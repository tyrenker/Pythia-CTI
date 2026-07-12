# API Reference

The interactive OpenAPI docs (Swagger UI) are always available at **[http://localhost:8000/docs](http://localhost:8000/docs)** when the server is running. This page provides a narrative overview.

---

## Authentication

Read endpoints are **open** (no key required) — Pythia runs on your machine.

Write endpoints require an API key in the `X-API-Key` header:

```bash
export PYTHIA_API_KEY=your-key-from-.env
curl -H "X-API-Key: $PYTHIA_API_KEY" http://localhost:8000/v1/parse -d '...'
```

Set `PYTHIA_API_KEY` in your `.env` file.

---

## Endpoint Summary

### Core Intel

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/v1/health` | Health check |
| `GET` | `/v1/threats` | List ingested intel reports (`?status=`, `?tlp=`) |
| `GET` | `/v1/threats/{id}` | Single report detail |
| `POST` | `/v1/parse` | Parse a URL or raw text with Claude *(auth)* |

### Threat Actors

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/v1/actors` | List actors (`?name=`, `?country=`, `?sponsor_type=`) |
| `GET` | `/v1/actors/{id}` | Actor profile — lookup by UUID, name, slug, or substring |
| `GET` | `/v1/actors/{id}/killchain` | TTPs placed on the 7-phase Kill Chain |
| `GET` | `/v1/actors/{id}/diamond` | Diamond Model view (adversary/capability/infrastructure/victim) |
| `GET` | `/v1/actors/{id}/stix` | STIX 2.1 bundle export |
| `GET` | `/v1/actors/{id}/diff` | TTP evolution over time (stub) |

### TTPs

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/v1/ttps` | List ATT&CK techniques (`?tactic=`, `?domain=enterprise\|mobile\|ics`) |
| `GET` | `/v1/ttps/{id}` | Technique detail — ATT&CK (`T*`) or ATLAS (`AML.T*`) |
| `GET` | `/v1/ttps/{id}/hunt-queries` | Splunk SPL + Elastic KQL + Sentinel KQL hunt queries |

### IoCs

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/v1/iocs` | List IoCs (`?type=`, `?pyramid_tier=`, `?actor_id=`, `?tlp=`) |
| `GET` | `/v1/iocs/{id}` | Single IoC detail |
| `GET` | `/v1/iocs/{id}/stix` | STIX 2.1 indicator bundle |
| `GET` | `/v1/iocs/stix/bundle` | STIX 2.1 bundle for filtered IoC set |

### Detection Rules

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/v1/rules` | List rules (`?rule_type=sigma\|yara`, `?technique_id=`, `?severity=`) |
| `GET` | `/v1/rules/sigma/{id}` | Sigma rule — full YAML |
| `GET` | `/v1/rules/yara/{id}` | Yara rule — full content |

### Malware Families

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/v1/malware` | List malware families (`?q=`, `?family_type=`, `?skip=`, `?limit=`) |
| `GET` | `/v1/malware/{id}` | Family detail — lookup by UUID, Malpedia slug, or name |

### Reports

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/v1/reports/{id}/pdf` | Download PDF (`?template=executive\|tactical`) |

### AI Threats

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/v1/ai-threats` | Coverage overview (ATLAS + OWASP LLM + incidents count) |
| `GET` | `/v1/ai-threats/atlas` | MITRE ATLAS adversarial ML techniques |
| `GET` | `/v1/ai-threats/owasp-llm` | OWASP LLM Top 10 (2025) items |
| `GET` | `/v1/ai-threats/owasp-llm/{id}` | Single item (e.g. `LLM01` or `LLM01:2025`) |
| `GET` | `/v1/ai-threats/incidents` | Curated real-world AI incidents (`?owasp_id=`, `?atlas_id=`) |

### Analytics

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/v1/analytics/coverage` | Detection gap report — observed TTPs vs rule coverage |
| `GET` | `/v1/analytics/sectors` | Sector targeting heatmap (`?sponsor_type=`, `?country=`) |

### Alerting

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/v1/watchlist` | List alert subscriptions |
| `POST` | `/v1/watchlist` | Create subscription *(auth)* |
| `DELETE` | `/v1/watchlist/{id}` | Remove subscription *(auth)* |
| `POST` | `/v1/watchlist/test` | Send test ping to a webhook URL *(auth)* |

### Threat Hunt Workbench

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/v1/hunts` | Create a new threat hunt session *(auth)* |
| `GET` | `/v1/hunts` | List threat hunt sessions (`?status=active\|archived\|closed`) |
| `GET` | `/v1/hunts/{id}` | Detailed session metadata, notes and observations |
| `PUT` | `/v1/hunts/{id}` | Update session metadata *(auth)* |
| `DELETE` | `/v1/hunts/{id}` | Archive a hunt session *(auth)* |
| `POST` | `/v1/hunts/{id}/observations` | Log an observation (auto-links to DB IoCs/actors/techniques) *(auth)* |
| `DELETE` | `/v1/hunts/{id}/observations/{obs_id}` | Remove an observation *(auth)* |
| `GET` | `/v1/hunts/{id}/notes` | Retrieve session notes |
| `PUT` | `/v1/hunts/{id}/notes` | Save session notes *(auth)* |
| `POST` | `/v1/hunts/{id}/suggest-actors` | Run Claude AI threat actor suggestions *(auth)* |
| `POST` | `/v1/hunts/{id}/refine-hypothesis` | Run Claude AI hypothesis refinement review *(auth)* |
| `POST` | `/v1/hunts/{id}/draft-detection` | Generate a code-level detection rule *(auth)* |
| `GET` | `/v1/hunts/{id}/detections` | List drafted rules |
| `PUT` | `/v1/hunts/{id}/detections/{det_id}` | Edit a drafted detection rule *(auth)* |
| `POST` | `/v1/hunts/{id}/detections/{det_id}/promote` | Promote a draft rule to Pythia's main signature database *(auth)* |

### Honeypot Collection

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/v1/honeypot/events/bulk` | Batch ingest Cowrie/T-Pot events *(auth)* |
| `POST` | `/v1/honeypot/events` | Single event ingest *(auth)* |
| `GET` | `/v1/honeypot/events` | List events (`?ip=`, `?type=`, `?campaign=`, `?since=`) |
| `GET` | `/v1/honeypot/events/{id}` | Event detail with enrichment data |
| `GET` | `/v1/honeypot/campaigns` | List campaigns (`?status=active\|dormant\|archived`) |
| `GET` | `/v1/honeypot/campaigns/{id}` | Campaign detail + member event summary |
| `POST` | `/v1/honeypot/campaigns/{id}/generate-report` | Queue campaign CTI report generation *(auth)* |
| `POST` | `/v1/honeypot/detect-now` | Manually trigger campaign clustering *(auth)* |
| `GET` | `/v1/honeypot/stats/daily` | Last 24-hour summary (top IPs, ports, countries, credentials) |
| `GET` | `/v1/honeypot/stats/realtime` | Last 5-minute event counts by honeypot type |
| `GET` | `/v1/honeypot/feeds/blocklist.txt` | Plaintext IP blocklist (high-confidence + active campaigns) |
| `GET` | `/v1/honeypot/taxii/honeypot-iocs` | STIX 2.1 bundle of campaign IOCs (TAXII-compatible) |
| `WS` | `/v1/honeypot/stream` | WebSocket — live event stream |

### SIEM Integration

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/v1/siem/status` | Test SIEM connection; return type and connection state |
| `POST` | `/v1/siem/rules/deploy/{rule_id}` | Convert + push one Sigma rule to the configured SIEM *(auth)* |
| `POST` | `/v1/siem/rules/deploy-all` | Push all active DetectionRules to the SIEM *(auth)* |
| `DELETE` | `/v1/siem/rules/{rule_id}` | Remove a rule from the SIEM *(auth)* |
| `GET` | `/v1/siem/alerts` | List SIEM alerts (`?triage_status=`, `?severity=`, `?since=`) |
| `GET` | `/v1/siem/alerts/stats` | Alert counts by severity and triage status |
| `GET` | `/v1/siem/alerts/{id}` | Alert detail |
| `POST` | `/v1/siem/alerts` | Webhook receiver — SIEM posts here when a rule fires |
| `PATCH` | `/v1/siem/alerts/{id}/triage` | Update triage status *(auth)* |

### Feed

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/v1/feed.atom` | Atom 1.0 feed of ingested intel reports |

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PHISHTANK_API_KEY` | — | PhishTank app key for phishing URL feed |
| `OTX_API_KEY` | — | AlienVault OTX API key (reserved, not yet implemented) |
| `PYTHIA_ENABLE_SCHEDULER` | `false` | Start APScheduler background sync jobs on API startup |
| `PYTHIA_HONEYPOT_INGEST_ENABLED` | `false` | Enable `/v1/honeypot` endpoints |
| `ABUSEIPDB_API_KEY` | — | AbuseIPDB enrichment (free: 1,000 checks/day) |
| `GREYNOISE_API_KEY` | — | GreyNoise enrichment (free community tier) |
| `VIRUSTOTAL_API_KEY` | — | VirusTotal enrichment (free: 500 req/day) |
| `MAXMIND_DB_PATH` | — | Path to `GeoLite2-City.mmdb` |
| `MAXMIND_ASN_DB_PATH` | — | Path to `GeoLite2-ASN.mmdb` |
| `PYTHIA_SIEM_TYPE` | — | `wazuh`, `splunk`, or `elastic` (blank = disabled) |
| `PYTHIA_SIEM_URL` | — | Base URL of the SIEM API |
| `PYTHIA_SIEM_USERNAME` | — | SIEM API username |
| `PYTHIA_SIEM_PASSWORD` | — | SIEM API password |
| `PYTHIA_SIEM_API_TOKEN` | — | API token (Elastic/OpenSearch only) |

---

## Common curl Examples

```bash
# Actor lookup (smart — slug, name, substring all work)
curl http://localhost:8000/v1/actors/apt28
curl http://localhost:8000/v1/actors/lazarus-group
curl http://localhost:8000/v1/actors/scattered

# Kill Chain for APT28
curl http://localhost:8000/v1/actors/apt28/killchain | jq .phases

# All high-pyramid IoCs (domain/tool/TTP tier)
curl "http://localhost:8000/v1/iocs?pyramid_tier=domain&limit=10"

# Hunt queries for PowerShell execution
curl http://localhost:8000/v1/ttps/T1059.001/hunt-queries

# OWASP LLM Top 10 — prompt injection detail
curl http://localhost:8000/v1/ai-threats/owasp-llm/LLM01

# AI incidents filtered to Morris II worm
curl "http://localhost:8000/v1/ai-threats/incidents?atlas_id=AML.T0051"

# Detection coverage gap
curl http://localhost:8000/v1/analytics/coverage | jq '{pct: .coverage_pct, uncovered: .uncovered_count}'

# Sector targeting for nation-state actors
curl "http://localhost:8000/v1/analytics/sectors?sponsor_type=nation-state"

# Export APT28 as STIX 2.1
curl http://localhost:8000/v1/actors/apt28/stix | jq .type

# Download executive PDF
curl "http://localhost:8000/v1/reports/<id>/pdf?template=executive" -o brief.pdf

# Subscribe to Slack alerts for any Lazarus Group intel
curl -X POST http://localhost:8000/v1/watchlist \
  -H "X-API-Key: $PYTHIA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"Lazarus Watch","filter_actor":"lazarus","webhook_url":"https://hooks.slack.com/...","webhook_type":"slack"}'

# Threat Hunt Workbench: create a new session
curl -X POST http://localhost:8000/v1/hunts \
  -H "X-API-Key: $PYTHIA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"Unsigned DLL side-loading hunt","hypothesis":"Threat actor is using unsigned DLL side-loading to bypass EDR."}'

# Threat Hunt Workbench: log an observation
curl -X POST http://localhost:8000/v1/hunts/<session_id>/observations \
  -H "X-API-Key: $PYTHIA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"obs_type":"ttp","value":"T1574.002","confidence_source":"B","confidence_info":"2"}'

# Threat Hunt Workbench: run AI actor attribution suggestions
curl -X POST http://localhost:8000/v1/hunts/<session_id>/suggest-actors -H "X-API-Key: $PYTHIA_API_KEY"
```
