# External Intel Sources

Pythia can pull threat data from a range of external open-source feeds and repositories. This page documents each integration: what it provides, how idempotency is handled, and what (if any) API key is required.

---

## Overview

On first run, `pythia sync` seeds the database from the **core sources** automatically:

| Source | Data type | Seeded by default |
|---|---|---|
| MITRE ATT&CK | Techniques, tactics | Yes |
| MITRE ATLAS | AI adversarial ML techniques | Yes |
| OWASP LLM Top 10 | AI security risk categories | Yes |
| MISP Galaxy | Threat actor clusters | Yes |
| CISA KEV | Known exploited vulnerabilities (as IoCs) | Yes |

All other sources below are **opt-in** — run their sync command explicitly or enable the scheduler.

---

## APT Groups Spreadsheet

The [APT Groups and Operations](https://docs.google.com/spreadsheets/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU) Google Sheet is the most comprehensive public mapping of threat actor names, aliases, and country attributions.

**Command:** `pythia sync apt-sheet`

**How it works:**

1. Downloads the sheet as CSV via the public export URL.
2. Parses each row into an `Actor` record (name, aliases, country code, sponsor type).
3. Upserts on `name` — safe to re-run; no duplicate actors are created.
4. Enriches existing actors imported from ATT&CK (merges aliases and country data).

**Idempotency:** The importer uses `INSERT OR IGNORE` / `ON CONFLICT DO UPDATE` on actor name. Repeated runs only add new rows.

**Stats after sync:** ~800+ actor profiles.

---

## IoC Feeds

### abuse.ch (ThreatFox, URLhaus, MalwareBazaar, Feodo, SSLBL)

**Command:** `pythia sync abuse-ch`

| Feed | Endpoint | Data type | Pyramid tier |
|---|---|---|---|
| ThreatFox | `threatfox.abuse.ch/export/json/recent/` | IPs, domains, URLs, hashes | ip / domain / hash |
| URLhaus | `urlhaus-api.abuse.ch/v1/urls/recent/` | Malicious URLs | domain |
| MalwareBazaar | `bazaar.abuse.ch/export/json/recent/` | Malware file hashes | hash |
| Feodo Tracker | `feodotracker.abuse.ch/downloads/ipblocklist.json` | C2 IPs | ip |
| SSLBL | `sslbl.abuse.ch/blacklist/sslblacklist.csv` | SSL certificate hashes | hash |

All feeds are free and require no API key.

### IPsum IP Blocklist

**Command:** `pythia sync ipsum`

Downloads the [stamparm/ipsum](https://github.com/stamparm/ipsum) daily IP blocklist. Each IP appears with a confidence score based on how many blocklists it appears on. Pythia stores IPs at pyramid tier `ip`.

No API key required.

### PhishTank

**Command:** `pythia sync phishtank`

Downloads verified phishing URLs from [PhishTank](https://www.phishtank.com/). Requires a **free PhishTank App Key** to avoid rate limiting on the bulk download endpoint.

**Setup:**

```bash
# .env
PHISHTANK_API_KEY=your-app-key
```

Without the key, the sync will fail with HTTP 429.

### CISA KEV (Known Exploited Vulnerabilities)

Seeded automatically as part of `pythia sync`. Downloads the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) JSON and imports CVE identifiers as IoCs at pyramid tier `ttp`.

---

## Detection Rule Repositories

All rule repos are large downloads. They are skipped in the default sync and must be run explicitly.

### SigmaHQ Full Ruleset

**Command:** `pythia sync sigma-full`

Clones or pulls [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) and imports all `.yml` rule files. Expect **4,000–6,000 rules** and a download of approximately **100 MB**.

Rules are tagged with their ATT&CK technique IDs from the `tags:` field.

### Yara-Rules Community Repository

**Command:** `pythia sync yara-rules`

Pulls [Yara-Rules/rules](https://github.com/Yara-Rules/rules). Imports `.yar` and `.yara` files. Large download; expect several hundred rules.

### Icewater YARA Rules

**Command:** `pythia sync icewater`

Pulls [SupportIntelligence/Icewater](https://github.com/SupportIntelligence/Icewater). Focused on file-based detection. Several thousand short rules.

### Neo23x0 signature-base

**Command:** `pythia sync signature-base`

Pulls [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) by Florian Roth — a large, high-quality collection of YARA and Sigma rules used by the community.

---

## Malware Families (Malpedia)

**Command:** `pythia sync malpedia`

[Malpedia](https://malpedia.caad.fkie.fraunhofer.de/) is the most comprehensive open malware family database maintained by Fraunhofer FKIE.

**Slug format:** Each family has a unique slug like `win.wannacry` or `elf.mirai`. The slug is the stable identifier used for cross-referencing. The Malpedia detail URL is:

```
https://malpedia.caad.fkie.fraunhofer.de/details/<slug>
```

**Unauthenticated access:** The public API returns family names, aliases, and type. No key required.

**Authenticated access:** With a `MALPEDIA_API_KEY`, the API also returns actor-to-family associations (which actors used which malware). Without the key, `actor_ids` on each family will be empty.

```bash
# .env
MALPEDIA_API_KEY=your-token
```

Get a token at [malpedia.caad.fkie.fraunhofer.de/register](https://malpedia.caad.fkie.fraunhofer.de/register).

---

## Scheduling Reference

Set `PYTHIA_ENABLE_SCHEDULER=true` in `.env` to run feeds automatically when the API server starts. Requires `pip install "pythia[scheduling]"`.

| Feed | Cadence |
|---|---|
| abuse.ch | Daily 02:00 UTC |
| IPsum | Daily 03:00 UTC |
| PhishTank | Daily 03:30 UTC |
| APT Sheet | Weekly (Sun 04:00 UTC) |
| Malpedia | Weekly (Sun 05:00 UTC) |
| Yara-Rules | Weekly (Sun 06:00 UTC) |
| Icewater | Weekly (Sun 07:00 UTC) |
| signature-base | Weekly (Sun 08:00 UTC) |

Core sources (ATT&CK, ATLAS, MISP Galaxy, CISA KEV) are seeded once on startup and do not re-sync automatically — run `pythia sync` manually when frameworks release new versions.

---

## Troubleshooting

**Rate limits:** abuse.ch and PhishTank will 429 if you sync too frequently. The scheduler cadences above are set below each feed's documented rate limit.

**Large downloads timing out:** Yara-Rules, Icewater, and signature-base clone full Git repositories. On slow connections this can take 5–10 minutes. If a sync times out, re-run — the importer is idempotent.

**Missing API key:** If `PHISHTANK_API_KEY` or `MALPEDIA_API_KEY` is absent, the respective sync will skip gracefully (Malpedia) or fail with a clear error (PhishTank). The Sync Status panel in the UI shows `⚠ no key` for feeds with missing required keys.

**Disk space:** A full sync of all rule repositories can consume 500 MB–1 GB of working storage (cloned repos + database). The database itself remains much smaller as only parsed rule metadata is stored.
