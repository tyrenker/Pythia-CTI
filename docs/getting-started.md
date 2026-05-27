# Getting Started

## Prerequisites

- Docker + Docker Compose (recommended), **or** Python 3.11+
- An [Anthropic API key](https://console.anthropic.com/) (free tier works for demos)

---

## Option A — Docker (Recommended)

```bash
git clone https://github.com/tyrenker/Pythia-CTI
cd Pythia-CTI
cp .env.example .env
# Edit .env and set ANTHROPIC_API_KEY=sk-ant-...
docker compose up -d
```

On first start, the entrypoint automatically runs `pythia sync` to seed the database from upstream open-source sources (ATT&CK, MISP Galaxy, CISA KEV, ATLAS). This takes ~2 minutes.

```bash
curl http://localhost:8000/v1/health
# {"status":"ok","version":"0.1.0"}
```

---

## Option B — Local Python

```bash
git clone https://github.com/tyrenker/Pythia-CTI
cd Pythia-CTI
python -m venv .venv && source .venv/bin/activate
pip install -e ".[all]" # Installs all modules: ingestion, reporting, detections, and scheduling
cp .env.example .env
# Edit .env and set ANTHROPIC_API_KEY=sk-ant-...
pythia sync          # seed the database (~2 min)
pythia serve         # starts API at http://127.0.0.1:8000
```

---

## Seeding Data

`pythia sync` pulls from all default upstream sources:

```bash
pythia sync                    # all sources (recommended on first run)
pythia sync attck atlas        # only ATT&CK + ATLAS
pythia sync owasp              # only OWASP LLM Top 10
pythia sync --dry-run          # count-only, no writes
```

Optional large pulls (off by default):

```bash
pythia sync sigma-full         # full SigmaHQ ruleset (thousands of rules)
pythia sync yara-full          # Yara-Rules community repo
pythia sync abuse-ch           # ThreatFox + URLhaus + MalwareBazaar
pythia sync otx                # AlienVault OTX (requires OTX_API_KEY)
```

## Optional External Feeds

These sources are off by default. Pass them explicitly to `pythia sync`:

| Source | Command | Requires |
|---|---|---|
| abuse.ch ThreatFox | `pythia sync abuse-ch` | None |
| IPsum IP blocklist | `pythia sync ipsum` | None |
| PhishTank phishing URLs | `pythia sync phishtank` | `PHISHTANK_API_KEY` in `.env` |
| Malpedia malware families | `pythia sync malpedia` | Optional `MALPEDIA_API_KEY` for full data |
| Full SigmaHQ ruleset | `pythia sync sigma-full` | None (large download ~100 MB) |
| Yara-Rules repository | `pythia sync yara-rules` | None (large download) |
| Icewater YARA rules | `pythia sync icewater` | None |
| Neo23x0 signature-base | `pythia sync signature-base` | None |

### Automatic Scheduling

Set `PYTHIA_ENABLE_SCHEDULER=true` in `.env` to enable background syncing when the API server runs. The schedule is:

| Feed | Cadence |
|---|---|
| abuse.ch | Daily 02:00 |
| IPsum | Daily 03:00 |
| PhishTank | Daily 03:30 |
| APT Sheet | Weekly (Sun 04:00) |
| Malpedia | Weekly (Sun 05:00) |
| Yara-Rules | Weekly (Sun 06:00) |
| Icewater | Weekly (Sun 07:00) |
| signature-base | Weekly (Sun 08:00) |

Requires the `scheduling` extra: `pip install "pythia[scheduling]"`.

---

## Ingesting Intel

### Paste a URL
```bash
# CLI
pythia ingest https://www.huntress.com/blog/the-gentlemen-ransomware-defense-evasion-ttps

# API
curl -X POST http://localhost:8000/v1/parse \
  -H "X-API-Key: $PYTHIA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://..."}'
```

### Paste raw text
```bash
curl -X POST http://localhost:8000/v1/parse \
  -H "X-API-Key: $PYTHIA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"text": "APT28 used T1566 phishing to deliver..."}'
```

Claude extracts: actors, TTPs, IoCs, sectors targeted, business impact, and optionally draft Sigma rules.

---

## Generating Reports

```bash
# Generate an executive PDF for a parsed report
pythia report <report_id> --template executive --output exec_brief.pdf

# Or via API
curl "http://localhost:8000/v1/reports/<id>/pdf?template=executive" --output brief.pdf
```

---

## Using the CLI

```
pythia --help

Commands:
  serve           Start the API server
  sync            Refresh seed data from upstream sources
  ingest          Parse a URL with Claude
  parse           Parse a URL or raw text with Claude
  report          Render a PDF report
  hunt            Generate multi-platform hunt queries for a TTP
  version         Print version

Subcommands:
  list actors     List threat actor profiles
  list threats    List ingested intel reports
  list ttps       List ATT&CK techniques
  list iocs       List indicators of compromise
  list rules      List Sigma/Yara detection rules
  list owasp-llm  List OWASP LLM Top 10 categories
  list ai-incidents  List curated AI security incidents

  stix actor      Export actor as STIX 2.1 bundle
  stix iocs       Export IoCs as STIX 2.1 bundle

  watchlist add   Create a webhook alert subscription
  watchlist list  List active subscriptions
  watchlist delete Remove a subscription

  create actor    Create a manual threat actor profile
```

---

## Docker Shell Alias

For Docker users who want native-feeling CLI access:

```bash
# Add to ~/.zshrc or ~/.bashrc
alias pythia='docker exec -it pythia pythia'

# Then use as if installed locally
pythia list actors --limit 10
pythia hunt T1059.001
```
