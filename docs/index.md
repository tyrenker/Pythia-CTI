# Pythia

**Oracle-grade threat intelligence, served as an API.**

> *Named after the high priestess of Delphi, who delivered Apollo's prophecies — built to surface the threats your business doesn't see coming yet.*

---

## What is Pythia?

Pythia is an open-source, clone-and-run **cyber threat intelligence (CTI) platform** that:

- Ingests raw intel from public sources (MITRE ATT&CK, MISP Galaxy, CISA KEV, MITRE ATLAS) and analyst-submitted reports
- Normalizes every record against industry frameworks: ATT&CK, ATLAS, OWASP LLM Top 10, Kill Chain, Diamond Model, Pyramid of Pain, Admiralty Code, and TLP
- Exposes a clean **REST API** with auto-generated OpenAPI docs
- Generates **executive-ready PDF reports** that translate attacker TTPs into CFO-readable business impact
- Exports **STIX 2.1 bundles** for interoperability with MISP, OpenCTI, and Splunk TAXII
- Ships with **8 curated real-world AI security incidents** mapped to MITRE ATLAS and OWASP LLM Top 10

No SaaS. No hosting fees. One command and it runs on your laptop.

---

## Quick Start

```bash
git clone https://github.com/tyrenker/pythia
cd pythia
cp .env.example .env           # add your ANTHROPIC_API_KEY
docker compose up -d           # starts API + auto-seeds DB on first run
curl http://localhost:8000/v1/health
```

Browse the interactive API docs at **[http://localhost:8000/docs](http://localhost:8000/docs)**.

---

## What's Seeded Out-of-the-Box

| Dataset | Count | Source |
|---|---|---|
| Threat actor profiles | 1,184 | MISP Galaxy + ATT&CK + APT Groups Sheet |
| ATT&CK techniques | 759 | MITRE ATT&CK v14 (Enterprise + Mobile + ICS) |
| Actor → TTP mappings | 3,634 | MITRE ATT&CK |
| CISA Known Exploited CVEs | 1,602 | CISA KEV |
| MITRE ATLAS AI/ML techniques | full catalog | MITRE ATLAS |
| OWASP LLM Top 10 (2025) | 10 | Hand-maintained |
| Curated Sigma rules | 16 | SigmaHQ-adapted (plus 14 Yara) |
| AI security incidents | 8 | Hand-curated |

---

## Key Differentiators

=== "Business Impact Translator"
    Most CTI tools dump IOC lists. Pythia generates a **CFO-readable brief** for every ingested report:
    financial impact range, operational risk, and three board-level recommended actions.

=== "AI Threat Coverage"
    Pythia is one of the few open-source CTI tools with dedicated **MITRE ATLAS** and **OWASP LLM Top 10 (2025)** coverage,
    including 8 curated real-world AI security incidents (Morris II worm, Slack AI RAG exfil, Samsung ChatGPT leak, etc.).

=== "STIX 2.1 Export"
    Every threat actor and IoC exports as a standards-compliant STIX 2.1 bundle — consumable by MISP, OpenCTI, and any TAXII-aware SIEM.

=== "Detection Engineering Ready"
    Multi-platform hunt query generator converts Sigma rules to Splunk SPL, Elastic KQL, and Microsoft Sentinel KQL per technique.
    Coverage gap report shows exactly which observed TTPs lack a detection rule.
