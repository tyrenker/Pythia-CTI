import { useState } from 'react'
import {
  BookOpen,
  Terminal,
  Layers,
  Shield,
  Zap,
  Code,
  Copy,
  Check,
  Server,
  Radio,
  Activity
} from 'lucide-react'

// API Endpoints definition schema for the interactive API documentation
interface ApiEndpoint {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  path: string
  title: string
  description: string
  authRequired: boolean
  queryParams?: { name: string; type: string; required: boolean; default?: string; description: string; enum?: string[] }[]
  requestBody?: string // JSON string description of request body
  responseSchema: string // JSON string of response
  curlExample: string
}

const API_ENDPOINTS: Record<string, ApiEndpoint[]> = {
  Ingestion: [
    {
      method: 'POST',
      path: '/v1/parse',
      title: 'Parse Threat Intelligence',
      description: 'Fetch an article from a URL or parse raw threat intel text using Claude AI. Automatically extracts actors, TTPs, IoCs, CVEs, targeted geographies/sectors, and drafts board-ready business impact reports.',
      authRequired: true,
      requestBody: `{
  "url": "https://www.huntress.com/blog/the-gentlemen-ransomware-defense-evasion-ttps",
  "text": "Optional raw report text if scraping is not desired"
}`,
      responseSchema: `{
  "id": "6de4cc51-abc6-4d57-864b-96a25b573046",
  "title": "The Gentlemen Ransomware: Defense Evasion TTPs",
  "url": "https://www.huntress.com/blog/the-gentlemen-ransomware-defense-evasion-ttps",
  "tlp": "WHITE",
  "status": "pending_review",
  "parsed_data": {
    "title": "The Gentlemen Ransomware...",
    "summary": "Huntress SOC analysts investigated two incidents involving...",
    "actors": [{"name": "The Gentlemen", "confidence": "A2"}],
    "ttps": [{"technique_id": "T1562.001", "evidence": "used Set-MpPreference..."}],
    "iocs": [{"type": "ip", "value": "193.233.202.17", "context": "C2 IP..."}],
    "killchain_phases": ["initial-access", "defense-evasion", "c2", "impact"],
    "business_impact_draft": {
      "financial_range_usd": [50000, 5000000],
      "operational": "Ransomware encryption of critical files...",
      "regulatory": "Clearing of logs constitutes destruction of evidence...",
      "recommended_board_actions": ["Mandate MFA", "Invest in 24/7 SOC"]
    }
  }
}`,
      curlExample: `curl -X POST http://localhost:8000/v1/parse \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -d '{
    "url": "https://www.huntress.com/blog/the-gentlemen-ransomware-defense-evasion-ttps"
  }'`
    }
  ],
  Reports: [
    {
      method: 'GET',
      path: '/v1/reports/{report_id}/pdf',
      title: 'Generate PDF Report',
      description: 'Compile an ingested threat intelligence record into an A4 print-ready PDF using Jinja2 templates and WeasyPrint. Supports Executive and Tactical layouts.',
      authRequired: false,
      queryParams: [
        {
          name: 'template',
          type: 'string',
          required: false,
          default: 'executive',
          description: 'Type of layout templates to generate.',
          enum: ['executive', 'tactical']
        }
      ],
      responseSchema: `// Returns a binary response stream (PDF)
Content-Type: application/pdf
Content-Disposition: attachment; filename="pythia-executive-4f7cbb25.pdf"`,
      curlExample: `curl -o data/report.pdf \\
  "http://localhost:8000/v1/reports/6de4cc51-abc6-4d57-864b-96a25b573046/pdf?template=executive"`
    }
  ],
  Threats: [
    {
      method: 'GET',
      path: '/v1/threats',
      title: 'List Threat Reports',
      description: 'Fetch a collection of ingested intelligence reports stored in the database, ordered chronologically by ingestion time.',
      authRequired: false,
      queryParams: [
        {
          name: 'status',
          type: 'string',
          required: false,
          description: 'Filter by status (pending_review | accepted | rejected).'
        },
        {
          name: 'tlp',
          type: 'string',
          required: false,
          description: 'Filter by TLP marking (WHITE, GREEN, AMBER, RED).'
        },
        {
          name: 'limit',
          type: 'integer',
          required: false,
          default: '50',
          description: 'Maximum number of threat reports to return.'
        }
      ],
      responseSchema: `[
  {
    "id": "6de4cc51-abc6-4d57-864b-96a25b573046",
    "title": "Lazarus Group Phishing Activity",
    "url": null,
    "publication_date": null,
    "tlp": "GREEN",
    "status": "pending_review",
    "actors": ["Lazarus Group"],
    "ttps": ["T1566.001"],
    "ioc_count": 5
  }
]`,
      curlExample: `curl http://localhost:8000/v1/threats?limit=5`
    },
    {
      method: 'GET',
      path: '/v1/threats/{report_id}',
      title: 'Get Detailed Threat Report',
      description: 'Retrieve the complete database record and original parsed Claude data structure for a specific threat report ID.',
      authRequired: false,
      responseSchema: `{
  "id": "6de4cc51-abc6-4d57-864b-96a25b573046",
  "title": "Lazarus Group Phishing Activity",
  "url": null,
  "publication_date": null,
  "tlp": "GREEN",
  "status": "pending_review",
  "created_at": "2026-05-25T20:46:30.333518",
  "actors": ["Lazarus Group"],
  "ttps": ["T1566.001"],
  "parsed_data": {
    "title": "Lazarus Group Phishing Activity",
    "summary": "...",
    "actors": [{"name": "Lazarus Group", "aliases": [], "confidence": "B2"}],
    "ttps": [{"technique_id": "T1566.001", "evidence": "..."}],
    "business_impact_draft": {...}
  }
}`,
      curlExample: `curl http://localhost:8000/v1/threats/6de4cc51-abc6-4d57-864b-96a25b573046`
    }
  ],
  Actors: [
    {
      method: 'GET',
      path: '/v1/actors',
      title: 'List Threat Actors',
      description: 'Browse the merged MISP Galaxy and MITRE ATT&CK adversary database (~1,067 pre-seeded profiles). Supports fuzzy-searching by actor name or alias.',
      authRequired: false,
      queryParams: [
        {
          name: 'name',
          type: 'string',
          required: false,
          description: 'Search string to filter actors by name.'
        },
        {
          name: 'country',
          type: 'string',
          required: false,
          description: 'Filter by 2-letter country code (e.g. RU, CN).'
        },
        {
          name: 'limit',
          type: 'integer',
          required: false,
          default: '50',
          description: 'Maximum actor profiles to return.'
        }
      ],
      responseSchema: `[
  {
    "id": "APT28",
    "name": "APT28",
    "aliases": ["Fancy Bear", "STRONTIUM", "Sofacy", "Pawn Storm"],
    "country_code": "RU",
    "sponsor_type": "nation-state",
    "sophistication": 4,
    "tlp": "WHITE",
    "source": "misp-galaxy"
  }
]`,
      curlExample: `curl "http://localhost:8000/v1/actors?name=Fancy+Bear&limit=2"`
    },
    {
      method: 'GET',
      path: '/v1/actors/{actor_id}/killchain',
      title: 'Lockheed Martin Kill Chain Map',
      description: 'Organize a threat actor\'s historical techniques mapped directly into chronological Lockheed Martin Cyber Kill Chain phases (Reconnaissance, Weaponization, Delivery, Exploitation, Installation, C2, Actions).',
      authRequired: false,
      responseSchema: `{
  "actor_name": "APT28",
  "phases": {
    "reconnaissance": [],
    "weaponization": [],
    "delivery": [
      {
        "technique_id": "T1566",
        "name": "Phishing",
        "use_note": "APT28 has used spearphishing emails with malicious attachments..."
      }
    ],
    "exploitation": [...],
    "installation": [...],
    "command-and-control": [...],
    "actions-on-objectives": [...]
  }
}`,
      curlExample: `curl http://localhost:8000/v1/actors/APT28/killchain`
    },
    {
      method: 'GET',
      path: '/v1/actors/{actor_id}/diamond',
      title: 'Adversary Diamond Model View',
      description: 'Generate a Diamond Model representation of an adversary mapping Adversary, Capability, Infrastructure, and Victim nodes.',
      authRequired: false,
      responseSchema: `{
  "adversary": {
    "name": "APT28",
    "country": "RU",
    "sponsor_type": "nation-state"
  },
  "capability": {
    "technique_count": 71,
    "sample_techniques": ["T1566", "T1059", "T1071"]
  },
  "infrastructure": {
    "patterns": null,
    "known_tool_techniques": []
  },
  "victim": {
    "sectors": [],
    "geographies": ["RU", "US", "DE"]
  }
}`,
      curlExample: `curl http://localhost:8000/v1/actors/APT28/diamond`
    }
  ],
  Rules: [
    {
      method: 'GET',
      path: '/v1/rules',
      title: 'List Detection Rules',
      description: 'Fetch and filter parsed Sigma and Yara detection rules from the threat intelligence database.',
      authRequired: false,
      queryParams: [
        {
          name: 'rule_type',
          type: 'string',
          required: false,
          description: 'Filter by type: sigma | yara'
        },
        {
          name: 'technique_id',
          type: 'string',
          required: false,
          description: 'Filter by linked MITRE ATT&CK technique ID (e.g. T1059)'
        },
        {
          name: 'severity',
          type: 'string',
          required: false,
          description: 'Filter by severity rating (low | medium | high | critical)'
        }
      ],
      responseSchema: `[
  {
    "id": "1e8c16e4-df0c-4334-a212-be02d17c3ae0",
    "rule_type": "sigma",
    "title": "Suspicious Beaconing Interval to Single External Host",
    "technique_ids": ["T1071.001"],
    "severity": "low",
    "status": "experimental",
    "source_url": null
  }
]`,
      curlExample: `curl "http://localhost:8000/v1/rules?rule_type=sigma&severity=high"`
    },
    {
      method: 'POST',
      path: '/v1/rules',
      title: 'Create Detection Rule',
      description: 'Submit and store a new manually drafted detection rule (Sigma or Yara syntax). Mapped to relevant techniques and actors.',
      authRequired: true,
      requestBody: `{
  "rule_type": "sigma",
  "title": "Defender Disabled via PowerShell Script",
  "content": "title: Defender Disabled via PowerShell\\nstatus: experimental...",
  "severity": "high",
  "technique_ids": ["T1562.001"],
  "actor_ids": [],
  "status": "experimental",
  "source_url": "https://example.com/defense-evasion"
}`,
      responseSchema: `{
  "id": "7de816f2-af02-4d22-b9dc-cb02d17c3ae0",
  "rule_type": "sigma",
  "title": "Defender Disabled via PowerShell Script",
  "content": "title: Defender Disabled...",
  "technique_ids": ["T1562.001"],
  "actor_ids": [],
  "severity": "high",
  "status": "experimental",
  "source_url": "https://example.com/defense-evasion"
}`,
      curlExample: `curl -X POST http://localhost:8000/v1/rules \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -d '{
    "rule_type": "sigma",
    "title": "Defender Disabled via PowerShell Script",
    "content": "...",
    "severity": "high",
    "technique_ids": ["T1562.001"]
  }'`
    },
    {
      method: 'PUT',
      path: '/v1/rules/{rule_id}',
      title: 'Update Detection Rule',
      description: 'Partially update an existing detection rule\'s fields (title, content, severity, linked techniques, status, etc.) via PATCH requests.',
      authRequired: true,
      requestBody: `{
  "title": "Updated Rule Title",
  "severity": "critical"
}`,
      responseSchema: `{
  "id": "7de816f2-af02-4d22-b9dc-cb02d17c3ae0",
  "rule_type": "sigma",
  "title": "Updated Rule Title",
  "content": "...",
  "technique_ids": ["T1562.001"],
  "actor_ids": [],
  "severity": "critical",
  "status": "experimental"
}`,
      curlExample: `curl -X PATCH http://localhost:8000/v1/rules/7de816f2-af02-4d22-b9dc-cb02d17c3ae0 \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -d '{
    "severity": "critical"
  }'`
    },
    {
      method: 'DELETE',
      path: '/v1/rules/{rule_id}',
      title: 'Delete Detection Rule',
      description: 'Permanently remove a Sigma or Yara rule from the threat database.',
      authRequired: true,
      responseSchema: `// Returns status code 204 No Content on success`,
      curlExample: `curl -X DELETE http://localhost:8000/v1/rules/7de816f2-af02-4d22-b9dc-cb02d17c3ae0 \\
  -H "Authorization: Bearer YOUR_API_KEY"`
    }
  ],
  Watchlist: [
    {
      method: 'POST',
      path: '/v1/watchlist',
      title: 'Create Watchlist Alert',
      description: 'Configure a new webhook subscription alert. Whenever threat intelligence matching your specified actor name, ATT&CK technique, or target sector is parsed, Pythia will trigger a structured payload to the target Slack, Discord, or generic Webhook URL.',
      authRequired: true,
      requestBody: `{
  "name": "Ransomware Alert Slack Integration",
  "filter_actor": "The Gentlemen",
  "filter_ttp": "T1486",
  "filter_sector": null,
  "webhook_url": "https://hooks.slack.com/services/YOUR_WORKSPACE_ID/YOUR_CHANNEL_ID/YOUR_TOKEN",
  "webhook_type": "slack"
}`,
      responseSchema: `{
  "id": "3be92b1a-abc6-4d57-864b-96a25b573046",
  "name": "Ransomware Alert Slack Integration",
  "filter_actor": "The Gentlemen",
  "filter_ttp": "T1486",
  "filter_sector": null,
  "webhook_url": "https://hooks.slack.com/services/...",
  "webhook_type": "slack",
  "enabled": true
}`,
      curlExample: `curl -X POST http://localhost:8000/v1/watchlist \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -d '{
    "name": "Ransomware Alert",
    "filter_ttp": "T1486",
    "webhook_url": "https://hooks.slack.com/services/...",
    "webhook_type": "slack"
  }'`
    },
    {
      method: 'GET',
      path: '/v1/watchlist',
      title: 'List Active Watchlists',
      description: 'Browse all configured webhook watchlist alert filters and targets.',
      authRequired: false,
      responseSchema: `[
  {
    "id": "3be92b1a-abc6-4d57-864b-96a25b573046",
    "name": "Ransomware Alert",
    "filter_actor": null,
    "filter_ttp": "T1486",
    "filter_sector": null,
    "webhook_url": "https://hooks.slack.com/services/...",
    "webhook_type": "slack",
    "enabled": true
  }
]`,
      curlExample: `curl http://localhost:8000/v1/watchlist`
    },
    {
      method: 'DELETE',
      path: '/v1/watchlist/{watchlist_id}',
      title: 'Delete Watchlist Alert',
      description: 'Remove a webhook watchlist subscription, stopping any future matches from triggering alerts.',
      authRequired: true,
      responseSchema: `// Returns status code 204 No Content on success`,
      curlExample: `curl -X DELETE http://localhost:8000/v1/watchlist/3be92b1a-abc6-4d57-864b-96a25b573046 \\
  -H "Authorization: Bearer YOUR_API_KEY"`
    },
    {
      method: 'POST',
      path: '/v1/watchlist/test',
      title: 'Test Webhook Connectivity',
      description: 'Fire a diagnostic mock alert text ping to the target Webhook URL to verify connectivity without waiting for a database trigger.',
      authRequired: true,
      requestBody: `{
  "webhook_url": "https://hooks.slack.com/services/YOUR_WORKSPACE_ID/YOUR_CHANNEL_ID/YOUR_TOKEN",
  "webhook_type": "slack"
}`,
      responseSchema: `{
  "status": "ok",
  "http_status": "200"
}`,
      curlExample: `curl -X POST http://localhost:8000/v1/watchlist/test \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -d '{
    "webhook_url": "https://hooks.slack.com/services/...",
    "webhook_type": "slack"
  }'`
    }
  ],
  Honeypot: [
    {
      method: 'POST',
      path: '/v1/honeypot/events/bulk',
      title: 'Batch Ingest Honeypot Events',
      description: 'Accept an array of raw Cowrie (or Dionaea / Honeytrap / Mailoney) JSON events. Pythia normalizes each event, persists it, then queues background enrichment (GeoIP, ASN, AbuseIPDB, GreyNoise, VirusTotal). Used by the honeypot-forwarder container that tails the Cowrie log on your VPS.',
      authRequired: true,
      requestBody: `[
  {
    "eventid": "cowrie.login.failed",
    "src_ip": "185.220.101.42",
    "username": "root",
    "password": "admin123",
    "timestamp": "2026-06-20T14:32:11Z",
    "sensor": "cowrie-vps-01"
  }
]`,
      responseSchema: `{
  "ingested": 1
}`,
      curlExample: `curl -X POST http://localhost:8000/v1/honeypot/events/bulk \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: YOUR_API_KEY" \\
  -d '[{"eventid":"cowrie.login.failed","src_ip":"185.220.101.42","username":"root","password":"admin123","timestamp":"2026-06-20T14:32:11Z"}]'`
    },
    {
      method: 'GET',
      path: '/v1/honeypot/events',
      title: 'List Honeypot Events',
      description: 'Browse raw attack events captured by the honeypot. Filter by attacker IP, honeypot type, campaign ID, or time window. Events include enrichment data (GeoIP country, ASN, AbuseIPDB score, GreyNoise classification) once the background enricher has run.',
      authRequired: false,
      queryParams: [
        { name: 'ip', type: 'string', required: false, description: 'Filter by attacker IP address.' },
        { name: 'honeypot_type', type: 'string', required: false, description: 'cowrie | dionaea | honeytrap | mailoney' },
        { name: 'campaign', type: 'string', required: false, description: 'Filter by campaign UUID.' },
        { name: 'since', type: 'datetime', required: false, description: 'ISO-8601 lower bound for event_timestamp.' },
        { name: 'limit', type: 'integer', required: false, default: '50', description: 'Max results (≤ 500).' },
        { name: 'offset', type: 'integer', required: false, default: '0', description: 'Pagination offset.' }
      ],
      responseSchema: `[
  {
    "id": "a1b2c3d4-...",
    "honeypot_type": "cowrie",
    "attacker_ip": "185.220.101.42",
    "attacker_country_code": "DE",
    "attacker_asn": "AS60781",
    "attacker_org": "LeaseWeb Netherlands B.V.",
    "target_port": 22,
    "protocol": "ssh",
    "event_timestamp": "2026-06-20T14:32:11",
    "username_attempted": "root",
    "password_attempted": "admin123",
    "commands_run": [],
    "ttp_ids": [],
    "campaign_id": null,
    "abuseipdb_score": 87,
    "greynoise_classification": "malicious",
    "vt_detections": null
  }
]`,
      curlExample: `curl "http://localhost:8000/v1/honeypot/events?honeypot_type=cowrie&limit=10"`
    },
    {
      method: 'GET',
      path: '/v1/honeypot/campaigns',
      title: 'List Attack Campaigns',
      description: 'Returns clustered attack campaigns built by the background campaign-detection job (runs every 15 minutes when PYTHIA_ENABLE_SCHEDULER=true). Each campaign groups related attacker IPs by shared ASN, payload hashes, and credential patterns. Campaign status: active | dormant | archived.',
      authRequired: false,
      queryParams: [
        { name: 'status', type: 'string', required: false, description: 'active | dormant | archived' },
        { name: 'since', type: 'datetime', required: false, description: 'Filter by first_seen ≥ this timestamp.' },
        { name: 'limit', type: 'integer', required: false, default: '50', description: 'Max results.' }
      ],
      responseSchema: `[
  {
    "id": "f9e8d7c6-...",
    "name": "CAMPAIGN-2026-001",
    "status": "active",
    "first_seen": "2026-06-18T09:14:00",
    "last_seen": "2026-06-20T14:32:11",
    "attacker_ips": ["185.220.101.42", "45.143.201.10"],
    "asns": ["AS60781"],
    "ttp_ids": ["T1110.001"],
    "payload_hashes": [],
    "credential_patterns": {"root": 47, "admin": 23},
    "target_ports": [22],
    "event_count": 142,
    "sigma_rule_id": null,
    "report_id": null
  }
]`,
      curlExample: `curl "http://localhost:8000/v1/honeypot/campaigns?status=active"`
    },
    {
      method: 'POST',
      path: '/v1/honeypot/campaigns/{campaign_id}/generate-report',
      title: 'Generate Campaign CTI Report',
      description: 'Queue a background job to compile a structured CTI report for the specified campaign. The report summarises attack timeline, credential patterns, TTPs, and IOC table, then stores it as a ThreatReport in the main database.',
      authRequired: true,
      responseSchema: `{
  "status": "queued",
  "campaign_id": "f9e8d7c6-..."
}`,
      curlExample: `curl -X POST http://localhost:8000/v1/honeypot/campaigns/f9e8d7c6-.../generate-report \\
  -H "X-API-Key: YOUR_API_KEY"`
    },
    {
      method: 'GET',
      path: '/v1/honeypot/stats/daily',
      title: 'Daily Attack Summary',
      description: 'Returns aggregated statistics for the last 24 hours: total event count, top attacker IPs, most-targeted ports, honeypot type breakdown, most-tried credentials, and top attacker countries.',
      authRequired: false,
      responseSchema: `{
  "event_count": 847,
  "top_ips": [["185.220.101.42", 203], ["45.143.201.10", 97]],
  "top_ports": [[22, 731], [23, 116]],
  "by_honeypot_type": {"cowrie": 847},
  "top_credentials": [["root:admin123", 47], ["admin:password", 23]],
  "top_countries": [["DE", 203], ["RU", 156], ["CN", 98]]
}`,
      curlExample: `curl http://localhost:8000/v1/honeypot/stats/daily`
    },
    {
      method: 'GET',
      path: '/v1/honeypot/feeds/blocklist.txt',
      title: 'IP Blocklist Feed',
      description: 'Returns a plaintext newline-delimited list of high-confidence attacker IPs suitable for direct import into a firewall, Fail2Ban, or threat intel platform. Includes IPs with AbuseIPDB score ≥ 70 and any IP from an active campaign. No authentication required — designed for automated ingestion.',
      authRequired: false,
      responseSchema: `// Content-Type: text/plain
// Cache-Control: max-age=3600

45.143.201.10
185.220.101.42
91.92.251.103`,
      curlExample: `# Import directly into iptables
curl -s http://localhost:8000/v1/honeypot/feeds/blocklist.txt | \\
  while read ip; do iptables -A INPUT -s "$ip" -j DROP; done`
    },
    {
      method: 'GET',
      path: '/v1/honeypot/taxii/honeypot-iocs',
      title: 'STIX 2.1 Campaign IOC Bundle',
      description: 'Returns a STIX 2.1 bundle containing Indicator objects for all active campaign IOCs. Compatible with TAXII 2.1 clients and threat intel platforms that consume STIX. The Content-Type header is set to application/taxii+json;version=2.1.',
      authRequired: false,
      queryParams: [
        { name: 'status', type: 'string', required: false, default: 'active', description: 'Campaign status to export (active | dormant | archived).' }
      ],
      responseSchema: `{
  "type": "bundle",
  "id": "bundle--...",
  "spec_version": "2.1",
  "objects": [
    {
      "type": "indicator",
      "id": "indicator--...",
      "name": "Honeypot Campaign CAMPAIGN-2026-001 IP: 185.220.101.42",
      "pattern": "[ipv4-addr:value = '185.220.101.42']",
      "pattern_type": "stix",
      "valid_from": "2026-06-18T09:14:00Z"
    }
  ]
}`,
      curlExample: `curl http://localhost:8000/v1/honeypot/taxii/honeypot-iocs | jq '.objects | length'`
    }
  ],
  SIEM: [
    {
      method: 'GET',
      path: '/v1/siem/status',
      title: 'SIEM Connection Status',
      description: 'Tests connectivity to the configured SIEM backend and returns the SIEM type and connection state. SIEM type is controlled by PYTHIA_SIEM_TYPE in .env (wazuh | splunk | elastic). Returns configured: false if no SIEM is set up.',
      authRequired: false,
      responseSchema: `{
  "configured": true,
  "siem_type": "wazuh",
  "connected": true
}`,
      curlExample: `curl http://localhost:8000/v1/siem/status`
    },
    {
      method: 'POST',
      path: '/v1/siem/rules/deploy-all',
      title: 'Deploy All Rules to SIEM',
      description: 'Converts all active DetectionRules (Sigma format) to the native SIEM query language and pushes them to the configured backend. Wazuh receives XML rules, Splunk receives SPL saved searches, Elastic receives EQL detection rules. Returns counts of deployed and failed rules.',
      authRequired: true,
      responseSchema: `{
  "deployed": 14,
  "failed": 0,
  "rule_ids": ["1e8c16e4-...", "7de816f2-...", "..."]
}`,
      curlExample: `curl -X POST http://localhost:8000/v1/siem/rules/deploy-all \\
  -H "X-API-Key: YOUR_API_KEY"`
    },
    {
      method: 'POST',
      path: '/v1/siem/rules/deploy/{rule_id}',
      title: 'Deploy Single Rule to SIEM',
      description: 'Convert and push a single Sigma detection rule to the configured SIEM. Stores the resulting SIEM-side rule ID back on the DetectionRule record so subsequent deploys are idempotent updates rather than duplicates.',
      authRequired: true,
      responseSchema: `{
  "rule_id": "1e8c16e4-df0c-4334-a212-be02d17c3ae0",
  "siem_rule_id": "wazuh-pythia-1e8c16e4",
  "deployed_at": "2026-06-20T15:00:00"
}`,
      curlExample: `curl -X POST http://localhost:8000/v1/siem/rules/deploy/1e8c16e4-df0c-4334-a212-be02d17c3ae0 \\
  -H "X-API-Key: YOUR_API_KEY"`
    },
    {
      method: 'GET',
      path: '/v1/siem/alerts',
      title: 'List SIEM Alerts',
      description: 'Browse alerts received from the SIEM via the webhook receiver endpoint. Each alert is correlated to a Pythia DetectionRule (if matched by title) and to a HoneypotCampaign (if the attacker IP is known). Triage status values: new | investigating | true_positive | false_positive | closed.',
      authRequired: false,
      queryParams: [
        { name: 'triage_status', type: 'string', required: false, description: 'new | investigating | true_positive | false_positive | closed' },
        { name: 'severity', type: 'string', required: false, description: 'critical | high | medium | low | info' },
        { name: 'since', type: 'datetime', required: false, description: 'Filter by received_at ≥ this timestamp.' },
        { name: 'limit', type: 'integer', required: false, default: '50', description: 'Max results.' }
      ],
      responseSchema: `[
  {
    "id": "c4d5e6f7-...",
    "siem_source": "wazuh",
    "external_alert_id": "1720483200.12345",
    "rule_id": "1e8c16e4-...",
    "campaign_id": "f9e8d7c6-...",
    "severity": "high",
    "title": "Suspicious SSH Brute Force from Known Malicious IP",
    "attacker_ip": "185.220.101.42",
    "mitre_techniques": ["T1110.001"],
    "triage_status": "new",
    "analyst_notes": null,
    "received_at": "2026-06-20T14:35:00"
  }
]`,
      curlExample: `curl "http://localhost:8000/v1/siem/alerts?triage_status=new&severity=high"`
    },
    {
      method: 'POST',
      path: '/v1/siem/alerts',
      title: 'SIEM Alert Webhook Receiver',
      description: 'Webhook endpoint that your SIEM calls when a detection rule fires. Wazuh, Splunk, and Elastic all support outbound webhooks. Pythia auto-correlates the incoming alert to a known DetectionRule (by title match) and to a HoneypotCampaign (by attacker IP). No authentication required — designed for SIEM integration.',
      authRequired: false,
      requestBody: `// Wazuh integration format (sent by the custom-pythia integration script)
{
  "id": "1720483200.12345",
  "rule": {
    "description": "Suspicious SSH Brute Force",
    "level": "high",
    "mitre": { "id": ["T1110.001"] }
  },
  "data": { "srcip": "185.220.101.42" }
}`,
      responseSchema: `{
  "alert_id": "c4d5e6f7-..."
}`,
      curlExample: `# Simulating a Wazuh alert webhook
curl -X POST http://localhost:8000/v1/siem/alerts \\
  -H "Content-Type: application/json" \\
  -d '{"id":"test-001","rule":{"description":"SSH Brute Force","level":"high","mitre":{"id":["T1110.001"]}},"data":{"srcip":"185.220.101.42"}}'`
    },
    {
      method: 'PATCH',
      path: '/v1/siem/alerts/{alert_id}/triage',
      title: 'Triage a SIEM Alert',
      description: 'Update the triage status of a SIEM alert. Valid transitions: new → investigating → true_positive | false_positive → closed. Analyst notes and triaged_by are optional free-text fields stored for audit trail purposes.',
      authRequired: true,
      requestBody: `{
  "triage_status": "true_positive",
  "analyst_notes": "Confirmed Mirai botnet scanner — matches CAMPAIGN-2026-001 TTPs.",
  "triaged_by": "analyst1"
}`,
      responseSchema: `{
  "id": "c4d5e6f7-...",
  "triage_status": "true_positive",
  "analyst_notes": "Confirmed Mirai botnet scanner — matches CAMPAIGN-2026-001 TTPs.",
  "triaged_by": "analyst1",
  "triaged_at": "2026-06-20T15:12:00",
  "severity": "high",
  "title": "Suspicious SSH Brute Force from Known Malicious IP"
}`,
      curlExample: `curl -X PATCH http://localhost:8000/v1/siem/alerts/c4d5e6f7-.../triage \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: YOUR_API_KEY" \\
  -d '{
    "triage_status": "true_positive",
    "analyst_notes": "Confirmed Mirai botnet scanner.",
    "triaged_by": "analyst1"
  }'`
    }
  ]
}

export function Docs() {
  const [activeSection, setActiveSection] = useState<string>('getting-started')
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [expandedEndpoints, setExpandedEndpoints] = useState<Record<string, boolean>>({})

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text)
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 2000)
  }

  const toggleEndpoint = (path: string) => {
    setExpandedEndpoints(prev => ({ ...prev, [path]: !prev[path] }))
  }

  return (
    <div className="flex flex-col lg:flex-row gap-6 text-text-primary">
      {/* Sidebar Navigation */}
      <aside className="w-full lg:w-64 shrink-0">
        <div className="sticky top-20 flex flex-col gap-1 rounded-xl border border-border bg-bg-surface p-4">
          <div className="mb-2 px-2 text-xs font-semibold uppercase tracking-wider text-text-muted">
            Getting Started
          </div>
          <button
            onClick={() => setActiveSection('getting-started')}
            className={`flex items-center gap-3 rounded-lg px-3 py-2 text-left text-xs font-medium transition-colors ${
              activeSection === 'getting-started'
                ? 'bg-accent/10 text-[#00ff88]'
                : 'text-text-muted hover:bg-bg-elevated hover:text-text-primary'
            }`}
          >
            <BookOpen size={14} />
            Overview & Design
          </button>
          <button
            onClick={() => setActiveSection('docker-cli')}
            className={`flex items-center gap-3 rounded-lg px-3 py-2 text-left text-xs font-medium transition-colors ${
              activeSection === 'docker-cli'
                ? 'bg-accent/10 text-[#00ff88]'
                : 'text-text-muted hover:bg-bg-elevated hover:text-text-primary'
            }`}
          >
            <Terminal size={14} />
            Docker & Shell CLI
          </button>

          <div className="mt-4 mb-2 px-2 text-xs font-semibold uppercase tracking-wider text-text-muted">
            CTI Workflows
          </div>
          <button
            onClick={() => setActiveSection('workflows')}
            className={`flex items-center gap-3 rounded-lg px-3 py-2 text-left text-xs font-medium transition-colors ${
              activeSection === 'workflows'
                ? 'bg-accent/10 text-[#00ff88]'
                : 'text-text-muted hover:bg-bg-elevated hover:text-text-primary'
            }`}
          >
            <Layers size={14} />
            Threat Operations
          </button>
          <button
            onClick={() => setActiveSection('honeypot-siem')}
            className={`flex items-center gap-3 rounded-lg px-3 py-2 text-left text-xs font-medium transition-colors ${
              activeSection === 'honeypot-siem'
                ? 'bg-accent/10 text-[#00ff88]'
                : 'text-text-muted hover:bg-bg-elevated hover:text-text-primary'
            }`}
          >
            <Radio size={14} />
            Honeypot & SIEM Ops
          </button>

          <div className="mt-4 mb-2 px-2 text-xs font-semibold uppercase tracking-wider text-text-muted">
            Interactive API Specs
          </div>
          {Object.keys(API_ENDPOINTS).map(category => (
            <button
              key={category}
              onClick={() => setActiveSection(`api-${category.toLowerCase()}`)}
              className={`flex items-center gap-3 rounded-lg px-3 py-2 text-left text-xs font-medium transition-colors ${
                activeSection === `api-${category.toLowerCase()}`
                  ? 'bg-accent/10 text-[#00ff88]'
                  : 'text-text-muted hover:bg-bg-elevated hover:text-text-primary'
              }`}
            >
              <Code size={14} />
              {category} API
            </button>
          ))}
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 min-w-0 bg-bg-surface border border-border rounded-xl p-6 lg:p-8">
        
        {/* Getting Started: Overview & Design */}
        {activeSection === 'getting-started' && (
          <section className="space-y-6">
            <div>
              <span className="text-xs font-semibold text-[#00ff88] uppercase tracking-wider font-mono">⬡ Platform Documentation</span>
              <h1 className="mt-1 text-2xl font-bold font-mono tracking-tight text-text-primary">Overview & Oracle Design</h1>
              <p className="mt-2 text-sm text-text-muted leading-relaxed">
                Named after the high priestess of Delphi who delivered Apollo's prophecies, <strong>Pythia</strong> ingests raw threat intelligence, normalizes it against industry frameworks, and delivers it through a clean REST API — including executive-ready PDF briefs a CFO can actually read.
              </p>
              <p className="mt-2 text-sm text-text-muted leading-relaxed">
                It ships <strong className="text-text-primary">fully loaded from the first clone</strong>: over 1,180 threat actor profiles, 759 MITRE ATT&CK techniques, 1,600+ known-exploited CVEs, and 16 curated Sigma detection rules (plus 14 Yara) — no scraping required, no account sign-ups, no SaaS subscriptions.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="rounded-lg border border-border bg-bg-base p-4">
                <div className="flex items-center gap-2 text-[#00ff88]">
                  <Shield size={16} />
                  <h3 className="text-sm font-semibold font-mono">STIX 2.1 Mappings</h3>
                </div>
                <p className="mt-2 text-xs text-text-muted leading-relaxed">
                  Adversaries, techniques, indicator nodes, and detection rules are stored using normalized STIX 2.1 schemas — including honeypot campaign IOC bundles exportable via TAXII.
                </p>
              </div>

              <div className="rounded-lg border border-border bg-bg-base p-4">
                <div className="flex items-center gap-2 text-[#00ff88]">
                  <Zap size={16} />
                  <h3 className="text-sm font-semibold font-mono">Claude AI Parser</h3>
                </div>
                <p className="mt-2 text-xs text-text-muted leading-relaxed">
                  Ingests raw URLs or copy-pasted IOC reports, performing automated extraction of malware techniques, impacts, and targeted countries. Also powers threat hunt AI suggestions and honeypot campaign report generation.
                </p>
              </div>

              <div className="rounded-lg border border-border bg-bg-base p-4">
                <div className="flex items-center gap-2 text-[#00ff88]">
                  <Server size={16} />
                  <h3 className="text-sm font-semibold font-mono">PDF Briefing Engine</h3>
                </div>
                <p className="mt-2 text-xs text-text-muted leading-relaxed">
                  Compiles data structures into elegant executive briefs and tactical forensics reports via Jinja2 & WeasyPrint. Honeypot campaign reports are also generated on demand.
                </p>
              </div>

              <div className="rounded-lg border border-border bg-bg-base p-4">
                <div className="flex items-center gap-2 text-[#00ff88]">
                  <Radio size={16} />
                  <h3 className="text-sm font-semibold font-mono">Honeypot Collection</h3>
                </div>
                <p className="mt-2 text-xs text-text-muted leading-relaxed">
                  Deploy a Cowrie SSH honeypot via Docker. Attacker events flow into Pythia in real time, enriched with GeoIP, ASN, AbuseIPDB, GreyNoise, and VirusTotal data, then clustered into named attack campaigns.
                </p>
              </div>

              <div className="rounded-lg border border-border bg-bg-base p-4">
                <div className="flex items-center gap-2 text-[#00ff88]">
                  <Activity size={16} />
                  <h3 className="text-sm font-semibold font-mono">SIEM Integration</h3>
                </div>
                <p className="mt-2 text-xs text-text-muted leading-relaxed">
                  Push Sigma detection rules to Wazuh, Splunk, or Elastic with one click. Receive alerts back via webhook and triage them in the Operations queue with automatic campaign correlation.
                </p>
              </div>

              <div className="rounded-lg border border-border bg-bg-base p-4">
                <div className="flex items-center gap-2 text-[#00ff88]">
                  <Layers size={16} />
                  <h3 className="text-sm font-semibold font-mono">Threat Hunt Workbench</h3>
                </div>
                <p className="mt-2 text-xs text-text-muted leading-relaxed">
                  AI-assisted hunt sessions with observation logging, Admiralty Code confidence scoring, Claude-powered actor attribution, and one-click promotion of drafted Sigma/YARA/KQL rules to the detection library.
                </p>
              </div>
            </div>

            <hr className="border-border" />

            <div className="space-y-4">
              <h2 className="text-lg font-bold font-mono text-text-primary">Bundled Intelligence</h2>
              <p className="text-sm text-text-muted">
                A fresh clone is immediately useful — no setup beyond configuration. All datasets are committed to the repo and seeded on first start (~60 seconds).
              </p>
              <div className="overflow-x-auto rounded-lg border border-border">
                <table className="w-full border-collapse text-left text-xs">
                  <thead className="bg-bg-elevated text-text-primary border-b border-border font-mono">
                    <tr>
                      <th className="p-3">Dataset</th>
                      <th className="p-3">Source</th>
                      <th className="p-3">Records</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border text-text-muted">
                    <tr>
                      <td className="p-3 font-semibold text-text-primary">Threat actor profiles</td>
                      <td className="p-3">MISP Galaxy + ATT&CK + APT Groups Sheet (merged)</td>
                      <td className="p-3 font-mono font-bold text-[#00ff88]">1,184</td>
                    </tr>
                    <tr>
                      <td className="p-3 font-semibold text-text-primary">ATT&CK techniques</td>
                      <td className="p-3">MITRE ATT&CK STIX 2.1 — Enterprise + Mobile + ICS</td>
                      <td className="p-3 font-mono font-bold text-[#00ff88]">759</td>
                    </tr>
                    <tr>
                      <td className="p-3 font-semibold text-text-primary">Known-exploited CVEs</td>
                      <td className="p-3">CISA KEV catalog</td>
                      <td className="p-3 font-mono font-bold text-[#00ff88]">1,602</td>
                    </tr>
                    <tr>
                      <td className="p-3 font-semibold text-text-primary">AI/ML adversarial techniques</td>
                      <td className="p-3">MITRE ATLAS</td>
                      <td className="p-3 font-mono font-bold text-[#00ff88]">full catalog</td>
                    </tr>
                    <tr>
                      <td className="p-3 font-semibold text-text-primary">Sigma detection rules</td>
                      <td className="p-3">Curated SigmaHQ subset</td>
                      <td className="p-3 font-mono font-bold text-[#00ff88]">16</td>
                    </tr>
                    <tr>
                      <td className="p-3 font-semibold text-text-primary">Yara detection rules</td>
                      <td className="p-3">Curated subset</td>
                      <td className="p-3 font-mono font-bold text-[#00ff88]">14</td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <p className="text-xs text-text-muted">
                Refresh from upstream any time: <code className="font-mono text-[#00ff88]">pythia sync</code> — or selectively: <code className="font-mono text-[#00ff88]">pythia sync attck misp-galaxy kev</code>
              </p>
            </div>
          </section>
        )}

        {/* Getting Started: Docker & Shell CLI */}
        {activeSection === 'docker-cli' && (
          <section className="space-y-6">
            <div>
              <span className="text-xs font-semibold text-[#00ff88] uppercase tracking-wider font-mono">⬡ Installation & Shells</span>
              <h1 className="mt-1 text-2xl font-bold font-mono tracking-tight text-text-primary">Docker & CLI Setup</h1>
              <p className="mt-2 text-sm text-text-muted leading-relaxed">
                Because generating PDF documents via CSS uses local rendering engines, it requires specific C-libraries. The **Docker Container** packages all required libraries natively, making it the bulletproof execution path.
              </p>
            </div>

            <div className="space-y-4">
              <h2 className="text-base font-bold font-mono text-[#00ff88]">1. Shell CLI Executions</h2>
              <p className="text-sm text-text-muted">
                You can run any Pythia command by passing it directly to the running container using `docker exec`:
              </p>
              <div className="relative group">
                <pre className="overflow-x-auto rounded-lg bg-bg-base border border-border p-4 text-xs font-mono text-[#00ff88]">
                  {`# List ingested threat records in your database
docker exec -it pythia pythia list threats

# Parse a threat URL using Claude
docker exec -it pythia pythia ingest "https://www.huntress.com/blog/the-gentlemen-ransomware-defense-evasion-ttps"

# Render a PDF report from any short-ID prefix
docker exec -it pythia pythia report "c881d693" --template executive --output data/gentlemen.pdf`}
                </pre>
                <button
                  onClick={() => handleCopy(`docker exec -it pythia pythia list threats`, 'docker-exec')}
                  className="absolute right-3 top-3 rounded border border-border bg-bg-elevated p-1.5 text-text-muted opacity-0 group-hover:opacity-100 hover:text-text-primary transition-opacity"
                >
                  {copiedId === 'docker-exec' ? <Check size={12} className="text-green-500" /> : <Copy size={12} />}
                </button>
              </div>
            </div>

            <div className="space-y-4">
              <h2 className="text-base font-bold font-mono text-[#00ff88] font-mono">2. Setup the Local Command Alias 🚀</h2>
              <p className="text-sm text-text-muted leading-relaxed">
                To run commands cleanly on your Mac as if it were a native application (e.g. typing just `pythia list threats`), you can set up a shell shortcut alias:
              </p>

              <div className="rounded-lg border border-border bg-bg-base p-4 space-y-3">
                <div>
                  <h4 className="text-xs font-semibold text-text-primary uppercase font-mono">For Zsh (macOS Default Shell)</h4>
                  <div className="mt-1 flex items-center justify-between rounded bg-bg-elevated px-3 py-2 border border-border">
                    <code className="text-xs font-mono text-text-primary">echo "alias pythia='docker exec -it pythia pythia'" &gt;&gt; ~/.zshrc && source ~/.zshrc</code>
                    <button
                      onClick={() => handleCopy(`echo "alias pythia='docker exec -it pythia pythia'" >> ~/.zshrc && source ~/.zshrc`, 'zsh-alias')}
                      className="text-text-muted hover:text-text-primary"
                    >
                      {copiedId === 'zsh-alias' ? <Check size={12} className="text-green-500" /> : <Copy size={12} />}
                    </button>
                  </div>
                </div>

                <div>
                  <h4 className="text-xs font-semibold text-text-primary uppercase font-mono">For Bash (Linux / Git Bash)</h4>
                  <div className="mt-1 flex items-center justify-between rounded bg-bg-elevated px-3 py-2 border border-border">
                    <code className="text-xs font-mono text-text-primary">echo "alias pythia='docker exec -it pythia pythia'" &gt;&gt; ~/.bashrc && source ~/.bashrc</code>
                    <button
                      onClick={() => handleCopy(`echo "alias pythia='docker exec -it pythia pythia'" >> ~/.bashrc && source ~/.bashrc`, 'bash-alias')}
                      className="text-text-muted hover:text-text-primary"
                    >
                      {copiedId === 'bash-alias' ? <Check size={12} className="text-green-500" /> : <Copy size={12} />}
                    </button>
                  </div>
                </div>
              </div>

              <p className="text-xs text-text-muted">
                *Note: All PDFs written by the `pythia report` command will be saved immediately to the `./data` directory in your cloned project root for easy host viewing.*
              </p>
            </div>
          </section>
        )}

        {/* CTI Workflows */}
        {activeSection === 'workflows' && (
          <section className="space-y-6">
            <div>
              <span className="text-xs font-semibold text-[#00ff88] uppercase tracking-wider font-mono">⬡ Threat Operations</span>
              <h1 className="mt-1 text-2xl font-bold font-mono tracking-tight text-text-primary">Common CTI Workflows</h1>
              <p className="mt-2 text-sm text-text-muted leading-relaxed">
                Pythia is optimized to support three distinct operations: translating technical telemetry for leadership, conducting rapid incident forensics, and cataloging target profiles.
              </p>
            </div>

            <div className="space-y-6 divide-y divide-border">
              {/* Workflow A */}
              <div className="pt-4 first:pt-0 space-y-3">
                <div className="flex items-center gap-3">
                  <span className="rounded bg-accent/20 px-2 py-1 font-mono text-xs font-bold text-[#00ff88]">Workflow A</span>
                  <h3 className="text-base font-bold font-mono text-text-primary">The C-Suite Executive Briefing</h3>
                </div>
                <p className="text-xs text-text-muted leading-relaxed">
                  <strong>Scenario:</strong> You discover a new threat report containing technical malware analysis. Your Board or CFO wants an immediate impact summary indicating financial exposure risks and required strategic decisions.
                </p>
                <div className="rounded bg-bg-base border border-border p-3 text-xs space-y-2 font-mono">
                  <div className="text-text-muted"># 1. Parse and extract threat structured CTI</div>
                  <div className="text-[#00ff88]">pythia ingest "https://www.huntress.com/blog/the-gentlemen-ransomware-defense-evasion-ttps"</div>
                  <div className="text-text-muted"># 2. Compile executive PDF report matching board concerns</div>
                  <div className="text-[#00ff88]">pythia report "c881d693" --template executive --output data/exec_brief.pdf</div>
                </div>
                <ul className="text-xs text-text-muted list-disc pl-5 space-y-1">
                  <li>Aggregates raw details into a simplified human-readable threat context narrative.</li>
                  <li>Highlights targeted industry sectors and maps threat actions onto a standard **Lockheed Martin Cyber Kill Chain** grid.</li>
                  <li>Outputs a critical **Business Impact Assessment** including financial exposure brackets, operational downtime projections, and recommended regulatory board actions.</li>
                </ul>
              </div>

              {/* Workflow B */}
              <div className="pt-6 space-y-3">
                <div className="flex items-center gap-3">
                  <span className="rounded bg-[#00ff88]/8 px-2 py-1 font-mono text-xs font-bold text-[#00ff88]/80">Workflow B</span>
                  <h3 className="text-base font-bold font-mono text-text-primary">Threat Hunting & Forensics (SecOps)</h3>
                </div>
                <p className="text-xs text-text-muted leading-relaxed">
                  <strong>Scenario:</strong> An active alert hits your network, resembling a known vulnerability exploit chain (e.g., ConnectWise ScreenConnect). You need to dump tactical IoCs, verify reliability, and extract ready-to-deploy detection rules.
                </p>
                <div className="rounded bg-bg-base border border-border p-3 text-xs space-y-2 font-mono">
                  <div className="text-text-muted"># 1. Parse the technical exploit writeup</div>
                  <div className="text-[#00ff88]">pythia ingest "https://www.huntress.com/blog/slashandgrab-the-connectwise-screenconnect-vulnerability-explained-2"</div>
                  <div className="text-text-muted"># 2. Render a comprehensive technical forensics report</div>
                  <div className="text-[#00ff88]">pythia report "4f7cbb25" --template tactical --output data/tactical_forensics.pdf</div>
                </div>
                <ul className="text-xs text-text-muted list-disc pl-5 space-y-1">
                  <li>Compiles detailed tables of **Indicators of Compromise** (hashes, IPs, URLs) sorted by the **Pyramid of Pain**.</li>
                  <li>Applies the **NATO Admiralty Code** to every IoC, classifying source reliability (A–F) and information credibility (1–6).</li>
                  <li>Stamps actionable, syntax-highlighted **Sigma and Yara rules** generated directly from Claude to immediately deploy in your SIEM or EDR system.</li>
                </ul>
              </div>

              {/* Workflow C */}
              <div className="pt-6 space-y-3">
                <div className="flex items-center gap-3">
                  <span className="rounded bg-purple-900/20 px-2 py-1 font-mono text-xs font-bold text-purple-400">Workflow C</span>
                  <h3 className="text-base font-bold font-mono text-text-primary">Adversary Profiling & Gap Analysis</h3>
                </div>
                <p className="text-xs text-text-muted leading-relaxed">
                  <strong>Scenario:</strong> Your threat research team is planning preemptive defenses for next quarter and wants to analyze the Diamond Model and historical TTPs of an active nation-state group (e.g., APT28).
                </p>
                <div className="rounded bg-bg-base border border-border p-3 text-xs space-y-2 font-mono">
                  <div className="text-text-muted"># 1. Check pre-seeded profile from the preloaded MISP database</div>
                  <div className="text-[#00ff88]">pythia list actors "APT28"</div>
                  <div className="text-text-muted"># 2. Fetch standard Diamond Model parameters from the API</div>
                  <div className="text-[#00ff88]">curl "http://localhost:8000/v1/actors/APT28/diamond"</div>
                </div>
                <ul className="text-xs text-text-muted list-disc pl-5 space-y-1">
                  <li>Reviews pre-seeded nation-state sponsor profiles, aliases, and targeted countries.</li>
                  <li>Builds visual Diamond Model shapes (Adversary → Infrastructure → Capability → Victim).</li>
                  <li>Organizes historical TTPs to easily identify log coverage gaps in security configurations.</li>
                </ul>
              </div>

              {/* Workflow D */}
              <div className="pt-6 space-y-3">
                <div className="flex items-center gap-3">
                  <span className="rounded bg-blue-900/20 px-2 py-1 font-mono text-xs font-bold text-blue-400">Workflow D</span>
                  <h3 className="text-base font-bold font-mono text-text-primary">AI-Assisted Threat Hunt Workbench</h3>
                </div>
                <p className="text-xs text-text-muted leading-relaxed">
                  <strong>Scenario:</strong> Your SOC has anomalous log activity suggesting a living-off-the-land attack. You want to run a structured hypothesis-driven hunt, log observations with confidence ratings, and draft SIEM-ready detections.
                </p>
                <div className="rounded bg-bg-base border border-border p-3 text-xs space-y-2 font-mono">
                  <div className="text-text-muted"># 1. Create a new hunt session via the API</div>
                  <div className="text-[#00ff88]">curl -X POST http://localhost:8000/v1/hunts -H "X-API-Key: $KEY" \</div>
                  <div className="text-[#00ff88] pl-4">-d '{"{"}\"name\":\"Unsigned DLL side-loading hunt\",\"hypothesis\":\"...\"{"}"}'</div>
                  <div className="text-text-muted"># 2. Log a TTP observation with NATO Admiralty confidence</div>
                  <div className="text-[#00ff88]">curl -X POST http://localhost:8000/v1/hunts/&lt;id&gt;/observations -H "X-API-Key: $KEY" \</div>
                  <div className="text-[#00ff88] pl-4">-d '{"{"}\"obs_type\":\"ttp\",\"value\":\"T1574.002\",\"confidence_source\":\"B\",\"confidence_info\":\"2\"{"}"}'</div>
                  <div className="text-text-muted"># 3. Run Claude AI actor attribution</div>
                  <div className="text-[#00ff88]">curl -X POST http://localhost:8000/v1/hunts/&lt;id&gt;/suggest-actors -H "X-API-Key: $KEY"</div>
                </div>
                <ul className="text-xs text-text-muted list-disc pl-5 space-y-1">
                  <li>Hunt sessions track hypothesis, scope, target sectors, and all analyst observations in one place.</li>
                  <li>Claude cross-references your observations against 1,180+ actor profiles for attribution suggestions.</li>
                  <li>Draft Sigma, YARA, or KQL rules from observations and promote them to the global detection library with one click.</li>
                </ul>
              </div>
            </div>
          </section>
        )}

        {/* Honeypot & SIEM Ops */}
        {activeSection === 'honeypot-siem' && (
          <section className="space-y-6">
            <div>
              <span className="text-xs font-semibold text-[#00ff88] uppercase tracking-wider font-mono">⬡ Live Collection & Response</span>
              <h1 className="mt-1 text-2xl font-bold font-mono tracking-tight text-text-primary">Honeypot Collection & SIEM Integration</h1>
              <p className="mt-2 text-sm text-text-muted leading-relaxed">
                Pythia can operate as an active collection platform, not just a passive intel store. Deploy a Cowrie SSH honeypot to capture real attacker behaviour, automatically enrich and cluster events into named campaigns, push detection rules to your SIEM, and triage incoming alerts — all from one interface.
              </p>
            </div>

            <div className="space-y-6 divide-y divide-border">
              {/* Workflow E */}
              <div className="pt-4 first:pt-0 space-y-3">
                <div className="flex items-center gap-3">
                  <span className="rounded bg-orange-900/20 px-2 py-1 font-mono text-xs font-bold text-orange-400">Workflow E</span>
                  <h3 className="text-base font-bold font-mono text-text-primary">Honeypot Deployment & Campaign Analysis</h3>
                </div>
                <p className="text-xs text-text-muted leading-relaxed">
                  <strong>Scenario:</strong> You want to capture real internet attack traffic, automatically enrich each attacker IP, cluster related events into campaigns, and produce CTI reports from first-party honeypot data.
                </p>

                <div className="rounded-lg border border-border bg-bg-base p-4 space-y-3">
                  <h4 className="text-xs font-semibold text-[#00ff88] font-mono uppercase">Architecture</h4>
                  <pre className="text-xs font-mono text-text-muted leading-relaxed whitespace-pre-wrap">{`Internet → Cowrie SSH Honeypot (VPS or localhost)
         │  cowrie.json log
         ▼
honeypot-forwarder (tails log, batches every 5s)
         │  POST /v1/honeypot/events/bulk
         ▼
Pythia (normalize → enrich → store)
         │
         ├── GeoIP + ASN (MaxMind)
         ├── AbuseIPDB score
         ├── GreyNoise classification
         └── VirusTotal detections
         │
Campaign clustering (every 15 min via scheduler)
         │
Auto-generated Sigma rules + CTI report`}</pre>
                </div>

                <div className="rounded bg-bg-base border border-border p-3 text-xs space-y-2 font-mono">
                  <div className="text-text-muted"># Start Pythia + Cowrie together</div>
                  <div className="text-[#00ff88]">docker compose -f docker-compose.yml -f docker-compose.honeypot.yml up -d</div>
                  <div className="text-text-muted"># Manually trigger campaign clustering (demo/testing)</div>
                  <div className="text-[#00ff88]">curl -X POST http://localhost:8000/v1/honeypot/detect-now -H "X-API-Key: $KEY"</div>
                  <div className="text-text-muted"># Generate a CTI report for a campaign</div>
                  <div className="text-[#00ff88]">curl -X POST http://localhost:8000/v1/honeypot/campaigns/&lt;id&gt;/generate-report -H "X-API-Key: $KEY"</div>
                  <div className="text-text-muted"># Pull the IP blocklist for your firewall</div>
                  <div className="text-[#00ff88]">curl http://localhost:8000/v1/honeypot/feeds/blocklist.txt</div>
                </div>
                <ul className="text-xs text-text-muted list-disc pl-5 space-y-1">
                  <li>Required config: set <code className="font-mono text-[#00ff88]">PYTHIA_HONEYPOT_INGEST_ENABLED=true</code> and <code className="font-mono text-[#00ff88]">PYTHIA_ENABLE_SCHEDULER=true</code> in <code className="font-mono">.env</code>.</li>
                  <li>For VPS deployment (real internet traffic), see <strong>docs/honeypot-siem-setup.md</strong> — includes Tailscale tunnel setup so your VPS can reach Pythia privately.</li>
                  <li>Export campaign IOCs as a STIX 2.1 bundle from <code className="font-mono text-[#00ff88]">/v1/honeypot/taxii/honeypot-iocs</code> for downstream TAXII clients.</li>
                  <li>The live feed in the <strong>Honeypot</strong> page updates via WebSocket (<code className="font-mono text-[#00ff88]">ws://localhost:8000/v1/honeypot/stream</code>) — no polling required.</li>
                </ul>
              </div>

              {/* Workflow F */}
              <div className="pt-6 space-y-3">
                <div className="flex items-center gap-3">
                  <span className="rounded bg-red-900/20 px-2 py-1 font-mono text-xs font-bold text-red-400">Workflow F</span>
                  <h3 className="text-base font-bold font-mono text-text-primary">SIEM Rule Deployment & Alert Triage</h3>
                </div>
                <p className="text-xs text-text-muted leading-relaxed">
                  <strong>Scenario:</strong> You have a Wazuh (or Splunk / Elastic) instance and want to push Pythia's Sigma detection rules to it, then receive and triage alerts back in Pythia — correlating fired alerts to known honeypot campaigns automatically.
                </p>

                <div className="rounded-lg border border-border bg-bg-base p-4 space-y-3">
                  <h4 className="text-xs font-semibold text-[#00ff88] font-mono uppercase">Supported SIEM Backends</h4>
                  <div className="overflow-x-auto rounded border border-border">
                    <table className="w-full text-xs text-left">
                      <thead className="bg-bg-elevated border-b border-border font-mono text-text-primary">
                        <tr>
                          <th className="p-2.5">PYTHIA_SIEM_TYPE</th>
                          <th className="p-2.5">Rule Format</th>
                          <th className="p-2.5">Alert Receiver</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border text-text-muted">
                        <tr>
                          <td className="p-2.5 font-mono text-[#00ff88]">wazuh</td>
                          <td className="p-2.5">Sigma → Wazuh XML rules</td>
                          <td className="p-2.5">Custom integration script (see setup guide)</td>
                        </tr>
                        <tr>
                          <td className="p-2.5 font-mono text-[#00ff88]">splunk</td>
                          <td className="p-2.5">Sigma → SPL saved searches</td>
                          <td className="p-2.5">Splunk alert webhook action</td>
                        </tr>
                        <tr>
                          <td className="p-2.5 font-mono text-[#00ff88]">elastic</td>
                          <td className="p-2.5">Sigma → EQL detection rules</td>
                          <td className="p-2.5">Elastic webhook connector</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>

                <div className="rounded bg-bg-base border border-border p-3 text-xs space-y-2 font-mono">
                  <div className="text-text-muted"># 1. Configure SIEM credentials in .env, then restart</div>
                  <div className="text-[#00ff88]">PYTHIA_SIEM_TYPE=wazuh</div>
                  <div className="text-[#00ff88]">PYTHIA_SIEM_URL=https://localhost:55000</div>
                  <div className="text-text-muted"># 2. Verify connection from the Operations page, or via API</div>
                  <div className="text-[#00ff88]">curl http://localhost:8000/v1/siem/status</div>
                  <div className="text-text-muted"># 3. Deploy all active Sigma rules</div>
                  <div className="text-[#00ff88]">curl -X POST http://localhost:8000/v1/siem/rules/deploy-all -H "X-API-Key: $KEY"</div>
                  <div className="text-text-muted"># 4. Triage an incoming alert</div>
                  <div className="text-[#00ff88]">curl -X PATCH http://localhost:8000/v1/siem/alerts/&lt;id&gt;/triage -H "X-API-Key: $KEY" \</div>
                  <div className="text-[#00ff88] pl-4">-d '{"{"}\"triage_status\":\"true_positive\",\"triaged_by\":\"analyst1\"{"}"}'</div>
                </div>
                <ul className="text-xs text-text-muted list-disc pl-5 space-y-1">
                  <li>Start Wazuh locally: <code className="font-mono text-[#00ff88]">docker compose -f docker-compose.siem.yml up -d</code> (requires ~4 GB RAM).</li>
                  <li>Wazuh must be configured to webhook back to <code className="font-mono text-[#00ff88]">POST /v1/siem/alerts</code> — see <strong>docs/honeypot-siem-setup.md</strong> for the integration script.</li>
                  <li>Incoming alerts are auto-correlated to a <strong>HoneypotCampaign</strong> if the attacker IP is in a known campaign — visible in the Operations page alert detail.</li>
                  <li>Watchlist webhooks (Slack/Discord) fire automatically when a campaign-correlated alert is received.</li>
                </ul>
              </div>
            </div>
          </section>
        )}

        {/* API Reference sections */}
        {activeSection.startsWith('api-') && (
          <section className="space-y-6">
            <div>
              <span className="text-xs font-semibold text-[#00ff88] uppercase tracking-wider font-mono">⬡ Interactive API Reference</span>
              <h1 className="mt-1 text-2xl font-bold font-mono tracking-tight text-text-primary">
                {activeSection.split('-')[1].toUpperCase()} API Endpoint Specifications
              </h1>
              <p className="mt-2 text-sm text-text-muted leading-relaxed">
                Browse detailed API request formats, query parameters, authorization states, and exact response models. Use the interactive schemas below to plan integrations.
              </p>
            </div>

            <div className="space-y-6">
              {API_ENDPOINTS[Object.keys(API_ENDPOINTS).find(k => k.toLowerCase() === activeSection.split('-')[1]) || '']?.map(endpoint => {
                const isExpanded = expandedEndpoints[endpoint.path] ?? true
                return (
                  <div key={endpoint.path} className="rounded-xl border border-border bg-bg-base overflow-hidden">
                    {/* Header */}
                    <div 
                      onClick={() => toggleEndpoint(endpoint.path)}
                      className="flex items-center gap-3 bg-bg-elevated px-4 py-3 border-b border-border cursor-pointer hover:bg-bg-elevated/80 transition-colors"
                    >
                      <span className={`rounded px-2.5 py-1 text-xs font-extrabold font-mono ${
                        endpoint.method === 'POST'
                          ? 'bg-green-500/10 text-green-400 border border-green-500/20'
                          : endpoint.method === 'DELETE'
                          ? 'bg-red-500/10 text-red-400 border border-red-500/20'
                          : endpoint.method === 'PATCH' || endpoint.method === 'PUT'
                          ? 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20'
                          : 'bg-[#00ff88]/10 text-[#00ff88] border border-[#00ff88]/20'
                      }`}>
                        {endpoint.method}
                      </span>
                      <span className="font-mono text-xs font-bold text-text-primary">{endpoint.path}</span>
                      <span className="text-xs text-text-muted ml-auto hidden sm:inline">{endpoint.title}</span>
                    </div>

                    {isExpanded && (
                      <div className="p-4 lg:p-6 space-y-6">
                        <div className="space-y-2">
                          <h4 className="text-xs font-semibold uppercase tracking-wider text-text-muted font-mono">Description</h4>
                          <p className="text-xs text-text-muted leading-relaxed">{endpoint.description}</p>
                        </div>

                        {/* Query Params */}
                        {endpoint.queryParams && endpoint.queryParams.length > 0 && (
                          <div className="space-y-2">
                            <h4 className="text-xs font-semibold uppercase tracking-wider text-text-muted font-mono font-mono">Query Parameters</h4>
                            <div className="overflow-x-auto rounded-lg border border-border">
                              <table className="w-full border-collapse text-left text-xs">
                                <thead className="bg-bg-elevated border-b border-border text-text-primary font-mono">
                                  <tr>
                                    <th className="p-2.5">Parameter</th>
                                    <th className="p-2.5">Type</th>
                                    <th className="p-2.5">Default</th>
                                    <th className="p-2.5">Description</th>
                                  </tr>
                                </thead>
                                <tbody className="divide-y divide-border text-text-muted">
                                  {endpoint.queryParams.map(param => (
                                    <tr key={param.name}>
                                      <td className="p-2.5 font-bold text-text-primary">
                                        {param.name} {param.required && <span className="text-red-500">*</span>}
                                      </td>
                                      <td className="p-2.5 font-mono text-[#00ff88]">{param.type}</td>
                                      <td className="p-2.5 font-mono">{param.default || '—'}</td>
                                      <td className="p-2.5">
                                        {param.description}
                                        {param.enum && (
                                          <div className="mt-1 text-[10px] text-[#00ff88] font-mono">
                                            Enum: {param.enum.join(' | ')}
                                          </div>
                                        )}
                                      </td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          </div>
                        )}

                        {/* Request Body */}
                        {endpoint.requestBody && (
                          <div className="space-y-2">
                            <h4 className="text-xs font-semibold uppercase tracking-wider text-text-muted font-mono">Request Body Schema</h4>
                            <div className="relative group">
                              <pre className="overflow-x-auto rounded-lg bg-bg-elevated border border-border p-4 text-xs font-mono text-text-primary">
                                {endpoint.requestBody}
                              </pre>
                            </div>
                          </div>
                        )}

                        {/* API Console Code Grid */}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div className="space-y-2 min-w-0">
                            <div className="flex items-center justify-between">
                              <h4 className="text-xs font-semibold uppercase tracking-wider text-text-muted font-mono">cURL Command</h4>
                              <button 
                                onClick={() => handleCopy(endpoint.curlExample, endpoint.path + '-curl')}
                                className="text-text-muted hover:text-text-primary transition-colors"
                              >
                                {copiedId === endpoint.path + '-curl' ? <Check size={12} className="text-green-500" /> : <Copy size={12} />}
                              </button>
                            </div>
                            <pre className="overflow-x-auto h-64 rounded-lg bg-bg-elevated border border-border p-4 text-xs font-mono text-[#00ff88] leading-relaxed">
                              {endpoint.curlExample}
                            </pre>
                          </div>

                          <div className="space-y-2 min-w-0">
                            <div className="flex items-center justify-between">
                              <h4 className="text-xs font-semibold uppercase tracking-wider text-text-muted font-mono">Response Schema (200 OK)</h4>
                              <button 
                                onClick={() => handleCopy(endpoint.responseSchema, endpoint.path + '-resp')}
                                className="text-text-muted hover:text-text-primary transition-colors"
                              >
                                {copiedId === endpoint.path + '-resp' ? <Check size={12} className="text-green-500" /> : <Copy size={12} />}
                              </button>
                            </div>
                            <pre className="overflow-x-auto h-64 rounded-lg bg-bg-elevated border border-border p-4 text-xs font-mono text-text-primary leading-relaxed">
                              {endpoint.responseSchema}
                            </pre>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          </section>
        )}
      </div>
    </div>
  )
}
