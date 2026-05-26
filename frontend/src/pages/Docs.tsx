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
  Server
} from 'lucide-react'

// API Endpoints definition schema for the interactive API documentation
interface ApiEndpoint {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE'
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
                ? 'bg-accent/10 text-accent-bright'
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
                ? 'bg-accent/10 text-accent-bright'
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
                ? 'bg-accent/10 text-accent-bright'
                : 'text-text-muted hover:bg-bg-elevated hover:text-text-primary'
            }`}
          >
            <Layers size={14} />
            Threat Operations
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
                  ? 'bg-accent/10 text-accent-bright'
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
              <span className="text-xs font-semibold text-accent-bright uppercase tracking-wider font-mono">⬡ Platform Documentation</span>
              <h1 className="mt-1 text-2xl font-bold font-mono tracking-tight text-text-primary">Overview & Oracle Design</h1>
              <p className="mt-2 text-sm text-text-muted leading-relaxed">
                Named after the high priestess of Delphi who delivered Apollo's prophecies, <strong>Pythia</strong> is an oracle-grade cyber threat intelligence (CTI) platform. It ingests unorganized, public security blog posts, parses and models them using Claude AI, and serves them natively as structured STIX 2.1 profiles, Sigma rules, and executive-ready A4 PDF intelligence briefs.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="rounded-lg border border-border bg-bg-base p-4">
                <div className="flex items-center gap-2 text-accent-bright">
                  <Shield size={16} />
                  <h3 className="text-sm font-semibold font-mono">STIX 2.1 Mappings</h3>
                </div>
                <p className="mt-2 text-xs text-text-muted leading-relaxed">
                  Adversaries, techniques, indicator nodes, and active detection rules are stored and queried using normalized STIX relationship schemas.
                </p>
              </div>

              <div className="rounded-lg border border-border bg-bg-base p-4">
                <div className="flex items-center gap-2 text-accent-bright">
                  <Zap size={16} />
                  <h3 className="text-sm font-semibold font-mono">Claude AI Parser</h3>
                </div>
                <p className="mt-2 text-xs text-text-muted leading-relaxed">
                  Ingests raw URLs or copy-pasted IOC reports, performing automated extraction of malware techniques, impacts, and targeted countries.
                </p>
              </div>

              <div className="rounded-lg border border-border bg-bg-base p-4">
                <div className="flex items-center gap-2 text-accent-bright">
                  <Server size={16} />
                  <h3 className="text-sm font-semibold font-mono">PDF Briefing engine</h3>
                </div>
                <p className="mt-2 text-xs text-text-muted leading-relaxed">
                  Compiles data structures into elegant executive briefs using custom A4 print-ready CSS templates powered by Jinja2 & WeasyPrint.
                </p>
              </div>
            </div>

            <hr className="border-border" />

            <div className="space-y-4">
              <h2 className="text-lg font-bold font-mono text-text-primary">Seeded CTI Database</h2>
              <p className="text-sm text-text-muted">
                To guarantee zero cold-start latency, a fresh Pythia database comes pre-populated with high-fidelity, open-source intelligence feeds merged from international cybersecurity standards:
              </p>
              <div className="overflow-x-auto rounded-lg border border-border">
                <table className="w-full border-collapse text-left text-xs">
                  <thead className="bg-bg-elevated text-text-primary border-b border-border font-mono">
                    <tr>
                      <th className="p-3">Feeds</th>
                      <th className="p-3">Source Provider</th>
                      <th className="p-3">Purpose / Usage</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border text-text-muted">
                    <tr>
                      <td className="p-3 font-semibold text-text-primary">MITRE ATT&CK</td>
                      <td className="p-3">STIX 2.1 Bundle (Enterprise + ICS)</td>
                      <td className="p-3">Fuzzy technique definitions & TTP mappings</td>
                    </tr>
                    <tr>
                      <td className="p-3 font-semibold text-text-primary">MISP Galaxy</td>
                      <td className="p-3">MISP Threat Actor Clusters</td>
                      <td className="p-3">Merged metadata profiles for 1,067 threat groups</td>
                    </tr>
                    <tr>
                      <td className="p-3 font-semibold text-text-primary">CISA KEV</td>
                      <td className="p-3">CISA Known Exploited Vulnerabilities</td>
                      <td className="p-3">Correlation engine checking if threat targets critical CVEs</td>
                    </tr>
                    <tr>
                      <td className="p-3 font-semibold text-text-primary">MITRE ATLAS</td>
                      <td className="p-3">Adversarial Threat Landscape (AI)</td>
                      <td className="p-3">Categorizing attacks targeted at AI/ML models</td>
                    </tr>
                    <tr>
                      <td className="p-3 font-semibold text-text-primary">SigmaHQ Subset</td>
                      <td className="p-3">Curated detection signatures</td>
                      <td className="p-3">Pre-mapped detection rules matching parsed techniques</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </section>
        )}

        {/* Getting Started: Docker & Shell CLI */}
        {activeSection === 'docker-cli' && (
          <section className="space-y-6">
            <div>
              <span className="text-xs font-semibold text-accent-bright uppercase tracking-wider font-mono">⬡ Installation & Shells</span>
              <h1 className="mt-1 text-2xl font-bold font-mono tracking-tight text-text-primary">Docker & CLI Setup</h1>
              <p className="mt-2 text-sm text-text-muted leading-relaxed">
                Because generating PDF documents via CSS uses local rendering engines, it requires specific C-libraries. The **Docker Container** packages all required libraries natively, making it the bulletproof execution path.
              </p>
            </div>

            <div className="space-y-4">
              <h2 className="text-base font-bold font-mono text-accent-bright">1. Shell CLI Executions</h2>
              <p className="text-sm text-text-muted">
                You can run any Pythia command by passing it directly to the running container using `docker exec`:
              </p>
              <div className="relative group">
                <pre className="overflow-x-auto rounded-lg bg-bg-base border border-border p-4 text-xs font-mono text-accent-bright">
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
              <h2 className="text-base font-bold font-mono text-accent-bright font-mono">2. Setup the Local Command Alias 🚀</h2>
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
              <span className="text-xs font-semibold text-accent-bright uppercase tracking-wider font-mono">⬡ Threat Operations</span>
              <h1 className="mt-1 text-2xl font-bold font-mono tracking-tight text-text-primary">Common CTI Workflows</h1>
              <p className="mt-2 text-sm text-text-muted leading-relaxed">
                Pythia is optimized to support three distinct operations: translating technical telemetry for leadership, conducting rapid incident forensics, and cataloging target profiles.
              </p>
            </div>

            <div className="space-y-6 divide-y divide-border">
              {/* Workflow A */}
              <div className="pt-4 first:pt-0 space-y-3">
                <div className="flex items-center gap-3">
                  <span className="rounded bg-accent/20 px-2 py-1 font-mono text-xs font-bold text-accent-bright">Workflow A</span>
                  <h3 className="text-base font-bold font-mono text-text-primary">The C-Suite Executive Briefing</h3>
                </div>
                <p className="text-xs text-text-muted leading-relaxed">
                  <strong>Scenario:</strong> You discover a new threat report containing technical malware analysis. Your Board or CFO wants an immediate impact summary indicating financial exposure risks and required strategic decisions.
                </p>
                <div className="rounded bg-bg-base border border-border p-3 text-xs space-y-2 font-mono">
                  <div className="text-text-muted"># 1. Parse and extract threat structured CTI</div>
                  <div className="text-accent-bright">pythia ingest "https://www.huntress.com/blog/the-gentlemen-ransomware-defense-evasion-ttps"</div>
                  <div className="text-text-muted"># 2. Compile executive PDF report matching board concerns</div>
                  <div className="text-accent-bright">pythia report "c881d693" --template executive --output data/exec_brief.pdf</div>
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
                  <span className="rounded bg-cyan-900/20 px-2 py-1 font-mono text-xs font-bold text-cyan-400">Workflow B</span>
                  <h3 className="text-base font-bold font-mono text-text-primary">Threat Hunting & Forensics (SecOps)</h3>
                </div>
                <p className="text-xs text-text-muted leading-relaxed">
                  <strong>Scenario:</strong> An active alert hits your network, resembling a known vulnerability exploit chain (e.g., ConnectWise ScreenConnect). You need to dump tactical IoCs, verify reliability, and extract ready-to-deploy detection rules.
                </p>
                <div className="rounded bg-bg-base border border-border p-3 text-xs space-y-2 font-mono">
                  <div className="text-text-muted"># 1. Parse the technical exploit writeup</div>
                  <div className="text-accent-bright">pythia ingest "https://www.huntress.com/blog/slashandgrab-the-connectwise-screenconnect-vulnerability-explained-2"</div>
                  <div className="text-text-muted"># 2. Render a comprehensive technical forensics report</div>
                  <div className="text-accent-bright">pythia report "4f7cbb25" --template tactical --output data/tactical_forensics.pdf</div>
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
                  <div className="text-accent-bright">pythia list actors "APT28"</div>
                  <div className="text-text-muted"># 2. Fetch standard Diamond Model parameters from the API</div>
                  <div className="text-accent-bright">curl "http://localhost:8000/v1/actors/APT28/diamond"</div>
                </div>
                <ul className="text-xs text-text-muted list-disc pl-5 space-y-1">
                  <li>Reviews pre-seeded nation-state sponsor profiles, aliases, and targeted countries.</li>
                  <li>Builds visual Diamond Model shapes (Adversary ➡️ Infrastructure ➡️ Capability ➡️ Victim).</li>
                  <li>Organizes historical TTPs to easily identify log coverage gaps in security configurations.</li>
                </ul>
              </div>
            </div>
          </section>
        )}

        {/* API Reference sections */}
        {activeSection.startsWith('api-') && (
          <section className="space-y-6">
            <div>
              <span className="text-xs font-semibold text-accent-bright uppercase tracking-wider font-mono">⬡ Interactive API Reference</span>
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
                          : 'bg-accent-bright/10 text-accent-bright border border-accent-bright/20'
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
                                      <td className="p-2.5 font-mono text-accent-bright">{param.type}</td>
                                      <td className="p-2.5 font-mono">{param.default || '—'}</td>
                                      <td className="p-2.5">
                                        {param.description}
                                        {param.enum && (
                                          <div className="mt-1 text-[10px] text-accent-bright font-mono">
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
                            <pre className="overflow-x-auto h-64 rounded-lg bg-bg-elevated border border-border p-4 text-xs font-mono text-accent-bright leading-relaxed">
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
