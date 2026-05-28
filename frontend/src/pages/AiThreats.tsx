import { useState } from 'react'
import { AlertTriangle, Brain, ChevronDown, ChevronRight, Shield } from 'lucide-react'
import { useOWASPItems, useAIIncidents, useAtlasTechniques, useAIThreatsOverview } from '@/api/ai-threats'
import { PageHeader } from '@/components/shared/PageHeader'

function owaspSeverityBadge(rank: number) {
  if (rank <= 5) {
    return <span className="rounded bg-red-900/60 px-1.5 py-0.5 text-[10px] font-bold uppercase text-red-300">HIGH</span>
  }
  return <span className="rounded bg-amber-900/60 px-1.5 py-0.5 text-[10px] font-bold uppercase text-amber-300">MEDIUM</span>
}

export function AiThreats() {
  const { data: overview } = useAIThreatsOverview()
  const { data: owasp } = useOWASPItems()
  const { data: incidents } = useAIIncidents()
  const { data: atlas } = useAtlasTechniques()
  const [expandedOwasps, setExpandedOwasps] = useState<string[]>([])
  const [showAtlas, setShowAtlas] = useState(false)
  const [filterTag, setFilterTag] = useState<string | null>(null)
  const [incidentSearch, setIncidentSearch] = useState('')
  const [incidentYear, setIncidentYear] = useState('')

  const toggleExpanded = (id: string) => {
    setExpandedOwasps(prev =>
      prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id],
    )
  }

  const incidentYears = Array.from(
    new Set(
      (incidents ?? [])
        .filter(i => i.date)
        .map(i => i.date!.slice(0, 4)),
    ),
  ).sort((a, b) => b.localeCompare(a))

  const filteredIncidents = (incidents ?? []).filter(i => {
    if (filterTag && !i.owasp_ids.includes(filterTag) && !i.atlas_ids.includes(filterTag)) return false
    if (incidentYear && !i.date?.startsWith(incidentYear)) return false
    if (incidentSearch && !i.title.toLowerCase().includes(incidentSearch.toLowerCase())) return false
    return true
  })

  const statCards = [
    {
      label: 'MITRE ATLAS Techniques',
      value: overview?.atlas_count ?? (atlas?.length ?? '—'),
      icon: Brain,
      color: 'text-cyan-400',
    },
    {
      label: 'OWASP LLM Categories',
      value: overview?.owasp_count ?? (owasp?.length ?? '—'),
      icon: Shield,
      color: 'text-amber-400',
    },
    {
      label: 'Real-world Incidents',
      value: overview?.incident_count ?? (incidents?.length ?? '—'),
      icon: AlertTriangle,
      color: 'text-red-400',
    },
  ]

  return (
    <div className="space-y-10">
      <PageHeader
        title="AI Threats"
        description="MITRE ATLAS adversarial ML techniques, OWASP LLM Top 10, and real-world AI security incidents."
      />

      {/* Overview */}
      <div className="grid grid-cols-3 gap-4">
        {statCards.map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="rounded-xl border border-[#2a2a3e] bg-bg-surface p-5">
            <div className="flex items-center gap-3">
              <div className="rounded-lg bg-bg-elevated p-2">
                <Icon size={16} className={color} />
              </div>
              <p className={`text-2xl font-bold tabular-nums ${color}`}>{value}</p>
            </div>
            <p className="mt-2 text-xs text-text-muted">{label}</p>
          </div>
        ))}
      </div>

      {/* OWASP LLM Top 10 */}
      <section>
        <h2 className="mb-4 text-sm font-semibold text-text-primary">OWASP LLM Top 10</h2>
        {owasp && owasp.length > 0 ? (
          <div className="grid gap-4 items-start sm:grid-cols-2">
            {owasp.map(item => (
              <div
                key={item.id}
                className="overflow-hidden rounded-xl border border-[#2a2a3e] bg-bg-surface"
              >
                <button
                  onClick={() => toggleExpanded(item.id)}
                  className="w-full p-4 text-left transition-colors hover:bg-bg-elevated"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs text-accent-bright">{item.id}</span>
                      {owaspSeverityBadge(item.rank)}
                    </div>
                    {expandedOwasps.includes(item.id)
                      ? <ChevronDown size={14} className="mt-0.5 shrink-0 text-text-muted" />
                      : <ChevronRight size={14} className="mt-0.5 shrink-0 text-text-muted" />}
                  </div>
                  <p className="mt-1.5 text-sm font-medium text-text-primary">{item.name}</p>
                  <div className="mt-2 flex flex-wrap gap-1">
                    {item.atlas_ids.map(a => (
                      <span key={a} className="rounded bg-cyan-900 px-1.5 py-0.5 text-xs font-mono text-cyan-300">{a}</span>
                    ))}
                    {item.cwe_ids.map(c => (
                      <span key={c} className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs font-mono text-zinc-300">{c}</span>
                    ))}
                  </div>
                </button>
                {expandedOwasps.includes(item.id) && (
                  <div className="space-y-3 border-t border-[#2a2a3e] p-4">
                    {item.description && (
                      <p className="text-xs leading-relaxed text-text-primary">{item.description}</p>
                    )}
                    {item.mitigations.length > 0 && (
                      <div>
                        <p className="mb-1 text-xs font-medium text-text-muted">Mitigations</p>
                        <ul className="space-y-1">
                          {item.mitigations.map((m, i) => (
                            <li key={i} className="text-xs text-text-primary">• {m}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {item.detection_notes && (
                      <div>
                        <p className="mb-1 text-xs font-medium text-text-muted">Detection</p>
                        <p className="text-xs text-text-primary">{item.detection_notes}</p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-text-muted">No OWASP LLM data loaded.</p>
        )}
      </section>

      {/* Incidents timeline */}
      <section>
        <div className="mb-4 flex flex-wrap items-center gap-3">
          <h2 className="text-sm font-semibold text-text-primary">Real-world AI Incidents</h2>
          <div className="ml-auto flex flex-wrap items-center gap-2">
            <input
              value={incidentSearch}
              onChange={e => setIncidentSearch(e.target.value)}
              placeholder="Search incidents..."
              className="rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-1.5 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
            />
            {incidentYears.length > 0 && (
              <select
                value={incidentYear}
                onChange={e => setIncidentYear(e.target.value)}
                className="rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-1.5 text-xs text-text-primary focus:outline-none"
              >
                <option value="">All years</option>
                {incidentYears.map(y => <option key={y} value={y}>{y}</option>)}
              </select>
            )}
            {filterTag && (
              <button
                onClick={() => setFilterTag(null)}
                className="rounded bg-accent px-2 py-0.5 text-xs text-white"
              >
                {filterTag} ✕
              </button>
            )}
          </div>
        </div>
        {incidents && incidents.length > 0 ? (
          filteredIncidents.length === 0 ? (
            <p className="text-xs text-text-muted">No incidents match the current filters.</p>
          ) : (
            <div className="relative ml-4 space-y-6 border-l border-[#2a2a3e] pl-6">
              {filteredIncidents.map(incident => (
                <div key={incident.id} className="relative">
                  <div className="absolute -left-8 top-1 h-3 w-3 rounded-full border-2 border-accent-bright bg-bg-base" />
                  <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface p-4">
                    <div className="mb-2 flex flex-wrap items-center gap-2">
                      {incident.date && (
                        <span className="font-mono text-xs text-text-muted">{incident.date.slice(0, 7)}</span>
                      )}
                      <h3 className="text-sm font-medium text-text-primary">{incident.title}</h3>
                    </div>
                    <div className="mb-2 flex flex-wrap gap-1">
                      {incident.owasp_ids.map(id => (
                        <button
                          key={id}
                          onClick={() => setFilterTag(id === filterTag ? null : id)}
                          className="rounded bg-amber-900 px-1.5 py-0.5 text-xs font-mono text-amber-300 hover:opacity-80"
                        >
                          {id}
                        </button>
                      ))}
                      {incident.atlas_ids.map(id => (
                        <button
                          key={id}
                          onClick={() => setFilterTag(id === filterTag ? null : id)}
                          className="rounded bg-cyan-900 px-1.5 py-0.5 text-xs font-mono text-cyan-300 hover:opacity-80"
                        >
                          {id}
                        </button>
                      ))}
                    </div>
                    {incident.description && (
                      <p className="text-xs leading-relaxed text-text-primary">{incident.description}</p>
                    )}
                    {incident.source_url && (
                      <a
                        href={incident.source_url}
                        target="_blank"
                        rel="noreferrer"
                        className="mt-2 inline-block text-xs text-accent-bright hover:underline"
                      >
                        Source ↗
                      </a>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )
        ) : (
          <p className="text-xs text-text-muted">No incidents loaded.</p>
        )}
      </section>

      {/* ATLAS techniques (collapsible) */}
      <section>
        <button
          onClick={() => setShowAtlas(s => !s)}
          className="flex items-center gap-2 rounded-lg border border-[#2a2a3e] bg-bg-surface px-4 py-2.5 text-sm font-medium text-text-primary transition-colors hover:bg-bg-elevated"
        >
          {showAtlas ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
          ATLAS Techniques
          <span className="ml-1 inline-flex h-5 min-w-[1.25rem] items-center justify-center rounded-full bg-cyan-900/60 px-1.5 text-xs font-bold text-cyan-300">
            {atlas?.length ?? 0}
          </span>
        </button>
        {showAtlas && atlas && (
          <div className="mt-4 overflow-x-auto rounded-xl border border-[#2a2a3e] bg-bg-surface">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-[#2a2a3e]">
                  {['ID', 'Name', 'Tactics', 'Subtechniques'].map(h => (
                    <th key={h} className="px-3 py-2 text-left font-medium text-text-muted">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {atlas.map(t => (
                  <tr key={t.technique_id} className="border-b border-[#2a2a3e] hover:bg-bg-elevated transition-colors">
                    <td className="px-3 py-2 font-mono text-cyan-300">{t.technique_id}</td>
                    <td className="px-3 py-2 text-text-primary">{t.name}</td>
                    <td className="px-3 py-2 text-text-muted">{t.tactics.join(', ')}</td>
                    <td className="px-3 py-2 text-text-muted">{t.subtechniques.length}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}
