import { useState } from 'react'
import { useOWASPItems, useAIIncidents, useAtlasTechniques, useAIThreatsOverview } from '@/api/ai-threats'

export function AiThreats() {
  const { data: overview } = useAIThreatsOverview()
  const { data: owasp } = useOWASPItems()
  const { data: incidents } = useAIIncidents()
  const { data: atlas } = useAtlasTechniques()
  const [expandedOwasps, setExpandedOwasps] = useState<string[]>([])
  const [showAtlas, setShowAtlas] = useState(false)
  const [filterTag, setFilterTag] = useState<string | null>(null)

  const toggleExpanded = (id: string) => {
    setExpandedOwasps(prev =>
      prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]
    )
  }

  return (
    <div className="space-y-10">
      <h1 className="text-lg font-semibold text-text-primary">AI Threats</h1>

      {/* Overview banner */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: 'MITRE ATLAS Techniques', value: overview?.atlas_count ?? (atlas?.length ?? '—') },
          { label: 'OWASP LLM Categories', value: overview?.owasp_count ?? (owasp?.length ?? '—') },
          { label: 'Real-world Incidents', value: overview?.incident_count ?? (incidents?.length ?? '—') },
        ].map(({ label, value }) => (
          <div key={label} className="rounded-xl border border-[#2a2a3e] bg-bg-surface p-5 text-center">
            <p className="text-2xl font-semibold text-accent-bright">{value}</p>
            <p className="mt-1 text-xs text-text-muted">{label}</p>
          </div>
        ))}
      </div>

      {/* OWASP LLM Top 10 */}
      <section>
        <h2 className="mb-4 text-sm font-semibold text-text-primary">OWASP LLM Top 10</h2>
        {owasp && owasp.length > 0 ? (
          <div className="grid gap-4 sm:grid-cols-2 items-start">
            {owasp.map(item => (
              <div
                key={item.id}
                className="rounded-xl border border-[#2a2a3e] bg-bg-surface overflow-hidden"
              >
                <button
                  onClick={() => toggleExpanded(item.id)}
                  className="w-full p-4 text-left hover:bg-bg-elevated transition-colors"
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <span className="font-mono text-xs text-accent-bright">{item.id}</span>
                      <p className="mt-1 text-sm font-medium text-text-primary">{item.name}</p>
                    </div>
                    <span className="text-text-muted">{expandedOwasps.includes(item.id) ? '▲' : '▼'}</span>
                  </div>
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
                  <div className="border-t border-[#2a2a3e] p-4 space-y-3">
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
          {filterTag && (
            <button
              onClick={() => setFilterTag(null)}
              className="rounded bg-accent px-2 py-0.5 text-xs text-white"
            >
              {filterTag} ✕
            </button>
          )}
        </div>
        {incidents && incidents.length > 0 ? (
          <div className="relative ml-4 border-l border-[#2a2a3e] pl-6 space-y-6">
            {incidents
              .filter(i =>
                !filterTag ||
                i.owasp_ids.includes(filterTag) ||
                i.atlas_ids.includes(filterTag),
              )
              .map(incident => (
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
                          onClick={() => setFilterTag(id)}
                          className="rounded bg-amber-900 px-1.5 py-0.5 text-xs font-mono text-amber-300 hover:opacity-80"
                        >
                          {id}
                        </button>
                      ))}
                      {incident.atlas_ids.map(id => (
                        <button
                          key={id}
                          onClick={() => setFilterTag(id)}
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
        ) : (
          <p className="text-xs text-text-muted">No incidents loaded.</p>
        )}
      </section>

      {/* ATLAS techniques (collapsible) */}
      <section>
        <button
          onClick={() => setShowAtlas(s => !s)}
          className="text-sm text-text-muted hover:text-text-primary transition-colors"
        >
          {showAtlas ? '▼' : '▶'} {atlas?.length ?? 0} ATLAS Techniques
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
                  <tr key={t.technique_id} className="border-b border-[#2a2a3e]">
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
