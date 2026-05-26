import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { useActor, useActorKillChain, useActorDiamond, useActorStix } from '@/api/actors'
import { TechniqueTag } from '@/components/shared/TechniqueTag'
import { CodeBlock } from '@/components/shared/CodeBlock'
import { Breadcrumb } from '@/components/layout/Breadcrumb'
import { cn } from '@/lib/utils'
import { SPONSOR_COLORS, KILL_CHAIN_PHASES } from '@/lib/constants'

type Tab = 'overview' | 'killchain' | 'diamond' | 'ttps' | 'stix'

export function ActorDetail() {
  const { id } = useParams<{ id: string }>()
  const [tab, setTab] = useState<Tab>('overview')
  const [stixEnabled, setStixEnabled] = useState(false)

  const { data: actor, isLoading } = useActor(id ?? '')
  const { data: killchain } = useActorKillChain(id ?? '')
  const { data: diamond } = useActorDiamond(id ?? '')
  const { data: stix } = useActorStix(id ?? '', stixEnabled)

  if (isLoading) return <div className="py-16 text-center text-sm text-text-muted">Loading…</div>
  if (!actor) return <div className="py-16 text-center text-sm text-red-400">Actor not found.</div>

  const TABS: { key: Tab; label: string }[] = [
    { key: 'overview', label: 'Overview' },
    { key: 'killchain', label: 'Kill Chain' },
    { key: 'diamond', label: 'Diamond Model' },
    { key: 'ttps', label: `TTPs (${actor.ttps.length})` },
    { key: 'stix', label: 'STIX' },
  ]

  return (
    <div>
      <Breadcrumb crumbs={[{ label: 'Actors', to: '/actors' }, { label: actor.name }]} />

      <div className="grid gap-6 lg:grid-cols-[240px_1fr]">
        {/* Profile card */}
        <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface p-5">
          <div className="mb-3 text-xs text-text-muted">{actor.country_code ?? 'Unknown origin'}</div>
          <h1 className="mb-2 text-lg font-semibold text-text-primary">{actor.name}</h1>
          <span
            className={cn(
              'inline-flex rounded px-2 py-0.5 text-xs font-medium',
              SPONSOR_COLORS[actor.sponsor_type] ?? 'bg-zinc-800 text-zinc-300',
            )}
          >
            {actor.sponsor_type}
          </span>
          {actor.sophistication && (
            <div className="mt-4">
              <p className="mb-1 text-xs text-text-muted">Sophistication</p>
              <span className="flex gap-0.5 text-base">
                {[1, 2, 3, 4, 5].map(n => (
                  <span
                    key={n}
                    className={n <= actor.sophistication! ? 'text-accent-bright' : 'text-[#2a2a3e]'}
                  >
                    ●
                  </span>
                ))}
              </span>
            </div>
          )}
          <div className="mt-4 flex flex-col gap-2">
            <button
              onClick={() => {
                setStixEnabled(true)
                setTab('stix')
              }}
              className="rounded-lg border border-[#2a2a3e] py-1.5 text-xs text-text-muted hover:text-text-primary transition-colors"
            >
              View STIX Export
            </button>
          </div>
        </div>

        {/* Right column */}
        <div>
          <div className="mb-4 flex border-b border-[#2a2a3e]">
            {TABS.map(t => (
              <button
                key={t.key}
                onClick={() => {
                  if (t.key === 'stix') setStixEnabled(true)
                  setTab(t.key)
                }}
                className={`px-4 py-2 text-xs font-medium transition-colors ${
                  tab === t.key
                    ? 'border-b-2 border-accent-bright text-text-primary -mb-px'
                    : 'text-text-muted hover:text-text-primary'
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>

          <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface p-6">
            {tab === 'overview' && (
              <div className="space-y-4 text-sm">
                {actor.description && <p className="leading-relaxed text-text-primary">{actor.description}</p>}
                {actor.aliases.length > 0 && (
                  <div>
                    <p className="mb-2 text-xs font-medium text-text-muted">Also known as</p>
                    <div className="flex flex-wrap gap-1">
                      {actor.aliases.map(a => (
                        <span key={a} className="rounded bg-bg-elevated px-2 py-0.5 text-xs text-text-primary">
                          {a}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {actor.first_observed && (
                  <p className="text-xs text-text-muted">First observed: {actor.first_observed}</p>
                )}
                {actor.sectors_targeted.length > 0 && (
                  <div>
                    <p className="mb-2 text-xs font-medium text-text-muted">Sectors targeted</p>
                    <div className="flex flex-wrap gap-1">
                      {actor.sectors_targeted.map(s => (
                        <span key={s} className="rounded bg-bg-elevated px-2 py-0.5 text-xs text-text-primary">
                          {s}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {tab === 'killchain' && killchain && (
              <div className="overflow-x-auto">
                <div className="flex min-w-max gap-2">
                  {KILL_CHAIN_PHASES.map(({ key, label }) => {
                    const phaseItems = killchain.phases[key] ?? []
                    return (
                      <div key={key} className="w-32 shrink-0">
                        <div className="mb-2 rounded bg-bg-elevated px-2 py-1 text-center text-xs font-medium text-text-muted">
                          {label}
                        </div>
                        <div className="space-y-1">
                          {phaseItems.length === 0 ? (
                            <div className="rounded border border-[#2a2a3e] border-dashed p-2 text-center text-xs text-[#2a2a3e]">
                              —
                            </div>
                          ) : (
                            phaseItems.map(t => (
                              <div key={t.technique_id} className="flex justify-center">
                                <TechniqueTag id={t.technique_id} />
                              </div>
                            ))
                          )}
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            )}

            {tab === 'diamond' && diamond && (
              <div className="grid grid-cols-2 gap-4">
                {[
                  {
                    label: 'Adversary',
                    content: [
                      `Name: ${diamond.adversary.name}`,
                      diamond.adversary.country && `Country: ${diamond.adversary.country}`,
                      `Sponsor: ${diamond.adversary.sponsor_type}`,
                    ].filter(Boolean),
                  },
                  {
                    label: 'Capability',
                    content: [
                      `${diamond.capability.technique_count} techniques`,
                      ...diamond.capability.sample_techniques.slice(0, 5),
                    ],
                  },
                  {
                    label: 'Infrastructure',
                    content: [
                      diamond.infrastructure.patterns ?? 'No patterns noted',
                    ],
                  },
                  {
                    label: 'Victim',
                    content: [
                      ...diamond.victim.sectors.map(s => `Sector: ${s}`),
                      ...diamond.victim.geographies.map(g => `Geo: ${g}`),
                    ],
                  },
                ].map(({ label, content }) => (
                  <div key={label} className="rounded-lg border border-[#2a2a3e] p-4">
                    <h3 className="mb-2 text-xs font-semibold text-accent-bright">{label}</h3>
                    <ul className="space-y-1">
                      {(content as string[]).filter(Boolean).map((line, i) => (
                        <li key={i} className="text-xs text-text-primary">{line}</li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            )}

            {tab === 'ttps' && (
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-[#2a2a3e]">
                      {['ID', 'Name', 'Tactics', 'Note'].map(h => (
                        <th key={h} className="px-3 py-2 text-left text-text-muted font-medium">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {actor.ttps.map(t => (
                      <tr key={t.technique_id} className="border-b border-[#2a2a3e]">
                        <td className="px-3 py-2">
                          <TechniqueTag id={t.technique_id} />
                        </td>
                        <td className="px-3 py-2 text-text-primary">{t.name ?? '—'}</td>
                        <td className="px-3 py-2 text-text-muted">{t.tactics.join(', ')}</td>
                        <td className="px-3 py-2 text-text-muted">{t.use_note ?? '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {tab === 'stix' && (
              <div>
                {stix ? (
                  <CodeBlock
                    code={JSON.stringify(stix, null, 2)}
                    language="json"
                    maxLines={100}
                  />
                ) : (
                  <div className="py-8 text-center text-xs text-text-muted">Loading STIX data…</div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
