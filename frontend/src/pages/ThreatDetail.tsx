import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useThreat } from '@/api/threats'
import { TlpBadge } from '@/components/shared/TlpBadge'
import { TechniqueTag } from '@/components/shared/TechniqueTag'
import { CodeBlock } from '@/components/shared/CodeBlock'
import { Breadcrumb } from '@/components/layout/Breadcrumb'
import { timeAgo } from '@/lib/utils'

type Tab = 'summary' | 'ttps' | 'iocs' | 'actors' | 'raw'

export function ThreatDetail() {
  const { id } = useParams<{ id: string }>()
  const { data, isLoading, error } = useThreat(id ?? '')
  const [tab, setTab] = useState<Tab>('summary')

  if (isLoading) return <div className="py-16 text-center text-sm text-text-muted">Loading…</div>
  if (error || !data) return <div className="py-16 text-center text-sm text-red-400">Report not found.</div>

  const pd = data.parsed_data
  const iocs = (pd.iocs as Array<{ value: string; type: string; pyramid_tier?: string }>) ?? []
  const ttps = data.ttps ?? []
  const actors = data.actors ?? []

  const TABS: { key: Tab; label: string }[] = [
    { key: 'summary', label: 'Summary' },
    { key: 'ttps', label: `TTPs (${ttps.length})` },
    { key: 'iocs', label: `IoCs (${iocs.length})` },
    { key: 'actors', label: `Actors (${actors.length})` },
    { key: 'raw', label: 'Raw JSON' },
  ]

  return (
    <div>
      <Breadcrumb crumbs={[{ label: 'Intel', to: '/intel' }, { label: data.title ?? 'Report' }]} />

      {/* Hero */}
      <div className="mb-6 rounded-xl border border-[#2a2a3e] bg-bg-surface p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-lg font-semibold text-text-primary">{data.title ?? 'Untitled Report'}</h1>
            <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-text-muted">
              {data.url && (
                <a href={data.url} target="_blank" rel="noreferrer" className="text-accent-bright hover:underline">
                  Source ↗
                </a>
              )}
              <span>Ingested {timeAgo(data.publication_date)}</span>
              <span className="capitalize">{data.status.replace('_', ' ')}</span>
            </div>
          </div>
          <TlpBadge tlp={data.tlp} className="text-sm px-2 py-1" />
        </div>
      </div>

      {/* Tabs */}
      <div className="mb-4 flex border-b border-[#2a2a3e]">
        {TABS.map(t => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
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
        {tab === 'summary' && (
          <div className="prose-sm max-w-none text-text-primary">
            <p className="text-sm leading-relaxed">
              {(pd.business_impact as string) ?? (pd.summary as string) ?? 'No summary available.'}
            </p>
            {Array.isArray(pd.sectors_targeted) && (
              <div className="mt-4">
                <p className="text-xs font-medium text-text-muted mb-2">Sectors Targeted</p>
                <div className="flex flex-wrap gap-1">
                  {(pd.sectors_targeted as string[]).map(s => (
                    <span key={s} className="rounded bg-bg-elevated px-2 py-0.5 text-xs text-text-primary">
                      {s}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {tab === 'ttps' && (
          <div>
            {ttps.length === 0 ? (
              <p className="text-xs text-text-muted">No techniques extracted.</p>
            ) : (
              <div className="flex flex-wrap gap-2">
                {ttps.map(id => (
                  <TechniqueTag key={id} id={id} />
                ))}
              </div>
            )}
          </div>
        )}

        {tab === 'iocs' && (
          <div className="overflow-x-auto">
            {iocs.length === 0 ? (
              <p className="text-xs text-text-muted">No IoCs extracted.</p>
            ) : (
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-[#2a2a3e]">
                    <th className="px-3 py-2 text-left text-text-muted font-medium">Type</th>
                    <th className="px-3 py-2 text-left text-text-muted font-medium">Value</th>
                    <th className="px-3 py-2 text-left text-text-muted font-medium">Tier</th>
                  </tr>
                </thead>
                <tbody>
                  {iocs.map((ioc, i) => (
                    <tr key={i} className="border-b border-[#2a2a3e]">
                      <td className="px-3 py-2 text-text-muted">{ioc.type}</td>
                      <td className="px-3 py-2 font-mono text-text-primary">{ioc.value}</td>
                      <td className="px-3 py-2 text-text-muted">{ioc.pyramid_tier ?? '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {tab === 'actors' && (
          <div>
            {actors.length === 0 ? (
              <p className="text-xs text-text-muted">No actors extracted.</p>
            ) : (
              <div className="flex flex-wrap gap-2">
                {actors.map(name => (
                  <Link
                    key={name}
                    to={`/actors/${encodeURIComponent(name)}`}
                    className="rounded bg-bg-elevated px-2 py-1 text-xs text-accent-bright hover:opacity-80"
                  >
                    {name}
                  </Link>
                ))}
              </div>
            )}
          </div>
        )}

        {tab === 'raw' && (
          <CodeBlock
            code={JSON.stringify(pd, null, 2)}
            language="json"
            maxLines={100}
          />
        )}
      </div>
    </div>
  )
}
