import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { useTTP, useHuntQueries } from '@/api/ttps'
import { SeverityBadge } from '@/components/shared/SeverityBadge'
import { CodeBlock } from '@/components/shared/CodeBlock'
import { Breadcrumb } from '@/components/layout/Breadcrumb'

type Tab = 'description' | 'hunt' | 'actors'
type QueryTab = 'splunk' | 'elastic' | 'sentinel' | 'sigma'

export function TtpDetail() {
  const { id } = useParams<{ id: string }>()
  const [tab, setTab] = useState<Tab>('description')
  const { data: ttp, isLoading } = useTTP(id ?? '')
  const { data: hunts } = useHuntQueries(id ?? '')

  if (isLoading) return <div className="py-16 text-center text-sm text-text-muted">Loading…</div>
  if (!ttp) return <div className="py-16 text-center text-sm text-red-400">Technique not found.</div>

  const TABS = [
    { key: 'description' as Tab, label: 'Description' },
    { key: 'hunt' as Tab, label: `Hunt Queries (${hunts?.rules.length ?? 0})` },
    { key: 'actors' as Tab, label: 'Actors Using This' },
  ]

  return (
    <div>
      <Breadcrumb crumbs={[{ label: 'TTPs', to: '/ttps' }, { label: ttp.technique_id }]} />

      {/* Hero */}
      <div className="mb-6 rounded-xl border border-[#2a2a3e] bg-bg-surface p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="mb-1 font-mono text-sm font-medium text-accent-bright">{ttp.technique_id}</p>
            <h1 className="text-lg font-semibold text-text-primary">{ttp.name}</h1>
            <div className="mt-2 flex flex-wrap gap-3 text-xs text-text-muted">
              <span>Tactics: {ttp.tactics.join(', ')}</span>
              <span>Domain: {ttp.domain}</span>
              {ttp.data_sources.length > 0 && (
                <span>Sources: {ttp.data_sources.slice(0, 3).join(', ')}</span>
              )}
            </div>
          </div>
          {ttp.url && (
            <a
              href={ttp.url}
              target="_blank"
              rel="noreferrer"
              className="rounded-lg border border-[#2a2a3e] px-3 py-1.5 text-xs text-text-muted hover:text-text-primary"
            >
              View on ATT&CK ↗
            </a>
          )}
        </div>
      </div>

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
        {tab === 'description' && (
          <div className="space-y-4">
            <p className="text-sm leading-relaxed text-text-primary">
              {ttp.description ?? 'No description available.'}
            </p>
            {ttp.detection && (
              <div>
                <h3 className="mb-2 text-xs font-semibold text-text-muted">Detection</h3>
                <p className="text-xs leading-relaxed text-text-primary">{ttp.detection}</p>
              </div>
            )}
            {ttp.platforms.length > 0 && (
              <div>
                <h3 className="mb-2 text-xs font-semibold text-text-muted">Platforms</h3>
                <div className="flex flex-wrap gap-1">
                  {ttp.platforms.map(p => (
                    <span key={p} className="rounded bg-bg-elevated px-2 py-0.5 text-xs text-text-primary">
                      {p}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {tab === 'hunt' && (
          <div className="space-y-6">
            {!hunts || hunts.rules.length === 0 ? (
              <div className="py-8 text-center text-xs text-text-muted">
                No detection rules for this technique yet.
              </div>
            ) : (
              hunts.rules.map(rule => (
                <RuleCard key={rule.id} rule={rule} />
              ))
            )}
          </div>
        )}

        {tab === 'actors' && (
          <p className="text-xs text-text-muted">
            Actor data will appear here when actor-TTP mappings are loaded.
          </p>
        )}
      </div>
    </div>
  )
}

function RuleCard({ rule }: { rule: import('@/types/api').HuntQuery }) {
  const [queryTab, setQueryTab] = useState<QueryTab>('splunk')
  const [showSigma, setShowSigma] = useState(false)

  const QUERY_TABS: { key: QueryTab; label: string; content: string | null }[] = [
    { key: 'splunk', label: 'Splunk SPL', content: rule.splunk_spl },
    { key: 'elastic', label: 'Elastic KQL', content: rule.elastic_kql },
    { key: 'sentinel', label: 'Sentinel KQL', content: rule.sentinel_kql },
  ]

  return (
    <div className="rounded-lg border border-[#2a2a3e] p-4">
      <div className="mb-3 flex items-center justify-between">
        <span className="text-sm font-medium text-text-primary">{rule.title}</span>
        <SeverityBadge severity={rule.severity} />
      </div>

      <div className="mb-3 flex gap-2">
        {QUERY_TABS.map(t => (
          <button
            key={t.key}
            onClick={() => setQueryTab(t.key)}
            disabled={!t.content}
            className={`rounded px-2.5 py-1 text-xs transition-colors disabled:opacity-30 ${
              queryTab === t.key
                ? 'bg-accent text-white'
                : 'text-text-muted hover:text-text-primary'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {QUERY_TABS.find(t => t.key === queryTab)?.content ? (
        <CodeBlock
          code={QUERY_TABS.find(t => t.key === queryTab)!.content!}
          language={queryTab === 'splunk' ? 'spl' : 'kql'}
        />
      ) : (
        <p className="text-xs text-text-muted">No query available for this platform.</p>
      )}

      {rule.sigma_yaml && (
        <div className="mt-3">
          <button
            onClick={() => setShowSigma(s => !s)}
            className="text-xs text-text-muted hover:text-text-primary"
          >
            {showSigma ? 'Hide' : 'Show'} Sigma YAML
          </button>
          {showSigma && (
            <div className="mt-2">
              <CodeBlock code={rule.sigma_yaml} language="yaml" />
            </div>
          )}
        </div>
      )}
    </div>
  )
}
