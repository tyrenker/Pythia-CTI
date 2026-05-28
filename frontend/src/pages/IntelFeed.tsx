import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useThreats } from '@/api/threats'
import {
  useFeedSources,
  useFeedArticles,
  useTriggerFetch,
  useIngestArticle,
  useToggleSource,
} from '@/api/intel-feed'
import { TlpBadge } from '@/components/shared/TlpBadge'
import { TechniqueTag } from '@/components/shared/TechniqueTag'
import { DataTable } from '@/components/shared/DataTable'
import { useDebounce } from '@/hooks/useDebounce'
import { timeAgo } from '@/lib/utils'
import type { ThreatSummary, FeedArticle, FeedSource } from '@/types/api'

const TLP_OPTIONS = ['WHITE', 'GREEN', 'AMBER', 'RED']

const STATUS_STYLES: Record<string, string> = {
  queued: 'bg-[#2a2a3e] text-text-muted',
  ingesting: 'bg-accent/20 text-accent-bright animate-pulse',
  done: 'bg-green-900/30 text-green-400',
  failed: 'bg-red-900/30 text-red-400',
  skipped: 'bg-[#2a2a3e] text-text-muted',
}

function SourceHealthDot({ source }: { source: FeedSource }) {
  if (source.last_error) return <span className="inline-block h-2 w-2 rounded-full bg-red-500" title={source.last_error} />
  if (!source.last_polled_at) return <span className="inline-block h-2 w-2 rounded-full bg-[#2a2a3e]" title="Never polled" />
  const hoursAgo = (Date.now() - new Date(source.last_polled_at).getTime()) / 3_600_000
  if (hoursAgo < 1) return <span className="inline-block h-2 w-2 animate-pulse rounded-full bg-green-500" title={`Polled ${timeAgo(source.last_polled_at)}`} />
  if (hoursAgo < 5) return <span className="inline-block h-2 w-2 rounded-full bg-green-500" title={`Polled ${timeAgo(source.last_polled_at)}`} />
  return <span className="inline-block h-2 w-2 rounded-full bg-yellow-500" title={`Polled ${timeAgo(source.last_polled_at)}`} />
}

// ── Tab: Processed (ingested SourceReports) ───────────────────────────────────

function ProcessedTab() {
  const navigate = useNavigate()
  const [search, setSearch] = useState('')
  const [tlpFilter, setTlpFilter] = useState<string[]>([])
  const [statusFilter, setStatusFilter] = useState('')
  const debouncedSearch = useDebounce(search, 300)
  const { data, isLoading } = useThreats({ limit: 100 })

  const filtered = (data ?? []).filter(t => {
    if (debouncedSearch && !t.title?.toLowerCase().includes(debouncedSearch.toLowerCase())) return false
    if (tlpFilter.length > 0 && !tlpFilter.includes(t.tlp.toUpperCase())) return false
    if (statusFilter && t.status !== statusFilter) return false
    return true
  })

  const columns = [
    {
      key: 'title',
      header: 'Title',
      sortable: true,
      render: (t: ThreatSummary) => (
        <span className="font-medium text-text-primary">{t.title ?? 'Untitled'}</span>
      ),
    },
    {
      key: 'actors',
      header: 'Actors',
      render: (t: ThreatSummary) => (
        <span className="text-text-muted">
          {t.actors.slice(0, 3).join(', ')}
          {t.actors.length > 3 && ` +${t.actors.length - 3} more`}
        </span>
      ),
    },
    {
      key: 'ttps',
      header: 'TTPs',
      render: (t: ThreatSummary) => (
        <div className="flex flex-wrap gap-1" onClick={e => e.stopPropagation()}>
          {t.ttps.slice(0, 3).map(id => <TechniqueTag key={id} id={id} />)}
          {t.ttps.length > 3 && <span className="text-xs text-text-muted">+{t.ttps.length - 3} more</span>}
        </div>
      ),
    },
    {
      key: 'tlp',
      header: 'TLP',
      sortable: true,
      render: (t: ThreatSummary) => <TlpBadge tlp={t.tlp} />,
    },
    {
      key: 'publication_date',
      header: 'Published',
      sortable: true,
      render: (t: ThreatSummary) => (
        <span className="text-text-muted">{timeAgo(t.publication_date)}</span>
      ),
    },
    {
      key: 'created_at',
      header: 'Ingested',
      sortable: true,
      render: (t: ThreatSummary) => (
        <span className="text-text-muted">{timeAgo(t.created_at)}</span>
      ),
    },
  ]

  return (
    <>
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2">
          {TLP_OPTIONS.map(tlp => (
            <label key={tlp} className="flex cursor-pointer items-center gap-1 text-xs">
              <input
                type="checkbox"
                checked={tlpFilter.includes(tlp)}
                onChange={e =>
                  setTlpFilter(prev =>
                    e.target.checked ? [...prev, tlp] : prev.filter(t => t !== tlp),
                  )
                }
                className="accent-accent"
              />
              <TlpBadge tlp={tlp} />
            </label>
          ))}
        </div>
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search title..."
          className="rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-1.5 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
        />
        <select
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value)}
          className="rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-1.5 text-xs text-text-primary focus:outline-none"
        >
          <option value="">All statuses</option>
          <option value="pending_review">Pending Review</option>
          <option value="accepted">Accepted</option>
          <option value="rejected">Rejected</option>
        </select>
      </div>
      <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface">
        <DataTable
          columns={columns}
          data={filtered}
          loading={isLoading}
          emptyTitle="No intel reports yet"
          emptyDescription="Ingest a URL using the bar above, or trigger a feed poll."
          onRowClick={t => navigate(`/intel/${t.id}`)}
          keyFn={t => t.id}
        />
      </div>
    </>
  )
}

// ── Tab: Queue (raw IntelFeedArticles) ────────────────────────────────────────

function QueueTab() {
  const [sourceFilter, setSourceFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const { data: sources } = useFeedSources()
  const { data: articles, isLoading } = useFeedArticles({
    source_id: sourceFilter || undefined,
    status: statusFilter || undefined,
    limit: 100,
  })
  const ingest = useIngestArticle()
  const trigger = useTriggerFetch()

  const columns = [
    {
      key: 'title',
      header: 'Title',
      render: (a: FeedArticle) => (
        <a
          href={a.url}
          target="_blank"
          rel="noopener noreferrer"
          onClick={e => e.stopPropagation()}
          className="font-medium text-accent-bright hover:underline"
        >
          {a.title ?? a.url}
        </a>
      ),
    },
    {
      key: 'source_name',
      header: 'Source',
      render: (a: FeedArticle) => (
        <span className="rounded-full bg-[#1e1e2f] px-2 py-0.5 text-xs text-text-muted">
          {a.source_name}
        </span>
      ),
    },
    {
      key: 'published_at',
      header: 'Published',
      sortable: true,
      render: (a: FeedArticle) => (
        <span className="text-text-muted">{timeAgo(a.published_at)}</span>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      render: (a: FeedArticle) => (
        <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${STATUS_STYLES[a.status] ?? ''}`}>
          {a.status}
        </span>
      ),
    },
    {
      key: 'actions',
      header: '',
      render: (a: FeedArticle) => {
        if (a.status === 'done' && a.report_id) {
          return (
            <span className="text-xs text-green-400">✓ ingested</span>
          )
        }
        if (a.status === 'ingesting') {
          return <span className="text-xs text-accent-bright animate-pulse">processing…</span>
        }
        if (a.status === 'queued' || a.status === 'failed') {
          return (
            <button
              onClick={e => { e.stopPropagation(); ingest.mutate(a.id) }}
              disabled={ingest.isPending}
              className="rounded-md bg-accent/20 px-2 py-1 text-xs text-accent-bright hover:bg-accent/30 disabled:opacity-50"
            >
              Ingest
            </button>
          )
        }
        return null
      },
    },
  ]

  return (
    <>
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <select
          value={sourceFilter}
          onChange={e => setSourceFilter(e.target.value)}
          className="rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-1.5 text-xs text-text-primary focus:outline-none"
        >
          <option value="">All sources</option>
          {(sources ?? []).map(s => (
            <option key={s.id} value={s.id}>{s.name}</option>
          ))}
        </select>
        <select
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value)}
          className="rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-1.5 text-xs text-text-primary focus:outline-none"
        >
          <option value="">All statuses</option>
          <option value="queued">Queued</option>
          <option value="ingesting">Ingesting</option>
          <option value="done">Done</option>
          <option value="failed">Failed</option>
        </select>
        <button
          onClick={() => trigger.mutate(undefined)}
          disabled={trigger.isPending}
          className="ml-auto rounded-lg bg-accent px-3 py-1.5 text-xs font-medium text-white hover:bg-accent-bright disabled:opacity-50"
        >
          {trigger.isPending ? 'Pulling…' : 'Pull Feeds Now'}
        </button>
      </div>

      {trigger.data && (
        <div className="mb-3 rounded-lg border border-green-800 bg-green-900/20 px-3 py-2 text-xs text-green-400">
          Pull complete — {trigger.data.new_articles} new articles queued.
        </div>
      )}

      <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface">
        <DataTable
          columns={columns}
          data={articles ?? []}
          loading={isLoading}
          emptyTitle="No articles in queue"
          emptyDescription="Click 'Poll Feeds Now' to fetch the latest articles from configured sources."
          keyFn={a => a.id}
        />
      </div>
    </>
  )
}

// ── Sources sidebar ───────────────────────────────────────────────────────────

function SourcesSidebar() {
  const { data: sources } = useFeedSources()
  const toggle = useToggleSource()

  const activeCount = (sources ?? []).filter(s => s.active).length
  const totalCount = sources?.length ?? 0

  return (
    <div className="w-56 shrink-0">
      <div className="mb-2 flex items-center justify-between">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-text-muted">
          Feed Sources
        </h2>
        {totalCount > 0 && (
          <span className="text-xs text-text-muted">
            <span className="text-green-400">{activeCount}</span>/{totalCount} active
          </span>
        )}
      </div>
      <div className="space-y-1">
        {(sources ?? []).map(s => (
          <div
            key={s.id}
            className="flex items-center gap-2 rounded-lg px-2 py-1.5 text-xs hover:bg-bg-elevated"
          >
            <SourceHealthDot source={s} />
            <span className={`flex-1 truncate ${s.active ? 'text-text-primary' : 'text-text-muted'}`}>
              {s.name}
            </span>
            <button
              onClick={() => toggle.mutate({ id: s.id, active: !s.active })}
              className={`text-[10px] ${s.active ? 'text-green-400' : 'text-text-muted'} hover:underline`}
            >
              {s.active ? 'on' : 'off'}
            </button>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Page root ─────────────────────────────────────────────────────────────────

export function IntelFeed() {
  const [tab, setTab] = useState<'processed' | 'queue'>('processed')

  return (
    <div className="flex gap-6">
      <SourcesSidebar />

      <div className="min-w-0 flex-1">
        <div className="mb-4 flex items-center gap-1">
          <h1 className="mr-4 text-lg font-semibold text-text-primary">Intel Feed</h1>
          {(['processed', 'queue'] as const).map(t => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${
                tab === t
                  ? 'bg-accent text-white'
                  : 'text-text-muted hover:bg-bg-elevated hover:text-text-primary'
              }`}
            >
              {t === 'processed' ? 'Processed' : 'Raw Queue'}
            </button>
          ))}
        </div>

        {tab === 'processed' ? <ProcessedTab /> : <QueueTab />}
      </div>
    </div>
  )
}
