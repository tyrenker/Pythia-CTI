import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ChevronDown, ChevronUp, Rss } from 'lucide-react'
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
  queued:    'border border-[#2a2a3a] text-[#6b7280]',
  ingesting: 'border border-[#00ff88] text-[#00ff88] animate-pulse',
  done:      'border border-[#00ff88] text-[#00ff88]',
  failed:    'border border-[#ff3366] text-[#ff3366]',
  skipped:   'border border-[#2a2a3a] text-[#6b7280]',
}

function SourceHealthDot({ source }: { source: FeedSource }) {
  if (source.last_error)
    return <span className="inline-block h-1.5 w-1.5 bg-[#ff3366] shadow-[0_0_4px_#ff3366]" title={source.last_error} />
  if (!source.last_polled_at)
    return <span className="inline-block h-1.5 w-1.5 bg-[#2a2a3a]" title="Never polled" />
  const hoursAgo = (Date.now() - new Date(source.last_polled_at).getTime()) / 3_600_000
  if (hoursAgo < 5)
    return <span className="inline-block h-1.5 w-1.5 bg-[#00ff88] shadow-[0_0_4px_#00ff88]" title={`Polled ${timeAgo(source.last_polled_at)}`} />
  return <span className="inline-block h-1.5 w-1.5 bg-[#f59e0b] shadow-[0_0_4px_#f59e0b]" title={`Polled ${timeAgo(source.last_polled_at)}`} />
}

// ── Collapsible Feed Sources Panel ────────────────────────────────────────────

function FeedSourcesPanel() {
  const [open, setOpen] = useState(false)
  const { data: sources } = useFeedSources()
  const toggle = useToggleSource()

  const activeCount = (sources ?? []).filter(s => s.active).length
  const totalCount = sources?.length ?? 0

  return (
    <div className="mb-5">
      <button
        onClick={() => setOpen(v => !v)}
        className="flex items-center gap-2 border border-[#2a2a3a] bg-[#12121a] px-4 py-2 font-mono text-[10px] uppercase tracking-wider text-[#9ca3af] transition-all hover:border-[#00ff88]/40 hover:text-[#00ff88]"
      >
        <Rss size={11} strokeWidth={1.5} />
        FEED SOURCES
        <span className="font-mono text-[#00ff88]">
          {activeCount}/{totalCount}
        </span>
        {open
          ? <ChevronUp size={11} strokeWidth={1.5} />
          : <ChevronDown size={11} strokeWidth={1.5} />
        }
      </button>

      {open && (
        <div className="mt-1 border border-[#2a2a3a] bg-[#0a0a0f] p-4">
          <div className="grid grid-cols-2 gap-x-6 gap-y-0.5 sm:grid-cols-3 lg:grid-cols-4">
            {(sources ?? []).map(s => (
              <div
                key={s.id}
                className="flex items-center gap-2 py-1.5"
              >
                <SourceHealthDot source={s} />
                <span className={`flex-1 truncate font-mono text-[10px] ${s.active ? 'text-[#e0e0e0]' : 'text-[#6b7280]'}`}>
                  {s.name}
                </span>
                <button
                  onClick={() => toggle.mutate({ id: s.id, active: !s.active })}
                  className={`font-mono text-[9px] uppercase tracking-wider transition-colors hover:underline ${
                    s.active ? 'text-[#00ff88]' : 'text-[#6b7280] hover:text-[#9ca3af]'
                  }`}
                >
                  {s.active ? 'ON' : 'OFF'}
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Tab: Processed ────────────────────────────────────────────────────────────

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

  function toggleTlp(tlp: string) {
    setTlpFilter(prev => prev.includes(tlp) ? prev.filter(t => t !== tlp) : [...prev, tlp])
  }

  const columns = [
    {
      key: 'title',
      header: 'Title',
      sortable: true,
      render: (t: ThreatSummary) => (
        <span className="font-mono font-medium text-[#e0e0e0]">{t.title ?? 'Untitled'}</span>
      ),
    },
    {
      key: 'actors',
      header: 'Actors',
      render: (t: ThreatSummary) => (
        <span className="font-mono text-[#9ca3af]">
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
          {t.ttps.length > 3 && (
            <span className="font-mono text-[10px] text-[#6b7280]">+{t.ttps.length - 3} more</span>
          )}
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
        <span className="font-mono text-[#6b7280]">{timeAgo(t.publication_date)}</span>
      ),
    },
    {
      key: 'created_at',
      header: 'Ingested',
      sortable: true,
      render: (t: ThreatSummary) => (
        <span className="font-mono text-[#6b7280]">{timeAgo(t.created_at)}</span>
      ),
    },
  ]

  return (
    <>
      {/* Filters */}
      <div className="mb-4 flex flex-wrap items-center gap-3">
        {/* TLP toggles — click to filter, no checkbox */}
        <div className="flex items-center gap-1.5">
          {TLP_OPTIONS.map(tlp => {
            const active = tlpFilter.includes(tlp)
            return (
              <button
                key={tlp}
                onClick={() => toggleTlp(tlp)}
                className={`transition-all duration-150 ${active ? 'opacity-100 scale-105' : 'opacity-40 hover:opacity-70'}`}
                title={`Filter TLP:${tlp}`}
              >
                <TlpBadge tlp={tlp} />
              </button>
            )
          })}
          {tlpFilter.length > 0 && (
            <button
              onClick={() => setTlpFilter([])}
              className="font-mono text-[9px] uppercase tracking-wider text-[#6b7280] hover:text-[#ff3366] transition-colors ml-1"
            >
              [clear]
            </button>
          )}
        </div>

        <div className="relative">
          <span className="absolute left-2.5 top-1/2 -translate-y-1/2 font-mono text-[10px] text-[#00ff88]/50 select-none">{'>'}</span>
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search title..."
            className="border border-[#2a2a3a] bg-[#12121a] pl-6 pr-3 py-1.5 font-mono text-[10px] text-[#e0e0e0] placeholder-[#6b7280]/60 focus:outline-none focus:border-[#00ff88] transition-colors"
          />
        </div>

        <select
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value)}
          className="border border-[#2a2a3a] bg-[#12121a] px-3 py-1.5 font-mono text-[10px] text-[#9ca3af] focus:outline-none focus:border-[#00ff88] transition-colors"
        >
          <option value="">All statuses</option>
          <option value="pending_review">Pending Review</option>
          <option value="accepted">Accepted</option>
          <option value="rejected">Rejected</option>
        </select>
      </div>

      <div className="border border-[#2a2a3a] bg-[#12121a]">
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

// ── Tab: Queue ────────────────────────────────────────────────────────────────

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
          className="font-mono text-[#00ff88] hover:text-[#00ff88] transition-colors"
        >
          {a.title ?? a.url}
        </a>
      ),
    },
    {
      key: 'source_name',
      header: 'Source',
      render: (a: FeedArticle) => (
        <span className="border border-[#2a2a3a] px-1.5 py-0.5 font-mono text-[9px] text-[#9ca3af]">
          {a.source_name}
        </span>
      ),
    },
    {
      key: 'published_at',
      header: 'Published',
      sortable: true,
      render: (a: FeedArticle) => (
        <span className="font-mono text-[#6b7280]">{timeAgo(a.published_at)}</span>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      render: (a: FeedArticle) => {
        const isIngestingThis = ingest.isPending && ingest.variables === a.id
        const displayStatus = isIngestingThis ? 'ingesting' : a.status
        return (
          <span className={`px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wider ${STATUS_STYLES[displayStatus] ?? ''}`}>
            {displayStatus}
          </span>
        )
      },
    },
    {
      key: 'actions',
      header: '',
      render: (a: FeedArticle) => {
        if (a.status === 'done' && a.report_id)
          return <span className="font-mono text-[9px] text-[#00ff88]">✓ INGESTED</span>
        
        const isIngestingThis = ingest.isPending && ingest.variables === a.id
        
        if (a.status === 'ingesting' || isIngestingThis)
          return <span className="font-mono text-[9px] text-[#00ff88] animate-pulse">PROCESSING…</span>
        if (a.status === 'queued' || a.status === 'failed') {
          return (
            <button
              onClick={e => { e.stopPropagation(); ingest.mutate(a.id) }}
              disabled={ingest.isPending}
              className="border border-[#00ff88]/50 px-2 py-0.5 font-mono text-[9px] uppercase tracking-wider text-[#00ff88] transition-all hover:bg-[#00ff88]/10 disabled:opacity-40"
            >
              INGEST
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
          className="border border-[#2a2a3a] bg-[#12121a] px-3 py-1.5 font-mono text-[10px] text-[#9ca3af] focus:outline-none focus:border-[#00ff88] transition-colors"
        >
          <option value="">All sources</option>
          {(sources ?? []).map(s => (
            <option key={s.id} value={s.id}>{s.name}</option>
          ))}
        </select>

        <select
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value)}
          className="border border-[#2a2a3a] bg-[#12121a] px-3 py-1.5 font-mono text-[10px] text-[#9ca3af] focus:outline-none focus:border-[#00ff88] transition-colors"
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
          className="ml-auto bg-[#00ff88] px-4 py-1.5 font-mono text-[10px] font-bold uppercase tracking-wider text-[#0a0a0f] cyber-chamfer-sm transition-all hover:shadow-[0_0_12px_rgba(0,255,136,0.4)] disabled:opacity-50"
        >
          {trigger.isPending ? 'PULLING…' : 'PULL_FEEDS_NOW'}
        </button>
      </div>

      {trigger.data && (
        <div className="mb-3 border border-[#00ff88]/40 bg-[#00ff88]/5 px-3 py-2 font-mono text-[10px] text-[#00ff88]">
          {'> '} PULL_COMPLETE — {trigger.data.new_articles} new articles queued.
        </div>
      )}

      <div className="border border-[#2a2a3a] bg-[#12121a]">
        <DataTable
          columns={columns}
          data={articles ?? []}
          loading={isLoading}
          emptyTitle="No articles in queue"
          emptyDescription="Click PULL_FEEDS_NOW to fetch the latest articles."
          keyFn={a => a.id}
        />
      </div>
    </>
  )
}

// ── Page root ─────────────────────────────────────────────────────────────────

export function IntelFeed() {
  const [tab, setTab] = useState<'processed' | 'queue'>('processed')

  return (
    <div className="space-y-0">
      {/* Header */}
      <div className="mb-5 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="font-mono text-xs text-[#00ff88]/50 select-none">{'// '}</span>
          <h1 className="font-display text-xl font-bold uppercase tracking-widest text-[#e0e0e0]">
            Intel Feed
          </h1>
        </div>

        {/* Tabs — underline style, no filled bg */}
        <div className="flex items-center gap-0">
          {(['processed', 'queue'] as const).map(t => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`px-4 py-2 font-mono text-[10px] uppercase tracking-wider transition-all border-b-2 ${
                tab === t
                  ? 'border-[#00ff88] text-[#00ff88]'
                  : 'border-transparent text-[#6b7280] hover:text-[#b0b0c8]'
              }`}
            >
              {t === 'processed' ? 'Processed' : 'Raw Queue'}
            </button>
          ))}
        </div>
      </div>

      {/* Collapsible feed sources */}
      <FeedSourcesPanel />

      {tab === 'processed' ? <ProcessedTab /> : <QueueTab />}
    </div>
  )
}
