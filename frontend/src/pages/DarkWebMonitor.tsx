import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { RefreshCw, Globe, Activity, Users, Clock, AlertTriangle, Shield, Download, X } from 'lucide-react'
import {
  useDarkWebSources,
  useDarkWebPosts,
  useDarkWebVictims,
  useDarkWebStats,
  usePullDarkWeb,
  useFetchDarkWebPost,
  useIngestDarkWebPost,
  useToggleDarkWebSource,
  type DarkWebPost,
  type DarkWebSource,
  type DarkWebVictim,
} from '@/api/darkweb'
import { timeAgo } from '@/lib/utils'
import { cn } from '@/lib/utils'

const CATEGORY_COLORS: Record<string, string> = {
  ransomware: 'bg-red-900/40 text-red-300 border border-red-700/40',
  hacking: 'bg-orange-900/40 text-orange-300 border border-orange-700/40',
  'initial-access': 'bg-purple-900/40 text-purple-300 border border-purple-700/40',
  'data-leak': 'bg-yellow-900/40 text-yellow-300 border border-yellow-700/40',
  malware: 'bg-blue-900/40 text-blue-300 border border-blue-700/40',
}

const STATUS_STYLES: Record<string, string> = {
  queued: 'bg-[#2a2a3e] text-text-muted',
  fetching: 'bg-accent/20 text-accent-bright animate-pulse',
  fetched: 'bg-blue-900/30 text-blue-300',
  ingesting: 'bg-yellow-900/30 text-yellow-300 animate-pulse',
  done: 'bg-green-900/30 text-green-400',
  failed: 'bg-red-900/30 text-red-400',
  skipped: 'bg-[#2a2a3e] text-text-muted',
}

function CategoryBadge({ category }: { category: string | null }) {
  if (!category) return null
  return (
    <span className={cn('rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide', CATEGORY_COLORS[category] ?? 'bg-[#2a2a3e] text-text-muted')}>
      {category}
    </span>
  )
}

function StatusChip({ status }: { status: string }) {
  return (
    <span className={cn('rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide', STATUS_STYLES[status] ?? 'bg-[#2a2a3e] text-text-muted')}>
      {status}
    </span>
  )
}

function SourceHealthDot({ source }: { source: DarkWebSource }) {
  if (source.last_error) return <span className="inline-block h-2.5 w-2.5 rounded-full bg-red-500" title={source.last_error} />
  if (!source.last_polled_at) return <span className="inline-block h-2.5 w-2.5 rounded-full bg-[#3a3a5e]" title="Never pulled" />
  const hoursAgo = (Date.now() - new Date(source.last_polled_at).getTime()) / 3_600_000
  if (hoursAgo < 6) return <span className="inline-block h-2.5 w-2.5 rounded-full bg-green-500" title={`Pulled ${timeAgo(source.last_polled_at)}`} />
  if (hoursAgo < 24) return <span className="inline-block h-2.5 w-2.5 rounded-full bg-yellow-500" title={`Pulled ${timeAgo(source.last_polled_at)}`} />
  return <span className="inline-block h-2.5 w-2.5 rounded-full bg-red-500" title={`Last pulled ${timeAgo(source.last_polled_at)}`} />
}

// ── Stats bar ─────────────────────────────────────────────────────────────────

function StatsBar() {
  const { data } = useDarkWebStats()
  if (!data) return null
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
      {[
        { icon: Globe, label: 'Active Sources', value: `${data.active_sources}/${data.total_sources}` },
        { icon: Activity, label: 'Posts Today', value: data.posts_today },
        { icon: Users, label: 'Victims (30d)', value: data.victims_30d },
        { icon: Clock, label: 'Pending Ingest', value: data.pending_ingest },
        { icon: AlertTriangle, label: 'Top Actor', value: data.top_actor ? `${data.top_actor} (${data.top_actor_count})` : '—' },
      ].map(({ icon: Icon, label, value }) => (
        <div key={label} className="rounded-lg border border-[#2a2a3e] bg-bg-surface p-3">
          <div className="flex items-center gap-2 text-text-muted">
            <Icon size={13} />
            <span className="text-[10px] uppercase tracking-wide">{label}</span>
          </div>
          <p className="mt-1 text-sm font-semibold text-text-primary">{String(value)}</p>
        </div>
      ))}
    </div>
  )
}

// ── Post detail modal (for done posts with no linked report) ──────────────────

function PostDetailModal({ post, onClose }: { post: DarkWebPost; onClose: () => void }) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={onClose}
    >
      <div
        className="w-full max-w-lg rounded-xl border border-[#2a2a3e] bg-bg-surface p-6 shadow-xl"
        onClick={e => e.stopPropagation()}
      >
        <div className="mb-4 flex items-start justify-between gap-3">
          <div className="flex flex-wrap gap-2">
            <CategoryBadge category={post.category} />
            <StatusChip status={post.status} />
            {post.threat_actor && (
              <span className="text-xs font-semibold text-red-400">{post.threat_actor}</span>
            )}
          </div>
          <button onClick={onClose} className="text-text-muted hover:text-text-primary">
            <X size={16} />
          </button>
        </div>

        <h2 className="text-base font-semibold text-text-primary">
          {post.victim_org ?? post.title ?? 'Unknown'}
        </h2>
        {(post.victim_sector || post.victim_country) && (
          <p className="mt-0.5 text-sm text-text-muted">
            {[post.victim_sector, post.victim_country].filter(Boolean).join(' · ')}
          </p>
        )}

        <dl className="mt-4 space-y-2 text-sm">
          {post.threat_actor && (
            <div className="flex gap-2">
              <dt className="w-28 shrink-0 text-text-muted">Threat Actor</dt>
              <dd className="font-medium text-red-400">{post.threat_actor}</dd>
            </div>
          )}
          <div className="flex gap-2">
            <dt className="w-28 shrink-0 text-text-muted">TLP</dt>
            <dd className={cn('font-mono font-medium', post.tlp === 'RED' ? 'text-red-400' : post.tlp === 'AMBER' ? 'text-yellow-400' : 'text-green-400')}>
              {post.tlp}
            </dd>
          </div>
          <div className="flex gap-2">
            <dt className="w-28 shrink-0 text-text-muted">Admiralty</dt>
            <dd className="text-text-primary">{post.admiralty_code}</dd>
          </div>
          <div className="flex gap-2">
            <dt className="w-28 shrink-0 text-text-muted">Source</dt>
            <dd className="text-text-primary">{post.source_name ?? '—'}</dd>
          </div>
          <div className="flex gap-2">
            <dt className="w-28 shrink-0 text-text-muted">Seen</dt>
            <dd className="text-text-primary">{timeAgo(post.created_at)}</dd>
          </div>
        </dl>

        {!post.report_id && (
          <p className="mt-4 rounded-md bg-[#2a2a3e] px-3 py-2 text-xs text-text-muted">
            No Intel Report linked — this post was ingested without creating a SourceReport.
          </p>
        )}
      </div>
    </div>
  )
}

// ── Tab: Threat Feed ──────────────────────────────────────────────────────────

function ThreatFeedTab() {
  const navigate = useNavigate()
  const [categoryFilter, setCategoryFilter] = useState('')
  const [sectorFilter, setSectorFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [actorFilter, setActorFilter] = useState('')
  const [selectedPost, setSelectedPost] = useState<DarkWebPost | null>(null)

  const { data: posts = [], isLoading } = useDarkWebPosts({
    category: categoryFilter || undefined,
    victim_sector: sectorFilter || undefined,
    status: statusFilter || undefined,
    threat_actor: actorFilter || undefined,
    limit: 100,
  })

  const fetchPost = useFetchDarkWebPost()
  const ingestPost = useIngestDarkWebPost()

  function handleFetch(postId: string, e: React.MouseEvent) {
    e.stopPropagation()
    fetchPost.mutate(postId)
  }

  function handleIngest(postId: string, e: React.MouseEvent) {
    e.stopPropagation()
    ingestPost.mutate(postId)
  }

  function handlePostClick(post: DarkWebPost) {
    if (post.report_id) {
      navigate(`/intel/${post.report_id}`)
    } else {
      setSelectedPost(post)
    }
  }

  return (
    <div className="space-y-4">
      {selectedPost && (
        <PostDetailModal post={selectedPost} onClose={() => setSelectedPost(null)} />
      )}
      {/* Filter bar */}
      <div className="flex flex-wrap gap-2">
        {[
          { label: 'Category', value: categoryFilter, onChange: setCategoryFilter, options: ['ransomware', 'hacking', 'initial-access', 'data-leak', 'malware'] },
          { label: 'Status', value: statusFilter, onChange: setStatusFilter, options: ['queued', 'fetching', 'fetched', 'ingesting', 'done', 'failed', 'skipped'] },
        ].map(({ label, value, onChange, options }) => (
          <select
            key={label}
            value={value}
            onChange={e => onChange(e.target.value)}
            className="rounded-md border border-[#2a2a3e] bg-bg-surface px-2 py-1.5 text-xs text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
          >
            <option value="">All {label}s</option>
            {options.map(o => <option key={o} value={o}>{o}</option>)}
          </select>
        ))}
        <input
          value={sectorFilter}
          onChange={e => setSectorFilter(e.target.value)}
          placeholder="Filter sector..."
          className="rounded-md border border-[#2a2a3e] bg-bg-surface px-2 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
        />
        <input
          value={actorFilter}
          onChange={e => setActorFilter(e.target.value)}
          placeholder="Filter actor..."
          className="rounded-md border border-[#2a2a3e] bg-bg-surface px-2 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
        />
      </div>

      {isLoading && <p className="text-sm text-text-muted">Loading posts...</p>}
      {!isLoading && posts.length === 0 && (
        <p className="text-sm text-text-muted">No posts found. Run "pythia sync dark-web" to seed sources, then pull.</p>
      )}

      <div className="space-y-2">
        {posts.map((post: DarkWebPost) => (
          <div
            key={post.id}
            onClick={() => handlePostClick(post)}
            className={cn(
              'cursor-pointer rounded-lg border border-[#2a2a3e] bg-bg-surface p-4 transition-colors hover:border-accent/40 hover:bg-bg-elevated',
            )}
          >
            <div className="flex flex-wrap items-start justify-between gap-2">
              <div className="flex flex-wrap items-center gap-2">
                <CategoryBadge category={post.category} />
                <StatusChip status={post.status} />
                {post.threat_actor && (
                  <span className="text-xs font-semibold text-red-400">{post.threat_actor}</span>
                )}
              </div>
              <div className="flex gap-2">
                {post.status === 'queued' && (
                  <button
                    onClick={e => handleFetch(post.id, e)}
                    disabled={fetchPost.isPending}
                    className="rounded-md bg-bg-elevated px-2 py-1 text-[11px] text-text-muted hover:text-text-primary disabled:opacity-50"
                  >
                    Fetch
                  </button>
                )}
                {post.status === 'fetched' && (
                  <button
                    onClick={e => handleIngest(post.id, e)}
                    disabled={ingestPost.isPending}
                    className="rounded-md bg-accent/20 px-2 py-1 text-[11px] text-accent-bright hover:bg-accent/30 disabled:opacity-50"
                  >
                    Ingest
                  </button>
                )}
              </div>
            </div>

            <div className="mt-2">
              <p className="text-sm font-medium text-text-primary">
                {post.victim_org ?? post.title ?? 'Unknown'}
              </p>
              {(post.victim_sector || post.victim_country) && (
                <p className="text-xs text-text-muted">
                  {[post.victim_sector, post.victim_country].filter(Boolean).join(' · ')}
                </p>
              )}
            </div>

            <div className="mt-2 flex items-center gap-3 text-[11px] text-text-muted">
              <span>{post.source_name}</span>
              <span>·</span>
              <span>{timeAgo(post.created_at)}</span>
              {post.admiralty_code !== 'E3' && <span>· {post.admiralty_code}</span>}
              <span className={cn('ml-auto font-mono', post.tlp === 'RED' ? 'text-red-400' : post.tlp === 'AMBER' ? 'text-yellow-400' : 'text-green-400')}>
                TLP:{post.tlp}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Tab: Victim Tracker ───────────────────────────────────────────────────────

function VictimTrackerTab() {
  const [sectorFilter, setSectorFilter] = useState('')
  const [countryFilter, setCountryFilter] = useState('')
  const [actorFilter, setActorFilter] = useState('')
  const { data: victims = [], isLoading } = useDarkWebVictims({
    sector: sectorFilter || undefined,
    country: countryFilter || undefined,
    actor: actorFilter || undefined,
    limit: 200,
  })

  function exportCsv() {
    const header = 'Org,Sector,Country,Actor,First Seen\n'
    const rows = victims.map((v: DarkWebVictim) =>
      [v.victim_org, v.victim_sector ?? '', v.victim_country ?? '', v.threat_actor ?? '', v.first_seen]
        .map(f => `"${String(f).replace(/"/g, '""')}"`)
        .join(',')
    ).join('\n')
    const blob = new Blob([header + rows], { type: 'text/csv' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = 'victims.csv'
    a.click()
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <input
          value={sectorFilter}
          onChange={e => setSectorFilter(e.target.value)}
          placeholder="Filter sector..."
          className="rounded-md border border-[#2a2a3e] bg-bg-surface px-2 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
        />
        <input
          value={countryFilter}
          onChange={e => setCountryFilter(e.target.value)}
          placeholder="Country (e.g. US)..."
          className="rounded-md border border-[#2a2a3e] bg-bg-surface px-2 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
        />
        <input
          value={actorFilter}
          onChange={e => setActorFilter(e.target.value)}
          placeholder="Filter actor..."
          className="rounded-md border border-[#2a2a3e] bg-bg-surface px-2 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
        />
        <button
          onClick={exportCsv}
          className="ml-auto flex items-center gap-1.5 rounded-md border border-[#2a2a3e] bg-bg-surface px-3 py-1.5 text-xs text-text-muted hover:text-text-primary"
        >
          <Download size={12} />
          Export CSV
        </button>
      </div>

      {isLoading && <p className="text-sm text-text-muted">Loading victims...</p>}
      {!isLoading && victims.length === 0 && (
        <p className="text-sm text-text-muted">No ingested victims yet. Posts must be fetched and ingested via Claude first.</p>
      )}

      <div className="overflow-x-auto rounded-lg border border-[#2a2a3e]">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[#2a2a3e] bg-bg-surface text-left text-[11px] uppercase tracking-wide text-text-muted">
              <th className="px-4 py-2">Organization</th>
              <th className="px-4 py-2">Sector</th>
              <th className="px-4 py-2">Country</th>
              <th className="px-4 py-2">Actor</th>
              <th className="px-4 py-2">First Seen</th>
            </tr>
          </thead>
          <tbody>
            {victims.map((v: DarkWebVictim) => (
              <tr key={v.post_id} className="border-b border-[#2a2a3e] hover:bg-bg-elevated">
                <td className="px-4 py-2 font-medium text-text-primary">{v.victim_org}</td>
                <td className="px-4 py-2 text-text-muted">{v.victim_sector ?? '—'}</td>
                <td className="px-4 py-2 text-text-muted">{v.victim_country ?? '—'}</td>
                <td className="px-4 py-2 text-red-400">{v.threat_actor ?? '—'}</td>
                <td className="px-4 py-2 text-text-muted">{timeAgo(v.first_seen)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── Tab: Source Health ────────────────────────────────────────────────────────

function SourceHealthTab() {
  const { data: sources = [], isLoading } = useDarkWebSources()
  const pull = usePullDarkWeb()
  const toggle = useToggleDarkWebSource()
  const [pullMsg, setPullMsg] = useState<{ text: string; ok: boolean } | null>(null)

  function doPull(sourceId?: string) {
    setPullMsg(null)
    pull.mutate(sourceId, {
      onSuccess: (data) => setPullMsg({ text: `${data.new_posts} new post${data.new_posts === 1 ? '' : 's'} queued`, ok: true }),
      onError: (err: Error) => setPullMsg({ text: err.message, ok: false }),
    })
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        {pullMsg && (
          <p className={cn('text-xs', pullMsg.ok ? 'text-green-400' : 'text-red-400')}>
            {pullMsg.text}
          </p>
        )}
        <button
          onClick={() => doPull(undefined)}
          disabled={pull.isPending}
          className="ml-auto flex items-center gap-2 rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-white hover:opacity-90 disabled:opacity-50"
        >
          <RefreshCw size={12} className={pull.isPending ? 'animate-spin' : ''} />
          Pull All Now
        </button>
      </div>

      {isLoading && <p className="text-sm text-text-muted">Loading sources...</p>}
      {!isLoading && sources.length === 0 && (
        <p className="text-sm text-text-muted">No sources configured. Run "pythia sync dark-web" first.</p>
      )}

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {sources.map((source: DarkWebSource) => (
          <div key={source.id} className="rounded-lg border border-[#2a2a3e] bg-bg-surface p-4">
            <div className="flex items-start justify-between gap-2">
              <div className="flex items-center gap-2">
                <SourceHealthDot source={source} />
                <span className="text-sm font-medium text-text-primary">{source.name}</span>
              </div>
              <CategoryBadge category={source.category} />
            </div>

            <div className="mt-2 space-y-1 text-xs text-text-muted">
              <p>Posts: {source.post_count}</p>
              <p>Pulled: {source.last_polled_at ? timeAgo(source.last_polled_at) : 'Never'}</p>
              <p>Interval: {source.poll_interval_h}h</p>
              {source.last_error && (
                <p className="text-red-400 line-clamp-1" title={source.last_error}>
                  Error: {source.last_error}
                </p>
              )}
            </div>

            <div className="mt-3 flex items-center gap-3">
              <label className="flex cursor-pointer items-center gap-1.5 text-xs text-text-muted">
                <input
                  type="checkbox"
                  checked={source.active}
                  onChange={e => toggle.mutate({ id: source.id, active: e.target.checked })}
                  className="h-3 w-3 accent-accent"
                />
                Active
              </label>
              <label className="flex cursor-pointer items-center gap-1.5 text-xs text-text-muted">
                <input
                  type="checkbox"
                  checked={source.auto_ingest}
                  onChange={e => toggle.mutate({ id: source.id, auto_ingest: e.target.checked })}
                  className="h-3 w-3 accent-accent"
                />
                Auto-ingest
              </label>
              <button
                onClick={() => doPull(source.id)}
                disabled={pull.isPending}
                className="ml-auto text-[11px] text-accent-bright hover:underline disabled:opacity-50"
              >
                Pull now
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

const TABS = [
  { id: 'feed', label: 'Threat Feed' },
  { id: 'victims', label: 'Victim Tracker' },
  { id: 'sources', label: 'Source Health' },
] as const

type TabId = (typeof TABS)[number]['id']

export function DarkWebMonitor() {
  const [activeTab, setActiveTab] = useState<TabId>('feed')
  const pull = usePullDarkWeb()
  const [pullMsg, setPullMsg] = useState<{ text: string; ok: boolean } | null>(null)

  function doPullAll() {
    setPullMsg(null)
    pull.mutate(undefined, {
      onSuccess: (data) => setPullMsg({ text: `${data.new_posts} new post${data.new_posts === 1 ? '' : 's'} queued`, ok: true }),
      onError: (err: Error) => setPullMsg({ text: err.message, ok: false }),
    })
  }

  return (
    <div className="space-y-5">
      {/* Page header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Shield size={18} className="text-red-400" />
            <h1 className="text-lg font-semibold text-text-primary">Dark Web Monitor</h1>
          </div>
          <p className="mt-0.5 text-sm text-text-muted">
            Ransomware leak sites and underground forums — early warning intelligence via Tor
          </p>
          {pullMsg && (
            <p className={cn('mt-1 text-xs', pullMsg.ok ? 'text-green-400' : 'text-red-400')}>
              {pullMsg.text}
            </p>
          )}
        </div>
        <button
          onClick={doPullAll}
          disabled={pull.isPending}
          className="flex items-center gap-2 rounded-md border border-[#2a2a3e] bg-bg-surface px-3 py-1.5 text-xs text-text-muted hover:text-text-primary disabled:opacity-50"
        >
          <RefreshCw size={12} className={pull.isPending ? 'animate-spin' : ''} />
          Pull All
        </button>
      </div>

      <StatsBar />

      {/* Tabs */}
      <div className="border-b border-[#2a2a3e]">
        <div className="flex gap-1">
          {TABS.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={cn(
                'px-4 py-2 text-sm font-medium transition-colors',
                activeTab === tab.id
                  ? 'border-b-2 border-accent-bright text-text-primary'
                  : 'text-text-muted hover:text-text-primary',
              )}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {activeTab === 'feed' && <ThreatFeedTab />}
      {activeTab === 'victims' && <VictimTrackerTab />}
      {activeTab === 'sources' && <SourceHealthTab />}
    </div>
  )
}
