import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import {
  Bug,
  Code2,
  Eye,
  EyeOff,
  FileText,
  Link2,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
  Users,
  Zap,
  type LucideIcon,
} from 'lucide-react'
import { useDashboardSummary, useCoverage, useGeographies, useSectors } from '@/api/analytics'
import { useFeedArticles } from '@/api/intel-feed'
import { useMalwareFamilies } from '@/api/malware'
import { useSyncStatus } from '@/api/sync'
import { useThreats } from '@/api/threats'
import { IngestBar } from '@/components/shared/IngestBar'
import { TlpBadge } from '@/components/shared/TlpBadge'
import { formatDate, timeAgo } from '@/lib/utils'

// ── Widget visibility ─────────────────────────────────────────────────────────

type WidgetKey =
  | 'actor_breakdown'
  | 'coverage'
  | 'ioc_breakdown'
  | 'recent_intel'
  | 'recent_articles'
  | 'sector_targeting'
  | 'geo_targeting'
  | 'tactic_bar'
  | 'sync_status'

const WIDGET_LABELS: Record<WidgetKey, string> = {
  actor_breakdown: 'Actor Breakdown',
  coverage: 'Detection Coverage',
  ioc_breakdown: 'IoC Breakdown',
  recent_intel: 'Recent Intel',
  recent_articles: 'Recent Articles',
  sector_targeting: 'Sector Targeting',
  geo_targeting: 'Geography Targeting',
  tactic_bar: 'ATT&CK Tactics',
  sync_status: 'Feed Sync Status',
}

const DEFAULTS: Record<WidgetKey, boolean> = {
  actor_breakdown: true,
  coverage: true,
  ioc_breakdown: true,
  recent_intel: true,
  recent_articles: true,
  sector_targeting: true,
  geo_targeting: true,
  tactic_bar: true,
  sync_status: true,
}

const STORAGE_KEY = 'pythia-dashboard-widgets'

function loadWidgets(): Record<WidgetKey, boolean> {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored) return { ...DEFAULTS, ...(JSON.parse(stored) as Record<WidgetKey, boolean>) }
  } catch { /* ignore */ }
  return { ...DEFAULTS }
}

// ── Color maps ────────────────────────────────────────────────────────────────

const SPONSOR_COLORS: Record<string, string> = {
  'nation-state': '#7c3aed',
  'financially-motivated': '#f59e0b',
  'hacktivist': '#ef4444',
  'script-kiddie': '#6b7280',
  'unknown': '#4b5563',
}

const IOC_COLORS: Record<string, string> = {
  ip: '#06b6d4',
  domain: '#3b82f6',
  hash: '#8b5cf6',
  url: '#10b981',
  email: '#f59e0b',
  cve: '#f97316',
}

const TACTIC_ORDER = [
  'reconnaissance',
  'resource-development',
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'defense-evasion',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'command-and-control',
  'exfiltration',
  'impact',
]

const TACTIC_LABELS: Record<string, string> = {
  'reconnaissance': 'Recon',
  'resource-development': 'Resource Dev',
  'initial-access': 'Initial Access',
  'execution': 'Execution',
  'persistence': 'Persistence',
  'privilege-escalation': 'Priv. Esc.',
  'defense-evasion': 'Def. Evasion',
  'credential-access': 'Cred. Access',
  'discovery': 'Discovery',
  'lateral-movement': 'Lateral Mov.',
  'collection': 'Collection',
  'command-and-control': 'C2',
  'exfiltration': 'Exfiltration',
  'impact': 'Impact',
}

const SOURCE_LABELS: Record<string, string> = {
  attck: 'ATT&CK',
  misp_galaxy: 'MISP Galaxy',
  apt_sheet: 'APT Sheet',
  abuse_ch: 'Abuse.ch',
  ipsum: 'Ipsum',
  phishtank: 'PhishTank',
  malpedia: 'Malpedia',
  yara_rules: 'Yara Rules',
  icewater: 'IceWater',
  signature_base: 'Sig. Base',
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function sponsorColor(sponsor: string): string {
  return SPONSOR_COLORS[sponsor] ?? '#6b7280'
}

function iocColor(type: string): string {
  const norm =
    type.startsWith('hash') || type.includes('md5') || type.includes('sha') ? 'hash' : type
  return IOC_COLORS[norm] ?? '#6b7280'
}

function syncDotColor(status: string): string {
  if (status === 'success') return '#22c55e'
  if (status === 'failed') return '#ef4444'
  if (status === 'pending' || status === 'no_key') return '#f59e0b'
  return '#6b7280'
}

// ── Sub-components ────────────────────────────────────────────────────────────

function StatCard({
  label,
  value,
  to,
  icon: Icon,
}: {
  label: string
  value: string | number
  to?: string
  icon: LucideIcon
}) {
  const inner = (
    <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface p-5 transition-colors hover:border-[#3a3a5e]">
      <div className="mb-3">
        <div className="inline-flex rounded-lg bg-bg-elevated p-1.5">
          <Icon size={14} className="text-[#7c3aed]" />
        </div>
      </div>
      <p className="text-2xl font-semibold text-text-primary">{value}</p>
      <p className="mt-1 text-xs text-text-muted">{label}</p>
    </div>
  )
  return to ? <Link to={to}>{inner}</Link> : inner
}

function DonutChart({
  data,
  colorFn,
}: {
  data: { name: string; value: number }[]
  colorFn: (name: string) => string
}) {
  const filled = data.filter(d => d.value > 0)
  if (!filled.length) {
    return <div className="flex h-32 items-center justify-center text-xs text-text-muted">No data</div>
  }
  return (
    <div className="flex items-center gap-4">
      <div style={{ width: 120, height: 120, flexShrink: 0 }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={filled}
              cx="50%"
              cy="50%"
              innerRadius={35}
              outerRadius={54}
              dataKey="value"
              stroke="none"
            >
              {filled.map((entry, i) => (
                <Cell key={i} fill={colorFn(entry.name)} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{ background: '#13131f', border: '1px solid #2a2a3e', fontSize: 11 }}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
      <div className="min-w-0 flex-1 space-y-1.5">
        {filled.map(d => (
          <div key={d.name} className="flex items-center justify-between gap-2 text-xs">
            <div className="flex items-center gap-1.5 min-w-0">
              <span
                className="inline-block h-2 w-2 shrink-0 rounded-full"
                style={{ background: colorFn(d.name) }}
              />
              <span className="truncate text-text-muted capitalize">{d.name.replace(/-/g, ' ')}</span>
            </div>
            <span className="shrink-0 font-medium text-text-primary">{d.value.toLocaleString()}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function WidgetCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface p-5">
      <h2 className="mb-4 text-sm font-semibold text-text-primary">{title}</h2>
      {children}
    </div>
  )
}

function CustomizePanel({
  widgets,
  onToggle,
  onClose,
}: {
  widgets: Record<WidgetKey, boolean>
  onToggle: (key: WidgetKey) => void
  onClose: () => void
}) {
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose()
    }
    document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [onClose])

  return (
    <div
      ref={ref}
      className="absolute right-0 top-full z-50 mt-2 w-56 rounded-xl border border-[#2a2a3e] bg-bg-surface p-3 shadow-xl"
    >
      <p className="mb-2 text-xs font-semibold text-text-muted">Show / hide widgets</p>
      {(Object.keys(WIDGET_LABELS) as WidgetKey[]).map(key => (
        <button
          key={key}
          onClick={() => onToggle(key)}
          className="flex w-full items-center justify-between rounded-lg px-2 py-1.5 text-xs text-text-primary hover:bg-bg-elevated"
        >
          <span>{WIDGET_LABELS[key]}</span>
          {widgets[key] ? (
            <Eye size={13} className="text-[#06b6d4]" />
          ) : (
            <EyeOff size={13} className="text-text-muted" />
          )}
        </button>
      ))}
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

export function Dashboard() {
  const [widgets, setWidgets] = useState<Record<WidgetKey, boolean>>(loadWidgets)
  const [showCustomize, setShowCustomize] = useState(false)
  const [ingestOpen, setIngestOpen] = useState(false)
  const [ingestTab, setIngestTab] = useState<'url' | 'text'>('url')

  function openIngest(tab: 'url' | 'text') {
    setIngestTab(tab)
    setIngestOpen(true)
  }

  const { data: threats } = useThreats({ limit: 5 })
  const { data: coverage } = useCoverage(3)
  const { data: sectors } = useSectors()
  const { data: geos } = useGeographies()
  const { data: malware } = useMalwareFamilies({ limit: 1000 })
  const { data: summary } = useDashboardSummary()
  const { data: syncItems } = useSyncStatus()
  const { data: recentArticles } = useFeedArticles({ limit: 10 })

  function toggleWidget(key: WidgetKey) {
    setWidgets(prev => {
      const next = { ...prev, [key]: !prev[key] }
      localStorage.setItem(STORAGE_KEY, JSON.stringify(next))
      return next
    })
  }

  // Derived data for stat cards
  const actorTotal = summary
    ? Object.values(summary.actor_by_sponsor).reduce((a, b) => a + b, 0)
    : null
  const iocTotal = summary
    ? Object.values(summary.ioc_by_type).reduce((a, b) => a + b, 0)
    : null

  // Actor donut data
  const actorDonutData = Object.entries(summary?.actor_by_sponsor ?? {}).map(([name, value]) => ({
    name,
    value,
  }))

  // IoC donut data — normalize hash variants
  const iocAgg: Record<string, number> = {}
  Object.entries(summary?.ioc_by_type ?? {}).forEach(([type, count]) => {
    const norm =
      type.startsWith('hash') || type.includes('md5') || type.includes('sha') ? 'hash' : type
    iocAgg[norm] = (iocAgg[norm] ?? 0) + count
  })
  const iocDonutData = Object.entries(iocAgg).map(([name, value]) => ({ name, value }))

  // Coverage donut data
  const coverageDonutData = coverage
    ? [
        { name: 'Covered', value: coverage.covered_technique_count, color: '#22c55e' },
        { name: 'Uncovered', value: coverage.uncovered_count, color: '#2a2a3e' },
      ]
    : []

  // ATT&CK tactic bar data
  const tacticData = TACTIC_ORDER.map(t => ({
    tactic: TACTIC_LABELS[t] ?? t,
    count: summary?.ttp_by_tactic[t] ?? 0,
  }))

  // Sector + geo chart data
  const sectorRows = (sectors?.rows ?? []).slice(0, 10).map(r => ({
    name: r.sector,
    'Nation-state': r.nation_state_count,
    'Fin. motivated': r.financially_motivated_count,
    Hacktivist: r.hacktivist_count,
  }))
  const geoRows = (geos?.rows ?? []).slice(0, 12).map(r => ({
    name: r.sector,
    'Nation-state': r.nation_state_count,
    'Fin. motivated': r.financially_motivated_count,
    Hacktivist: r.hacktivist_count,
  }))

  const anyDonutVisible = widgets.actor_breakdown || widgets.coverage || widgets.ioc_breakdown

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="relative flex items-center justify-between">
        <h1 className="text-lg font-semibold text-text-primary">Intelligence Overview</h1>
        <button
          onClick={() => setShowCustomize(v => !v)}
          className="flex items-center gap-1.5 rounded-lg border border-[#2a2a3e] bg-bg-surface px-3 py-1.5 text-xs text-text-muted transition-colors hover:border-[#3a3a5e] hover:text-text-primary"
        >
          <SlidersHorizontal size={12} />
          Customize
        </button>
        {showCustomize && (
          <CustomizePanel
            widgets={widgets}
            onToggle={toggleWidget}
            onClose={() => setShowCustomize(false)}
          />
        )}
      </div>

      {/* Ingest hero */}
      <div className="rounded-xl border border-accent/30 bg-gradient-to-r from-accent/10 via-accent/5 to-transparent p-6">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-start gap-3">
            <div className="mt-0.5 rounded-lg bg-accent/20 p-2">
              <Zap size={16} className="text-accent-bright" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-text-primary">Analyze Threat Intelligence</h2>
              <p className="mt-1 text-xs text-text-muted">
                Paste a URL or raw text — Claude extracts IOCs, TTPs, threat actors, and malware families in seconds.
              </p>
            </div>
          </div>
          <div className="flex shrink-0 gap-2">
            <button
              onClick={() => openIngest('url')}
              className="flex items-center gap-2 rounded-lg bg-accent px-4 py-2 text-xs font-semibold text-white hover:opacity-90 transition-opacity"
            >
              <Link2 size={12} />
              Analyze URL
            </button>
            <button
              onClick={() => openIngest('text')}
              className="flex items-center gap-2 rounded-lg border border-[#2a2a3e] bg-bg-elevated px-4 py-2 text-xs font-medium text-text-primary hover:border-[#3a3a5e] hover:text-text-primary transition-colors"
            >
              <FileText size={12} />
              Paste Text
            </button>
          </div>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
        <StatCard
          label="Threat Actors"
          value={actorTotal ?? '—'}
          to="/actors"
          icon={Users}
        />
        <StatCard
          label="Techniques"
          value={summary?.technique_count ?? '—'}
          to="/ttps"
          icon={Shield}
        />
        <StatCard
          label="Intel Reports"
          value={threats?.length ?? '—'}
          to="/intel"
          icon={FileText}
        />
        <StatCard
          label="Detection Coverage"
          value={coverage ? `${coverage.coverage_pct}%` : '—'}
          to="/analytics"
          icon={ShieldCheck}
        />
        <StatCard
          label="Rules"
          value={coverage?.rule_count ?? '—'}
          to="/rules"
          icon={Code2}
        />
        <StatCard
          label="Malware Families"
          value={malware?.length ?? '—'}
          to="/malware"
          icon={Bug}
        />
      </div>

      {/* Donut row */}
      {anyDonutVisible && (
        <div className="grid gap-6 lg:grid-cols-3">
          {widgets.actor_breakdown && (
            <WidgetCard title="Actor Breakdown">
              <DonutChart
                data={actorDonutData}
                colorFn={sponsorColor}
              />
              {actorTotal !== null && (
                <p className="mt-3 text-xs text-text-muted">
                  {actorTotal.toLocaleString()} total actors
                </p>
              )}
            </WidgetCard>
          )}

          {widgets.coverage && (
            <WidgetCard title="Detection Coverage">
              {coverage ? (
                <>
                  <div className="flex items-center gap-6">
                    <div style={{ width: 120, height: 120, flexShrink: 0 }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={coverageDonutData}
                            cx="50%"
                            cy="50%"
                            innerRadius={35}
                            outerRadius={54}
                            dataKey="value"
                            stroke="none"
                          >
                            {coverageDonutData.map((entry, i) => (
                              <Cell key={i} fill={entry.color} />
                            ))}
                          </Pie>
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                    <div>
                      <p className="text-3xl font-semibold text-text-primary">
                        {coverage.coverage_pct}%
                      </p>
                      <p className="text-xs text-text-muted">
                        {coverage.covered_technique_count}/{coverage.observed_technique_count} techniques
                      </p>
                    </div>
                  </div>
                  {coverage.top_uncovered.length > 0 && (
                    <div className="mt-3 space-y-1">
                      <p className="text-xs font-medium text-text-muted">Top uncovered</p>
                      {coverage.top_uncovered.map(t => (
                        <Link
                          key={t.technique_id}
                          to={`/ttps/${t.technique_id}`}
                          className="flex items-center justify-between rounded p-1 text-xs hover:bg-bg-elevated"
                        >
                          <span className="font-mono text-purple-300">{t.technique_id}</span>
                          <span className="ml-2 flex-1 truncate text-text-muted">{t.name}</span>
                          <span className="shrink-0 text-text-muted">{t.actor_count}a</span>
                        </Link>
                      ))}
                    </div>
                  )}
                </>
              ) : (
                <div className="flex h-32 items-center justify-center text-xs text-text-muted">
                  No data
                </div>
              )}
            </WidgetCard>
          )}

          {widgets.ioc_breakdown && (
            <WidgetCard title="IoC Breakdown">
              <DonutChart data={iocDonutData} colorFn={iocColor} />
              {iocTotal !== null && (
                <p className="mt-3 text-xs text-text-muted">
                  {iocTotal.toLocaleString()} total indicators
                </p>
              )}
            </WidgetCard>
          )}
        </div>
      )}

      {/* Intel + Sector row */}
      {(widgets.recent_intel || widgets.sector_targeting) && (
        <div className="grid gap-6 lg:grid-cols-2 items-start">
          {widgets.recent_intel && (
            <WidgetCard title="Recent Intel">
              {threats && threats.length > 0 ? (
                <div className="space-y-1">
                  {threats.map(t => (
                    <Link
                      key={t.id}
                      to={`/intel/${t.id}`}
                      className="flex items-start justify-between gap-3 rounded-lg p-2 text-xs hover:bg-bg-elevated transition-colors"
                    >
                      <span className="flex-1 truncate text-text-primary">
                        {t.title ?? 'Untitled report'}
                      </span>
                      <div className="flex shrink-0 flex-col items-end gap-1">
                        <TlpBadge tlp={t.tlp} />
                        <span className="text-text-muted">{timeAgo(t.publication_date)}</span>
                        {t.ttps.length > 0 && (
                          <span className="rounded bg-bg-elevated px-1.5 py-0.5 font-mono text-[10px] text-text-muted">
                            {t.ttps.length} TTP{t.ttps.length !== 1 ? 's' : ''}
                          </span>
                        )}
                      </div>
                    </Link>
                  ))}
                  <Link
                    to="/intel"
                    className="block pt-2 text-xs text-accent-bright hover:underline"
                  >
                    → View all
                  </Link>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-8 text-center gap-3">
                  <p className="text-xs text-text-muted">No intel reports yet.</p>
                  <button
                    onClick={() => openIngest('url')}
                    className="flex items-center gap-2 rounded-lg bg-accent px-4 py-2 text-xs font-semibold text-white hover:opacity-90 transition-opacity"
                  >
                    <Zap size={12} />
                    Analyze your first report
                  </button>
                </div>
              )}
            </WidgetCard>
          )}

          {widgets.sector_targeting && sectorRows.length > 0 && (
            <WidgetCard title="Sector Targeting">
              <ResponsiveContainer width="100%" height={sectorRows.length * 44 + 40}>
                <BarChart data={sectorRows} layout="vertical" margin={{ left: 80 }}>
                  <XAxis type="number" tick={{ fill: '#6b6b8a', fontSize: 10 }} />
                  <YAxis
                    type="category"
                    dataKey="name"
                    tick={{ fill: '#e8e8f0', fontSize: 9 }}
                    width={80}
                  />
                  <Tooltip
                    contentStyle={{
                      background: '#13131f',
                      border: '1px solid #2a2a3e',
                      fontSize: 11,
                    }}
                  />
                  <Bar dataKey="Nation-state" stackId="a" fill="#7c3aed" barSize={18} />
                  <Bar dataKey="Fin. motivated" stackId="a" fill="#f59e0b" barSize={18} />
                  <Bar dataKey="Hacktivist" stackId="a" fill="#ef4444" barSize={18} />
                </BarChart>
              </ResponsiveContainer>
            </WidgetCard>
          )}
        </div>
      )}

      {/* Recent Articles */}
      {widgets.recent_articles && (
        <WidgetCard title="Recent Blogs & Articles">
          {recentArticles && recentArticles.length > 0 ? (
            <div className="space-y-1">
              {recentArticles.map(a => (
                <div
                  key={a.id}
                  className="flex items-center justify-between gap-3 rounded-lg p-2 text-xs hover:bg-bg-elevated transition-colors"
                >
                  <a
                    href={a.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex-1 truncate text-accent-bright hover:underline"
                  >
                    {a.title ?? a.url}
                  </a>
                  <div className="flex shrink-0 items-center gap-2">
                    <span className="rounded-full bg-[#1e1e2f] px-2 py-0.5 text-text-muted">
                      {a.source_name}
                    </span>
                    <span className="text-text-muted">{formatDate(a.published_at)}</span>
                  </div>
                </div>
              ))}
              <Link
                to="/articles"
                className="block pt-2 text-xs text-accent-bright hover:underline"
              >
                → View all
              </Link>
            </div>
          ) : (
            <p className="py-4 text-center text-xs text-text-muted">
              No articles yet — pull feeds from the Intel Feed page.
            </p>
          )}
        </WidgetCard>
      )}

      {/* Geography targeting */}
      {widgets.geo_targeting && geoRows.length > 0 && (
        <WidgetCard title="Geography Targeting">
          <ResponsiveContainer width="100%" height={Math.max(240, geoRows.length * 26)}>
            <BarChart data={geoRows} layout="vertical" margin={{ left: 110 }}>
              <XAxis type="number" tick={{ fill: '#6b6b8a', fontSize: 10 }} />
              <YAxis
                type="category"
                dataKey="name"
                tick={{ fill: '#e8e8f0', fontSize: 10 }}
                width={110}
              />
              <Tooltip
                contentStyle={{ background: '#13131f', border: '1px solid #2a2a3e', fontSize: 11 }}
              />
              <Bar dataKey="Nation-state" stackId="a" fill="#7c3aed" />
              <Bar dataKey="Fin. motivated" stackId="a" fill="#f59e0b" />
              <Bar dataKey="Hacktivist" stackId="a" fill="#ef4444" />
            </BarChart>
          </ResponsiveContainer>
        </WidgetCard>
      )}

      {/* ATT&CK tactic bar */}
      {widgets.tactic_bar && summary && (
        <WidgetCard title="ATT&CK Tactic Coverage">
          <ResponsiveContainer width="100%" height={360}>
            <BarChart data={tacticData} layout="vertical" margin={{ left: 90 }}>
              <XAxis type="number" tick={{ fill: '#6b6b8a', fontSize: 10 }} />
              <YAxis
                type="category"
                dataKey="tactic"
                tick={{ fill: '#e8e8f0', fontSize: 10 }}
                width={90}
              />
              <Tooltip
                contentStyle={{ background: '#13131f', border: '1px solid #2a2a3e', fontSize: 11 }}
                formatter={(v: number) => [v, 'techniques']}
              />
              <Bar dataKey="count" radius={[0, 3, 3, 0]}>
                {tacticData.map((_, i) => (
                  <Cell
                    key={i}
                    fill={`hsl(${262 + i * 6}, 70%, ${55 - i * 1.5}%)`}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </WidgetCard>
      )}

      {/* Feed sync status */}
      {widgets.sync_status && syncItems && syncItems.length > 0 && (
        <WidgetCard title="Feed Sync Status">
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 md:grid-cols-5">
            {syncItems.map(item => (
              <div
                key={item.source}
                className="rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2"
              >
                <div className="flex items-center gap-1.5">
                  <span
                    className="inline-block h-2 w-2 shrink-0 rounded-full"
                    style={{ background: syncDotColor(item.status) }}
                  />
                  <span className="truncate font-mono text-xs font-medium text-text-primary">
                    {SOURCE_LABELS[item.source] ?? item.source}
                  </span>
                </div>
                <p className="mt-1 text-[10px] text-text-muted">
                  {item.last_run ? timeAgo(item.last_run) : 'never'}
                </p>
              </div>
            ))}
          </div>
        </WidgetCard>
      )}

      <IngestBar open={ingestOpen} onClose={() => setIngestOpen(false)} defaultTab={ingestTab} />
    </div>
  )
}
