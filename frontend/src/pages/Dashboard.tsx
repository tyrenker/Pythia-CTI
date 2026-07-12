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
  'nation-state': '#ff00ff',
  'financially-motivated': '#f59e0b',
  'hacktivist': '#ff3366',
  'script-kiddie': '#6b7280',
  'unknown': '#4b5563',
}

const IOC_COLORS: Record<string, string> = {
  ip: '#00ff88',
  domain: '#00ff88',
  hash: '#ff00ff',
  url: '#f59e0b',
  email: '#f97316',
  cve: '#ff3366',
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

const TACTIC_COLORS = [
  '#00ff88', '#00eea0', '#00ddb8', '#00ccd0', '#00bbec', '#00aaff',
  '#2299ff', '#4488ff', '#6677ef', '#8866df', '#aa55cf', '#cc44bf',
  '#ee33af', '#ff00ff',
]

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
  if (status === 'success') return '#00ff88'
  if (status === 'failed') return '#ff3366'
  if (status === 'pending' || status === 'no_key') return '#f59e0b'
  return '#6b7280'
}

const CHART_TOOLTIP_STYLE = {
  background: '#12121a',
  border: '1px solid #2a2a3a',
  fontSize: 10,
  fontFamily: 'JetBrains Mono, monospace',
  color: '#e0e0e0',
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
    <div className="border border-[#2a2a3a] bg-[#12121a] p-5 transition-all duration-200 hover:border-[#00ff88]/40 hover:shadow-[0_0_15px_rgba(0,255,136,0.07)] hover:-translate-y-px corner-deco">
      <div className="mb-3">
        <div className="inline-flex border border-[#00ff88]/20 bg-[#00ff88]/5 p-1.5">
          <Icon size={13} className="text-[#00ff88]" strokeWidth={1.5} />
        </div>
      </div>
      <p className="font-mono text-2xl font-bold tabular-nums text-[#e0e0e0]">{value}</p>
      <p className="mt-1 font-mono text-[10px] uppercase tracking-[0.12em] text-[#6b7280]">{label}</p>
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
    return <div className="flex h-32 items-center justify-center font-mono text-[10px] uppercase tracking-widest text-[#6b7280]">[ NULL ]</div>
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
            <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
          </PieChart>
        </ResponsiveContainer>
      </div>
      <div className="min-w-0 flex-1 space-y-1.5">
        {filled.map(d => (
          <div key={d.name} className="flex items-center justify-between gap-2 text-xs">
            <div className="flex items-center gap-1.5 min-w-0">
              <span
                className="inline-block h-1.5 w-1.5 shrink-0"
                style={{ background: colorFn(d.name) }}
              />
              <span className="truncate font-mono text-[10px] text-[#6b7280] capitalize">
                {d.name.replace(/-/g, ' ')}
              </span>
            </div>
            <span className="shrink-0 font-mono text-[10px] font-medium text-[#e0e0e0]">
              {d.value.toLocaleString()}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

function WidgetCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="border border-[#2a2a3a] bg-[#12121a] p-5">
      <div className="mb-4 flex items-center gap-2">
        <span className="font-mono text-[9px] text-[#00ff88]/40 select-none">{'// '}</span>
        <h2 className="font-mono text-[10px] uppercase tracking-[0.15em] text-[#00ff88]/80">{title}</h2>
      </div>
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
      className="absolute right-0 top-full z-50 mt-1 w-56 border border-[#2a2a3a] bg-[#0a0a0f] p-3 shadow-[0_0_20px_rgba(0,0,0,0.6)]"
    >
      <p className="mb-2 font-mono text-[9px] uppercase tracking-[0.15em] text-[#6b7280]">
        {'// '} WIDGET_VISIBILITY
      </p>
      {(Object.keys(WIDGET_LABELS) as WidgetKey[]).map(key => (
        <button
          key={key}
          onClick={() => onToggle(key)}
          className="flex w-full items-center justify-between px-2 py-1.5 font-mono text-[10px] text-[#e0e0e0] transition-colors hover:bg-[#00ff88]/5 hover:text-[#00ff88]"
        >
          <span>{WIDGET_LABELS[key]}</span>
          {widgets[key] ? (
            <Eye size={12} className="text-[#00ff88]" strokeWidth={1.5} />
          ) : (
            <EyeOff size={12} className="text-[#6b7280]" strokeWidth={1.5} />
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
        { name: 'Covered', value: coverage.covered_technique_count, color: '#00ff88' },
        { name: 'Uncovered', value: coverage.uncovered_count, color: '#2a2a3a' },
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
        <div className="flex items-center gap-2">
          <span className="font-mono text-xs text-[#00ff88]/50 select-none">{'// '}</span>
          <h1 className="font-display text-lg font-bold uppercase tracking-widest text-[#e0e0e0]">
            Intelligence Overview
          </h1>
          <span className="font-mono text-xs text-[#00ff88]/30 animate-blink">_</span>
        </div>
        <button
          onClick={() => setShowCustomize(v => !v)}
          className="flex items-center gap-1.5 border border-[#2a2a3a] bg-[#12121a] px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider text-[#6b7280] transition-all hover:border-[#00ff88]/40 hover:text-[#00ff88]"
        >
          <SlidersHorizontal size={11} strokeWidth={1.5} />
          CUSTOMIZE
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
      <div className="border border-[#00ff88]/20 bg-[#00ff88]/[0.03] p-6 relative overflow-hidden">
        {/* Corner accents */}
        <div className="absolute top-0 left-0 w-3 h-3 border-t border-l border-[#00ff88]/60" />
        <div className="absolute top-0 right-0 w-3 h-3 border-t border-r border-[#00ff88]/60" />
        <div className="absolute bottom-0 left-0 w-3 h-3 border-b border-l border-[#00ff88]/60" />
        <div className="absolute bottom-0 right-0 w-3 h-3 border-b border-r border-[#00ff88]/60" />

        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-start gap-3">
            <div className="mt-0.5 border border-[#00ff88]/30 bg-[#00ff88]/10 p-2">
              <Zap size={14} className="text-[#00ff88]" strokeWidth={2} />
            </div>
            <div>
              <h2 className="font-mono text-xs font-bold uppercase tracking-[0.1em] text-[#e0e0e0]">
                Analyze Threat Intelligence
              </h2>
              <p className="mt-1 font-mono text-[11px] text-[#6b7280] leading-relaxed">
                Paste a URL or raw text — Claude extracts IOCs, TTPs, threat actors, and malware families in seconds.
              </p>
            </div>
          </div>
          <div className="flex shrink-0 gap-2">
            <button
              onClick={() => openIngest('url')}
              className="flex items-center gap-2 bg-[#00ff88] px-4 py-2 font-mono text-[10px] font-bold uppercase tracking-wider text-[#0a0a0f] cyber-chamfer-sm transition-all hover:shadow-[0_0_15px_rgba(0,255,136,0.4)] active:scale-[0.98]"
            >
              <Link2 size={11} strokeWidth={2} />
              ANALYZE URL
            </button>
            <button
              onClick={() => openIngest('text')}
              className="flex items-center gap-2 border border-[#2a2a3a] bg-[#12121a] px-4 py-2 font-mono text-[10px] font-medium uppercase tracking-wider text-[#6b7280] transition-all hover:border-[#00ff88]/40 hover:text-[#e0e0e0]"
            >
              <FileText size={11} strokeWidth={1.5} />
              PASTE TEXT
            </button>
          </div>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <StatCard label="Threat Actors" value={actorTotal ?? '—'} to="/actors" icon={Users} />
        <StatCard label="Techniques" value={summary?.technique_count ?? '—'} to="/ttps" icon={Shield} />
        <StatCard label="Intel Reports" value={threats?.length ?? '—'} to="/intel" icon={FileText} />
        <StatCard label="Det. Coverage" value={coverage ? `${coverage.coverage_pct}%` : '—'} to="/analytics" icon={ShieldCheck} />
        <StatCard label="Rules" value={coverage?.rule_count ?? '—'} to="/rules" icon={Code2} />
        <StatCard label="Malware Fam." value={malware?.length ?? '—'} to="/malware" icon={Bug} />
      </div>

      {/* Donut row */}
      {anyDonutVisible && (
        <div className="grid gap-5 lg:grid-cols-3">
          {widgets.actor_breakdown && (
            <WidgetCard title="Actor Breakdown">
              <DonutChart data={actorDonutData} colorFn={sponsorColor} />
              {actorTotal !== null && (
                <p className="mt-3 font-mono text-[10px] text-[#6b7280]">
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
                      <p className="font-mono text-3xl font-bold tabular-nums text-[#e0e0e0]">
                        {coverage.coverage_pct}%
                      </p>
                      <p className="font-mono text-[10px] text-[#6b7280]">
                        {coverage.covered_technique_count}/{coverage.observed_technique_count} techniques
                      </p>
                    </div>
                  </div>
                  {coverage.top_uncovered.length > 0 && (
                    <div className="mt-3 space-y-0.5">
                      <p className="font-mono text-[9px] uppercase tracking-widest text-[#6b7280] mb-1">
                        Top uncovered
                      </p>
                      {coverage.top_uncovered.map(t => (
                        <Link
                          key={t.technique_id}
                          to={`/ttps/${t.technique_id}`}
                          className="flex items-center justify-between p-1 font-mono text-[10px] transition-colors hover:bg-[#00ff88]/[0.04]"
                        >
                          <span className="text-[#ff00ff]">{t.technique_id}</span>
                          <span className="ml-2 flex-1 truncate text-[#6b7280]">{t.name}</span>
                          <span className="shrink-0 text-[#6b7280]">{t.actor_count}a</span>
                        </Link>
                      ))}
                    </div>
                  )}
                </>
              ) : (
                <div className="flex h-32 items-center justify-center font-mono text-[10px] uppercase tracking-widest text-[#6b7280]">
                  [ NULL ]
                </div>
              )}
            </WidgetCard>
          )}

          {widgets.ioc_breakdown && (
            <WidgetCard title="IoC Breakdown">
              <DonutChart data={iocDonutData} colorFn={iocColor} />
              {iocTotal !== null && (
                <p className="mt-3 font-mono text-[10px] text-[#6b7280]">
                  {iocTotal.toLocaleString()} total indicators
                </p>
              )}
            </WidgetCard>
          )}
        </div>
      )}

      {/* Intel + Sector row */}
      {(widgets.recent_intel || widgets.sector_targeting) && (
        <div className="grid gap-5 lg:grid-cols-2 items-start">
          {widgets.recent_intel && (
            <WidgetCard title="Recent Intel">
              {threats && threats.length > 0 ? (
                <div className="space-y-0.5">
                  {threats.map(t => (
                    <Link
                      key={t.id}
                      to={`/intel/${t.id}`}
                      className="flex items-start justify-between gap-3 p-2 font-mono text-[10px] transition-colors hover:bg-[#00ff88]/[0.03]"
                    >
                      <span className="flex-1 truncate text-[#e0e0e0]">
                        {t.title ?? 'Untitled report'}
                      </span>
                      <div className="flex shrink-0 flex-col items-end gap-1">
                        <TlpBadge tlp={t.tlp} />
                        <span className="text-[#6b7280]">{timeAgo(t.publication_date)}</span>
                        {t.ttps.length > 0 && (
                          <span className="border border-[#2a2a3a] px-1.5 py-0.5 font-mono text-[9px] text-[#6b7280]">
                            {t.ttps.length} TTP{t.ttps.length !== 1 ? 's' : ''}
                          </span>
                        )}
                      </div>
                    </Link>
                  ))}
                  <Link
                    to="/intel"
                    className="block pt-2 font-mono text-[10px] text-[#00ff88] hover:text-[#00ff88] transition-colors"
                  >
                    {'>> VIEW_ALL'}
                  </Link>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-8 text-center gap-3">
                  <p className="font-mono text-[10px] uppercase tracking-widest text-[#6b7280]">No intel reports yet.</p>
                  <button
                    onClick={() => openIngest('url')}
                    className="flex items-center gap-2 bg-[#00ff88] px-4 py-2 font-mono text-[10px] font-bold uppercase tracking-wider text-[#0a0a0f] cyber-chamfer-sm hover:shadow-[0_0_15px_rgba(0,255,136,0.4)]"
                  >
                    <Zap size={11} strokeWidth={2} />
                    ANALYZE FIRST REPORT
                  </button>
                </div>
              )}
            </WidgetCard>
          )}

          {widgets.sector_targeting && sectorRows.length > 0 && (
            <WidgetCard title="Sector Targeting">
              <ResponsiveContainer width="100%" height={sectorRows.length * 44 + 40}>
                <BarChart data={sectorRows} layout="vertical" margin={{ left: 80 }}>
                  <XAxis type="number" tick={{ fill: '#6b7280', fontSize: 9, fontFamily: 'JetBrains Mono' }} />
                  <YAxis
                    type="category"
                    dataKey="name"
                    tick={{ fill: '#e0e0e0', fontSize: 8, fontFamily: 'JetBrains Mono' }}
                    width={80}
                  />
                  <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                  <Bar dataKey="Nation-state" stackId="a" fill="#ff00ff" barSize={16} />
                  <Bar dataKey="Fin. motivated" stackId="a" fill="#f59e0b" barSize={16} />
                  <Bar dataKey="Hacktivist" stackId="a" fill="#ff3366" barSize={16} />
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
            <div className="space-y-0.5">
              {recentArticles.map(a => (
                <div
                  key={a.id}
                  className="flex items-center justify-between gap-3 p-2 font-mono text-[10px] transition-colors hover:bg-[#00ff88]/[0.03]"
                >
                  <a
                    href={a.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex-1 truncate text-[#00ff88] hover:text-[#00ff88] transition-colors"
                  >
                    {a.title ?? a.url}
                  </a>
                  <div className="flex shrink-0 items-center gap-2">
                    <span className="border border-[#2a2a3a] px-1.5 py-0.5 text-[#6b7280]">
                      {a.source_name}
                    </span>
                    <span className="text-[#6b7280]">{formatDate(a.published_at)}</span>
                  </div>
                </div>
              ))}
              <Link
                to="/articles"
                className="block pt-2 font-mono text-[10px] text-[#00ff88] hover:text-[#00ff88] transition-colors"
              >
                {'>> VIEW_ALL'}
              </Link>
            </div>
          ) : (
            <p className="py-4 text-center font-mono text-[10px] uppercase tracking-widest text-[#6b7280]">
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
              <XAxis type="number" tick={{ fill: '#6b7280', fontSize: 9, fontFamily: 'JetBrains Mono' }} />
              <YAxis
                type="category"
                dataKey="name"
                tick={{ fill: '#e0e0e0', fontSize: 9, fontFamily: 'JetBrains Mono' }}
                width={110}
              />
              <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
              <Bar dataKey="Nation-state" stackId="a" fill="#ff00ff" />
              <Bar dataKey="Fin. motivated" stackId="a" fill="#f59e0b" />
              <Bar dataKey="Hacktivist" stackId="a" fill="#ff3366" />
            </BarChart>
          </ResponsiveContainer>
        </WidgetCard>
      )}

      {/* ATT&CK tactic bar */}
      {widgets.tactic_bar && summary && (
        <WidgetCard title="ATT&CK Tactic Coverage">
          <ResponsiveContainer width="100%" height={360}>
            <BarChart data={tacticData} layout="vertical" margin={{ left: 90 }}>
              <XAxis type="number" tick={{ fill: '#6b7280', fontSize: 9, fontFamily: 'JetBrains Mono' }} />
              <YAxis
                type="category"
                dataKey="tactic"
                tick={{ fill: '#e0e0e0', fontSize: 9, fontFamily: 'JetBrains Mono' }}
                width={90}
              />
              <Tooltip
                contentStyle={CHART_TOOLTIP_STYLE}
                formatter={(v: number) => [v, 'techniques']}
              />
              <Bar dataKey="count" radius={[0, 0, 0, 0]}>
                {tacticData.map((_, i) => (
                  <Cell key={i} fill={TACTIC_COLORS[i % TACTIC_COLORS.length]} />
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
                className="border border-[#2a2a3a] bg-[#1c1c2e] px-3 py-2"
              >
                <div className="flex items-center gap-1.5">
                  <span
                    className="inline-block h-1.5 w-1.5 shrink-0"
                    style={{ background: syncDotColor(item.status), boxShadow: `0 0 4px ${syncDotColor(item.status)}` }}
                  />
                  <span className="truncate font-mono text-[10px] font-medium text-[#e0e0e0]">
                    {SOURCE_LABELS[item.source] ?? item.source}
                  </span>
                </div>
                <p className="mt-1 font-mono text-[9px] text-[#6b7280]">
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
