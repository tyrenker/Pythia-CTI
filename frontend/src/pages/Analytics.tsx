import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Info, ShieldCheck, TrendingUp, Users, Zap } from 'lucide-react'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts'
import { useCoverage, useSectors, useDashboardSummary } from '@/api/analytics'
import { PageHeader } from '@/components/shared/PageHeader'
import { StatStrip } from '@/components/shared/StatStrip'

export function Analytics() {
  const { data: coverage, isLoading: covLoading } = useCoverage(20)
  const { data: summary, isLoading: summaryLoading } = useDashboardSummary()
  const [sponsorType, setSponsorType] = useState('')
  const [country, setCountry] = useState('')
  const { data: sectors } = useSectors(sponsorType || undefined, country || undefined)

  const totalActors = summary
    ? Object.values(summary.actor_by_sponsor).reduce((a, b) => a + b, 0)
    : 0
  const nationStatePct = totalActors
    ? Math.round(((summary?.actor_by_sponsor['nation-state'] ?? 0) / totalActors) * 100)
    : 0

  const topSector = (sectors?.rows ?? [])[0]?.sector ?? '—'

  const uncoveredData = (coverage?.top_uncovered ?? []).map(t => ({
    id: t.technique_id,
    name: t.name ?? t.technique_id,
    actors: t.actor_count,
  }))

  const coveredData = (coverage?.top_covered ?? []).map(t => ({
    id: t.technique_id,
    name: t.name ?? t.technique_id,
    actors: t.actor_count,
  }))

  const sectorData = (sectors?.rows ?? []).map(r => ({
    name: r.sector,
    'Nation-state': r.nation_state_count,
    'Fin. motivated': r.financially_motivated_count,
    Hacktivist: r.hacktivist_count,
    total: r.actor_count,
    top: r.top_actors,
  }))

  const stats = [
    {
      label: 'Detection Coverage',
      value: coverage ? `${coverage.coverage_pct}%` : '—',
      color: coverage && coverage.coverage_pct >= 70 ? 'text-green-400' : 'text-amber-400',
      icon: ShieldCheck,
    },
    {
      label: 'Coverage Gaps',
      value: coverage?.uncovered_count ?? '—',
      color: 'text-red-400',
      icon: Zap,
    },
    {
      label: 'Top Targeted Sector',
      value: topSector,
      color: 'text-cyan-400',
      icon: TrendingUp,
    },
    {
      label: 'Nation-State Actors',
      value: nationStatePct > 0 ? `${nationStatePct}%` : '—',
      color: 'text-purple-400',
      icon: Users,
    },
  ]

  return (
    <div className="space-y-8">
      <PageHeader
        title="Analytics"
        description="Coverage gaps, technique frequency, and sector targeting trends across your threat actor database."
      />

      <StatStrip stats={stats} loading={covLoading || summaryLoading} />

      {/* Coverage gap */}
      <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface p-6">
        <div className="mb-4 flex items-start justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-text-primary">Detection Coverage Gap</h2>
            <p className="mt-0.5 text-xs text-text-muted">
              Techniques observed in actor profiles vs. techniques with at least one detection rule.
            </p>
          </div>
          <span title="Only ATT&CK techniques attributed to tracked actors are counted in coverage scope.">
            <Info size={14} className="mt-0.5 shrink-0 text-text-muted cursor-help" />
          </span>
        </div>

        {covLoading ? (
          <div className="h-48 animate-pulse rounded bg-bg-elevated" />
        ) : coverage ? (
          <>
            <div className="mb-6 flex items-center gap-5">
              <div className="relative flex h-24 w-24 shrink-0 items-center justify-center">
                <svg viewBox="0 0 36 36" className="-rotate-90 h-24 w-24">
                  <circle cx="18" cy="18" r="15.9" fill="none" stroke="#1a1a2e" strokeWidth="3" />
                  <circle
                    cx="18"
                    cy="18"
                    r="15.9"
                    fill="none"
                    stroke={coverage.coverage_pct >= 70 ? '#22c55e' : '#f59e0b'}
                    strokeWidth="3"
                    strokeDasharray={`${coverage.coverage_pct} ${100 - coverage.coverage_pct}`}
                    strokeLinecap="round"
                  />
                </svg>
                <span className="absolute text-lg font-bold text-text-primary">
                  {coverage.coverage_pct}%
                </span>
              </div>
              <div>
                <p className="text-sm font-medium text-text-primary">
                  {coverage.covered_technique_count.toLocaleString()} of{' '}
                  {coverage.observed_technique_count.toLocaleString()} techniques covered
                </p>
                <p className="mt-1 text-xs text-text-muted">
                  {coverage.uncovered_count.toLocaleString()} gap{coverage.uncovered_count !== 1 ? 's' : ''} — techniques used by tracked actors but with no detection rule
                </p>
                <p className="mt-0.5 text-xs text-text-muted">
                  {coverage.rule_count.toLocaleString()} total rules in system
                </p>
              </div>
            </div>

            <div className="grid gap-6 lg:grid-cols-2">
              <div>
                <h3 className="mb-3 text-xs font-semibold text-red-400">
                  Top Uncovered (gap priority)
                </h3>
                <ResponsiveContainer width="100%" height={320}>
                  <BarChart data={uncoveredData} layout="vertical" margin={{ left: 90 }}>
                    <XAxis type="number" tick={{ fill: '#6b6b8a', fontSize: 10 }} />
                    <YAxis
                      type="category"
                      dataKey="id"
                      tick={{ fill: '#e8e8f0', fontSize: 9, fontFamily: 'monospace' }}
                      width={90}
                    />
                    <Tooltip
                      formatter={(v, _n, p) => [v, p.payload.name]}
                      contentStyle={{ background: '#13131f', border: '1px solid #2a2a3e', fontSize: 11 }}
                    />
                    <Bar dataKey="actors" radius={[0, 3, 3, 0]}>
                      {uncoveredData.map((_, i) => (
                        <Cell key={i} fill="#ef4444" />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
                <div className="mt-2 space-y-1">
                  {uncoveredData.slice(0, 5).map(t => (
                    <Link key={t.id} to={`/ttps/${t.id}`} className="block text-xs text-accent-bright hover:underline">
                      {t.id} — {t.name}
                    </Link>
                  ))}
                </div>
              </div>

              <div>
                <h3 className="mb-3 text-xs font-semibold text-green-400">Top Covered</h3>
                <ResponsiveContainer width="100%" height={320}>
                  <BarChart data={coveredData} layout="vertical" margin={{ left: 90 }}>
                    <XAxis type="number" tick={{ fill: '#6b6b8a', fontSize: 10 }} />
                    <YAxis
                      type="category"
                      dataKey="id"
                      tick={{ fill: '#e8e8f0', fontSize: 9, fontFamily: 'monospace' }}
                      width={90}
                    />
                    <Tooltip
                      formatter={(v, _n, p) => [v, p.payload.name]}
                      contentStyle={{ background: '#13131f', border: '1px solid #2a2a3e', fontSize: 11 }}
                    />
                    <Bar dataKey="actors" radius={[0, 3, 3, 0]}>
                      {coveredData.map((_, i) => (
                        <Cell key={i} fill="#22c55e" />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
                <div className="mt-2 space-y-1">
                  {coveredData.slice(0, 5).map(t => (
                    <Link key={t.id} to={`/ttps/${t.id}`} className="block text-xs text-text-muted hover:text-accent-bright hover:underline transition-colors">
                      {t.id} — {t.name}
                    </Link>
                  ))}
                </div>
              </div>
            </div>
          </>
        ) : null}
      </div>

      {/* Sector heatmap */}
      <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface p-6">
        <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-text-primary">Sector Targeting</h2>
            <p className="mt-0.5 text-xs text-text-muted">
              Industries most targeted by tracked threat actors, segmented by sponsor type.
            </p>
          </div>
          <div className="flex gap-3">
            <select
              value={sponsorType}
              onChange={e => setSponsorType(e.target.value)}
              className="rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-1.5 text-xs text-text-primary focus:outline-none"
            >
              <option value="">All sponsor types</option>
              <option value="nation-state">Nation-state</option>
              <option value="financially-motivated">Financially motivated</option>
              <option value="hacktivist">Hacktivist</option>
            </select>
            <input
              value={country}
              onChange={e => setCountry(e.target.value.toUpperCase())}
              placeholder="Country (US, RU...)"
              maxLength={2}
              className="w-28 rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-1.5 text-xs text-text-primary focus:outline-none"
            />
          </div>
        </div>

        {sectorData.length > 0 ? (
          <>
            <ResponsiveContainer width="100%" height={Math.max(240, sectorData.length * 28)}>
              <BarChart data={sectorData} layout="vertical" margin={{ left: 100 }}>
                <XAxis type="number" tick={{ fill: '#6b6b8a', fontSize: 10 }} />
                <YAxis
                  type="category"
                  dataKey="name"
                  tick={{ fill: '#e8e8f0', fontSize: 10 }}
                  width={100}
                />
                <Tooltip
                  content={({ active, payload }) => {
                    if (!active || !payload?.length) return null
                    const d = payload[0].payload
                    return (
                      <div className="rounded border border-[#2a2a3e] bg-[#13131f] p-2 text-xs">
                        <p className="font-semibold">{d.name}</p>
                        <p>Total: {d.total}</p>
                        {d.top.slice(0, 3).map((a: string) => (
                          <p key={a} className="text-text-muted">• {a}</p>
                        ))}
                      </div>
                    )
                  }}
                />
                <Bar dataKey="Nation-state" stackId="a" fill="#7c3aed" />
                <Bar dataKey="Fin. motivated" stackId="a" fill="#f59e0b" />
                <Bar dataKey="Hacktivist" stackId="a" fill="#ef4444" />
              </BarChart>
            </ResponsiveContainer>
            <div className="mt-3 flex items-center gap-4">
              {[
                { label: 'Nation-state', color: 'bg-[#7c3aed]' },
                { label: 'Fin. motivated', color: 'bg-[#f59e0b]' },
                { label: 'Hacktivist', color: 'bg-[#ef4444]' },
              ].map(l => (
                <div key={l.label} className="flex items-center gap-1.5 text-xs text-text-muted">
                  <span className={`h-2.5 w-2.5 rounded-sm ${l.color}`} />
                  {l.label}
                </div>
              ))}
            </div>
          </>
        ) : (
          <p className="text-xs text-text-muted">No sector data available.</p>
        )}
      </div>
    </div>
  )
}
