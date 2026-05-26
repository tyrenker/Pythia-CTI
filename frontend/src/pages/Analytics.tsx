import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts'
import { useCoverage, useSectors } from '@/api/analytics'

export function Analytics() {
  const { data: coverage, isLoading: covLoading } = useCoverage(20)
  const [sponsorType, setSponsorType] = useState('')
  const [country, setCountry] = useState('')
  const { data: sectors } = useSectors(sponsorType || undefined, country || undefined)

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

  return (
    <div className="space-y-8">
      <h1 className="text-lg font-semibold text-text-primary">Analytics</h1>

      {/* Coverage gap */}
      <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface p-6">
        <h2 className="mb-2 text-sm font-semibold text-text-primary">Detection Coverage Gap</h2>
        {covLoading ? (
          <div className="h-48 animate-pulse rounded bg-bg-elevated" />
        ) : coverage ? (
          <>
            <div className="mb-4 flex items-center gap-4">
              <span className="text-3xl font-semibold text-text-primary">{coverage.coverage_pct}%</span>
              <div>
                <div className="h-2 w-64 overflow-hidden rounded-full bg-bg-elevated">
                  <div
                    className="h-full rounded-full bg-green-500 transition-all"
                    style={{ width: `${coverage.coverage_pct}%` }}
                  />
                </div>
                <p className="mt-1 text-xs text-text-muted">
                  {coverage.covered_technique_count} / {coverage.observed_technique_count} techniques with detection rules
                </p>
              </div>
            </div>

            <div className="grid gap-6 lg:grid-cols-2">
              <div>
                <h3 className="mb-3 text-xs font-semibold text-red-400">Top Uncovered (gap priority)</h3>
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
              </div>
            </div>
          </>
        ) : null}
      </div>

      {/* Sector heatmap */}
      <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface p-6">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <h2 className="text-sm font-semibold text-text-primary">Sector Targeting</h2>
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
        ) : (
          <p className="text-xs text-text-muted">No sector data available.</p>
        )}
      </div>
    </div>
  )
}
