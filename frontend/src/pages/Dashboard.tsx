import { Link } from 'react-router-dom'
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'
import { useThreats } from '@/api/threats'
import { useActors } from '@/api/actors'
import { useTTPs } from '@/api/ttps'
import { useCoverage, useSectors } from '@/api/analytics'
import { useMalwareFamilies } from '@/api/malware'
import { TlpBadge } from '@/components/shared/TlpBadge'
import { timeAgo } from '@/lib/utils'

function StatCard({ label, value, to }: { label: string; value: string | number; to?: string }) {
  const inner = (
    <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface p-5">
      <p className="text-2xl font-semibold text-text-primary">{value}</p>
      <p className="mt-1 text-xs text-text-muted">{label}</p>
    </div>
  )
  return to ? <Link to={to}>{inner}</Link> : inner
}

export function Dashboard() {
  const { data: threats } = useThreats({ limit: 5 })
  const { data: actors } = useActors({ limit: 1 })
  const { data: ttps } = useTTPs({ limit: 1 })
  const { data: coverage } = useCoverage(3)
  const { data: sectors } = useSectors()
  // TODO: replace with a count endpoint
  const { data: malwareFamilies } = useMalwareFamilies({ limit: 500 })

  const pieData = coverage
    ? [
        { name: 'Covered', value: coverage.covered_technique_count, color: '#22c55e' },
        { name: 'Uncovered', value: coverage.uncovered_count, color: '#2a2a3e' },
      ]
    : []

  const sectorRows = sectors?.rows.slice(0, 8).map(r => ({
    name: r.sector,
    'Nation-state': r.nation_state_count,
    'Fin. motivated': r.financially_motivated_count,
    Hacktivist: r.hacktivist_count,
  })) ?? []

  return (
    <div className="space-y-6">
      {/* Stat cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
        <StatCard label="Threat Actors" value={actors?.length ?? '—'} to="/actors" />
        <StatCard label="Techniques" value={ttps?.length ?? '—'} to="/ttps" />
        <StatCard label="Intel Reports" value={threats?.length ?? '—'} to="/intel" />
        <StatCard
          label="Detection Coverage"
          value={coverage ? `${coverage.coverage_pct}%` : '—'}
          to="/analytics"
        />
        <StatCard label="Rules" value={coverage?.rule_count ?? '—'} to="/rules" />
        <StatCard label="Malware Families" value={malwareFamilies?.length ?? '—'} to="/malware" />
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Recent Intel */}
        <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface p-5">
          <h2 className="mb-4 text-sm font-semibold text-text-primary">Recent Intel</h2>
          {threats && threats.length > 0 ? (
            <div className="space-y-2">
              {threats.map(t => (
                <Link
                  key={t.id}
                  to={`/intel/${t.id}`}
                  className="flex items-center justify-between rounded-lg p-2 hover:bg-bg-elevated transition-colors"
                >
                  <span className="flex-1 truncate text-xs text-text-primary">
                    {t.title ?? 'Untitled report'}
                  </span>
                  <div className="ml-3 flex shrink-0 items-center gap-2">
                    <TlpBadge tlp={t.tlp} />
                    <span className="text-xs text-text-muted">
                      {timeAgo(t.publication_date)}
                    </span>
                  </div>
                </Link>
              ))}
              <Link to="/intel" className="block pt-2 text-xs text-accent-bright hover:underline">
                → View all
              </Link>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-8 text-center">
              <p className="text-xs text-text-muted">No intel reports yet.</p>
              <p className="mt-1 text-xs text-text-muted">
                Paste a URL to ingest your first intel report.
              </p>
            </div>
          )}
        </div>

        {/* Coverage donut */}
        <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface p-5">
          <h2 className="mb-4 text-sm font-semibold text-text-primary">Detection Coverage</h2>
          {coverage && (
            <>
              <div className="flex items-center gap-6">
                <div style={{ width: 120, height: 120 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={pieData}
                        cx="50%"
                        cy="50%"
                        innerRadius={35}
                        outerRadius={55}
                        dataKey="value"
                        stroke="none"
                      >
                        {pieData.map((entry, i) => (
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
              <h3 className="mt-4 text-xs font-medium text-text-muted">Top uncovered</h3>
              <div className="mt-2 space-y-1">
                {coverage.top_uncovered.map(t => (
                  <Link
                    key={t.technique_id}
                    to={`/ttps/${t.technique_id}`}
                    className="flex items-center justify-between rounded p-1 hover:bg-bg-elevated text-xs"
                  >
                    <span className="font-mono text-purple-300">{t.technique_id}</span>
                    <span className="text-text-muted">{t.name}</span>
                    <span className="text-text-muted">{t.actor_count} actors</span>
                  </Link>
                ))}
              </div>
            </>
          )}
        </div>
      </div>

      {/* Sector bar */}
      {sectorRows.length > 0 && (
        <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface p-5">
          <h2 className="mb-4 text-sm font-semibold text-text-primary">Sector Targeting</h2>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={sectorRows} layout="vertical" margin={{ left: 80 }}>
              <XAxis type="number" tick={{ fill: '#6b6b8a', fontSize: 10 }} />
              <YAxis
                type="category"
                dataKey="name"
                tick={{ fill: '#e8e8f0', fontSize: 10 }}
                width={80}
              />
              <Tooltip
                contentStyle={{ background: '#13131f', border: '1px solid #2a2a3e', fontSize: 11 }}
              />
              <Bar dataKey="Nation-state" stackId="a" fill="#7c3aed" />
              <Bar dataKey="Fin. motivated" stackId="a" fill="#f59e0b" />
              <Bar dataKey="Hacktivist" stackId="a" fill="#ef4444" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  )
}
