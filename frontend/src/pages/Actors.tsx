import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { BarChart2, Globe, ShieldAlert, Users } from 'lucide-react'
import { useActors } from '@/api/actors'
import { useDashboardSummary } from '@/api/analytics'
import { DataTable } from '@/components/shared/DataTable'
import { FilterBar } from '@/components/shared/FilterBar'
import { PageHeader } from '@/components/shared/PageHeader'
import { ResultCount } from '@/components/shared/ResultCount'
import { StatStrip } from '@/components/shared/StatStrip'
import { cn } from '@/lib/utils'
import { SPONSOR_COLORS } from '@/lib/constants'
import type { ActorSummary } from '@/types/api'

const SPONSOR_TYPES = [
  { value: '', label: 'All sponsors' },
  { value: 'nation-state', label: 'Nation-state' },
  { value: 'financially-motivated', label: 'Financially motivated' },
  { value: 'hacktivist', label: 'Hacktivist' },
  { value: 'unknown', label: 'Unknown' },
]

const PAGE_SIZE = 50

export function Actors() {
  const navigate = useNavigate()
  const [search, setSearch] = useState('')
  const [country, setCountry] = useState('')
  const [sponsorType, setSponsorType] = useState('')
  const [page, setPage] = useState(0)

  const { data, isLoading } = useActors({
    name: search || undefined,
    country: country || undefined,
    sponsor_type: sponsorType || undefined,
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  })

  const { data: summary, isLoading: summaryLoading } = useDashboardSummary()

  const totalActors = summary
    ? Object.values(summary.actor_by_sponsor).reduce((a, b) => a + b, 0)
    : undefined
  const nationStateCount = summary?.actor_by_sponsor['nation-state'] ?? 0
  const nationStatePct = totalActors ? Math.round((nationStateCount / totalActors) * 100) : 0
  const finMotCount = summary?.actor_by_sponsor['financially-motivated'] ?? 0
  const hacktivistCount = summary?.actor_by_sponsor['hacktivist'] ?? 0

  const activeFilterCount = [search, country, sponsorType].filter(Boolean).length

  function clearFilters() {
    setSearch('')
    setCountry('')
    setSponsorType('')
    setPage(0)
  }

  const stats = [
    { label: 'Total Actors', value: totalActors ?? '—', icon: Users },
    {
      label: 'Nation-State',
      value: totalActors ? `${nationStatePct}%` : '—',
      color: 'text-purple-400',
      icon: ShieldAlert,
    },
    {
      label: 'Financially Motivated',
      value: finMotCount || '—',
      color: 'text-amber-400',
      icon: BarChart2,
    },
    {
      label: 'Hacktivist',
      value: hacktivistCount || '—',
      color: 'text-red-400',
      icon: Globe,
    },
  ]

  const columns = [
    {
      key: 'name',
      header: 'Name',
      sortable: true,
      render: (a: ActorSummary) => (
        <span className="font-medium text-text-primary">{a.name}</span>
      ),
    },
    {
      key: 'country_code',
      header: 'Country',
      sortable: true,
      render: (a: ActorSummary) =>
        a.country_code ? (
          <span className="inline-flex items-center rounded-md bg-bg-elevated px-2 py-0.5 font-mono text-xs font-semibold text-text-primary">
            {a.country_code}
          </span>
        ) : (
          <span className="text-text-muted">—</span>
        ),
    },
    {
      key: 'sponsor_type',
      header: 'Sponsor',
      sortable: true,
      render: (a: ActorSummary) => (
        <span
          className={cn(
            'inline-flex rounded-md px-2.5 py-1 text-xs font-medium',
            SPONSOR_COLORS[a.sponsor_type] ?? 'bg-zinc-800 text-zinc-300',
          )}
        >
          {a.sponsor_type}
        </span>
      ),
    },
    {
      key: 'ttps',
      header: 'Techniques',
      render: (a: ActorSummary) => (
        <span className="inline-flex items-center rounded-full bg-bg-elevated px-2.5 py-0.5 text-xs font-semibold text-text-muted">
          {a.ttp_count}
        </span>
      ),
    },
    {
      key: 'sophistication',
      header: 'Sophistication',
      sortable: true,
      render: (a: ActorSummary) => {
        if (a.sophistication == null) return <span className="text-text-muted">—</span>
        const filled = Math.round(a.sophistication / 2)
        return (
          <span className="flex gap-0.5" title={`${a.sophistication}/10`}>
            {[1, 2, 3, 4, 5].map(n => (
              <span
                key={n}
                className={n <= filled ? 'text-accent-bright' : 'text-[#2a2a3e]'}
              >
                ●
              </span>
            ))}
          </span>
        )
      },
    },
  ]

  return (
    <div>
      <PageHeader
        title="Threat Actors"
        description="Pre-seeded from MISP Galaxy and MITRE ATT&CK adversary clusters."
      />

      <StatStrip stats={stats} loading={summaryLoading} />

      <FilterBar
        activeCount={activeFilterCount}
        onClearFilters={clearFilters}
      >
        <input
          value={search}
          onChange={e => { setSearch(e.target.value); setPage(0) }}
          placeholder="Search by name..."
          className="rounded-lg border border-[#2a2a3e] bg-bg-surface px-3 py-1.5 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
        />
        <input
          value={country}
          onChange={e => { setCountry(e.target.value.toUpperCase()); setPage(0) }}
          placeholder="Country (US, RU...)"
          maxLength={2}
          className="w-28 rounded-lg border border-[#2a2a3e] bg-bg-surface px-3 py-1.5 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
        />
        <select
          value={sponsorType}
          onChange={e => { setSponsorType(e.target.value); setPage(0) }}
          className="rounded-lg border border-[#2a2a3e] bg-bg-surface px-3 py-1.5 text-xs text-text-primary focus:outline-none"
        >
          {SPONSOR_TYPES.map(o => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>
      </FilterBar>

      <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface">
        <DataTable
          columns={columns}
          data={data ?? []}
          loading={isLoading}
          emptyTitle="No actors found"
          onRowClick={a => navigate(`/actors/${a.id}`)}
          keyFn={a => a.id}
        />
      </div>

      <ResultCount
        page={page}
        pageSize={PAGE_SIZE}
        total={activeFilterCount === 0 ? totalActors : undefined}
        pageItemCount={data?.length ?? 0}
        onPrev={() => setPage(p => Math.max(0, p - 1))}
        onNext={() => setPage(p => p + 1)}
        noun="actors"
      />
    </div>
  )
}
