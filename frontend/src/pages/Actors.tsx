import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ChevronLeft, ChevronRight } from 'lucide-react'
import { useActors } from '@/api/actors'
import { DataTable } from '@/components/shared/DataTable'
import { cn } from '@/lib/utils'
import { SPONSOR_COLORS } from '@/lib/constants'
import type { ActorSummary } from '@/types/api'

const SPONSOR_TYPES = [
  { value: '', label: 'All' },
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
      render: (a: ActorSummary) => (
        <span className="font-mono text-xs text-text-muted">{a.country_code ?? '—'}</span>
      ),
    },
    {
      key: 'sponsor_type',
      header: 'Sponsor',
      sortable: true,
      render: (a: ActorSummary) => (
        <span
          className={cn(
            'inline-flex rounded px-1.5 py-0.5 text-xs font-medium',
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
        <span className="text-text-muted">{a.sophistication ?? 0} TTP(s)</span>
      ),
    },
    {
      key: 'sophistication',
      header: 'Sophistication',
      sortable: true,
      render: (a: ActorSummary) => {
        if (!a.sophistication) return <span className="text-text-muted">—</span>
        return (
          <span className="flex gap-0.5">
            {[1, 2, 3, 4, 5].map(n => (
              <span
                key={n}
                className={n <= a.sophistication! ? 'text-accent-bright' : 'text-[#2a2a3e]'}
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
      <div className="mb-6 flex flex-wrap items-center gap-3">
        <h1 className="text-lg font-semibold text-text-primary">Threat Actors</h1>
        <div className="ml-auto flex flex-wrap items-center gap-3">
          <input
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(0) }}
            placeholder="Search by name..."
            className="rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-1.5 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
          />
          <input
            value={country}
            onChange={e => { setCountry(e.target.value.toUpperCase()); setPage(0) }}
            placeholder="Country (US, RU...)"
            maxLength={2}
            className="w-28 rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-1.5 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
          />
          <select
            value={sponsorType}
            onChange={e => { setSponsorType(e.target.value); setPage(0) }}
            className="rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-1.5 text-xs text-text-primary focus:outline-none"
          >
            {SPONSOR_TYPES.map(o => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
        </div>
      </div>

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

      {/* Pagination */}
      <div className="mt-4 flex items-center justify-center gap-4 text-xs text-text-muted">
        <button
          onClick={() => setPage(p => Math.max(0, p - 1))}
          disabled={page === 0}
          className="flex items-center gap-1 disabled:opacity-40 hover:text-text-primary"
        >
          <ChevronLeft size={14} /> Prev
        </button>
        <span>Page {page + 1}</span>
        <button
          onClick={() => setPage(p => p + 1)}
          disabled={(data?.length ?? 0) < PAGE_SIZE}
          className="flex items-center gap-1 disabled:opacity-40 hover:text-text-primary"
        >
          Next <ChevronRight size={14} />
        </button>
      </div>
    </div>
  )
}
