import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useThreats } from '@/api/threats'
import { TlpBadge } from '@/components/shared/TlpBadge'
import { TechniqueTag } from '@/components/shared/TechniqueTag'
import { DataTable } from '@/components/shared/DataTable'
import { useDebounce } from '@/hooks/useDebounce'
import { timeAgo } from '@/lib/utils'
import type { ThreatSummary } from '@/types/api'

const TLP_OPTIONS = ['WHITE', 'GREEN', 'AMBER', 'RED']

export function IntelFeed() {
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
          {t.ttps.slice(0, 3).map(id => (
            <TechniqueTag key={id} id={id} />
          ))}
          {t.ttps.length > 3 && (
            <span className="text-xs text-text-muted">+{t.ttps.length - 3} more</span>
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
      header: 'Ingested',
      sortable: true,
      render: (t: ThreatSummary) => (
        <span className="text-text-muted">{timeAgo(t.publication_date)}</span>
      ),
    },
  ]

  return (
    <div>
      <div className="mb-6 flex flex-wrap items-center gap-4">
        <h1 className="text-lg font-semibold text-text-primary">Intel Feed</h1>
        <div className="ml-auto flex flex-wrap items-center gap-3">
          {/* TLP filter */}
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
      </div>

      <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface">
        <DataTable
          columns={columns}
          data={filtered}
          loading={isLoading}
          emptyTitle="No intel reports yet"
          emptyDescription="Ingest a URL or paste raw text using the bar above."
          onRowClick={t => navigate(`/intel/${t.id}`)}
          keyFn={t => t.id}
        />
      </div>
    </div>
  )
}
