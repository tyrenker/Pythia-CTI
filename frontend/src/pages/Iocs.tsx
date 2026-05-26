import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ChevronLeft, ChevronRight } from 'lucide-react'
import { useIocs } from '@/api/iocs'
import { TlpBadge } from '@/components/shared/TlpBadge'
import { DataTable } from '@/components/shared/DataTable'
import { useDebounce } from '@/hooks/useDebounce'
import { cn, truncate } from '@/lib/utils'
import { PYRAMID_COLORS, PYRAMID_TIERS, IOC_SOURCE_LABELS } from '@/lib/constants'
import type { IocSummary } from '@/types/api'

const IOC_TYPES = ['ip', 'domain', 'url', 'email', 'cve', 'md5', 'sha256']
const IOC_SOURCES = Object.entries(IOC_SOURCE_LABELS)
const PAGE_SIZE = 100

export function Iocs() {
  const navigate = useNavigate()
  const [search, setSearch] = useState('')
  const [iocType, setIocType] = useState('')
  const [tier, setTier] = useState('')
  const [tlp, setTlp] = useState('')
  const [source, setSource] = useState('')
  const [page, setPage] = useState(0)
  const debouncedSearch = useDebounce(search, 300)

  // Backend param is "type", not "ioc_type"
  const { data, isLoading } = useIocs({
    type: iocType || undefined,
    pyramid_tier: tier || undefined,
    tlp: tlp || undefined,
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  })

  const filtered = (data ?? []).filter(ioc => {
    if (debouncedSearch && !ioc.value.toLowerCase().includes(debouncedSearch.toLowerCase())) return false
    if (source && !ioc.source_url?.includes(source)) return false
    return true
  })

  const columns = [
    {
      key: 'value',
      header: 'Value',
      render: (ioc: IocSummary) => (
        <span title={ioc.value} className="font-mono text-xs text-text-primary">
          {truncate(ioc.value, 40)}
        </span>
      ),
    },
    {
      key: 'type',
      header: 'Type',
      sortable: true,
      render: (ioc: IocSummary) => (
        <span className="font-mono text-xs text-text-muted">{ioc.type}</span>
      ),
    },
    {
      key: 'actor_name',
      header: 'Actor',
      sortable: true,
      render: (ioc: IocSummary) => (
        ioc.actor_name ? (
          <span
            onClick={(e) => {
              e.stopPropagation()
              navigate(`/actors/${ioc.actor_id}`)
            }}
            className="text-xs font-semibold text-accent-bright hover:underline cursor-pointer"
          >
            {ioc.actor_name}
          </span>
        ) : (
          <span className="text-xs text-text-muted">—</span>
        )
      ),
    },
    {
      key: 'pyramid_tier',
      header: 'Pyramid',
      sortable: true,
      render: (ioc: IocSummary) => (
        <span
          className={cn(
            'inline-flex rounded px-1.5 py-0.5 text-xs font-medium',
            PYRAMID_COLORS[ioc.pyramid_tier] ?? 'bg-zinc-800 text-zinc-300',
          )}
        >
          {ioc.pyramid_tier}
        </span>
      ),
    },
    {
      key: 'admiralty',
      header: 'Admiralty',
      render: (ioc: IocSummary) => {
        const code = `${ioc.confidence_source}${ioc.confidence_info}`
        return (
          <span
            title={`Source: ${ioc.confidence_source} · Info: ${ioc.confidence_info}`}
            className="inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium font-mono bg-zinc-800 text-zinc-300 cursor-help"
          >
            {code}
          </span>
        )
      },
    },
    {
      key: 'tlp',
      header: 'TLP',
      render: (ioc: IocSummary) => <TlpBadge tlp={ioc.tlp} />,
    },
  ]

  return (
    <div>
      <div className="mb-6 flex flex-wrap items-center gap-3">
        <h1 className="text-lg font-semibold text-text-primary">Indicators of Compromise</h1>
        <div className="ml-auto flex flex-wrap items-center gap-3">
          <input
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(0) }}
            placeholder="Search value..."
            className="rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-1.5 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
          />
          <select
            value={iocType}
            onChange={e => { setIocType(e.target.value); setPage(0) }}
            className="rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-1.5 text-xs text-text-primary focus:outline-none"
          >
            <option value="">All types</option>
            {IOC_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
          <select
            value={tier}
            onChange={e => { setTier(e.target.value); setPage(0) }}
            className="rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-1.5 text-xs text-text-primary focus:outline-none"
          >
            <option value="">All tiers</option>
            {PYRAMID_TIERS.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
          <select
            value={tlp}
            onChange={e => { setTlp(e.target.value); setPage(0) }}
            className="rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-1.5 text-xs text-text-primary focus:outline-none"
          >
            <option value="">All TLP</option>
            {['WHITE', 'GREEN', 'AMBER', 'RED'].map(t => <option key={t} value={t}>{t}</option>)}
          </select>
          <select
            value={source}
            onChange={e => { setSource(e.target.value); setPage(0) }}
            className="rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-1.5 text-xs text-text-primary focus:outline-none"
          >
            <option value="">All sources</option>
            {IOC_SOURCES.map(([key, label]) => <option key={key} value={key}>{label}</option>)}
          </select>
        </div>
      </div>

      <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface">
        <DataTable
          columns={columns}
          data={filtered}
          loading={isLoading}
          emptyTitle="No IoCs found"
          emptyDescription="Adjust your filters or ingest some threat intel."
          onRowClick={ioc => navigate(`/iocs/${ioc.id}`)}
          keyFn={ioc => ioc.id}
        />
      </div>

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
