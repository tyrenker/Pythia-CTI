import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Globe, Hash, Link2, Shield } from 'lucide-react'
import { useIocs } from '@/api/iocs'
import { useDashboardSummary } from '@/api/analytics'
import { TlpBadge } from '@/components/shared/TlpBadge'
import { DataTable } from '@/components/shared/DataTable'
import { FilterBar } from '@/components/shared/FilterBar'
import { PageHeader } from '@/components/shared/PageHeader'
import { ResultCount } from '@/components/shared/ResultCount'
import { StatStrip } from '@/components/shared/StatStrip'
import { useDebounce } from '@/hooks/useDebounce'
import { cn, truncate } from '@/lib/utils'
import { PYRAMID_COLORS, PYRAMID_TIERS, IOC_SOURCE_LABELS } from '@/lib/constants'
import { ADMIRALTY_SOURCE, ADMIRALTY_ACCURACY } from '@/lib/constants'
import type { IocSummary } from '@/types/api'

const IOC_TYPES = ['ip', 'domain', 'url', 'email', 'cve', 'md5', 'sha256']
const IOC_SOURCES = Object.entries(IOC_SOURCE_LABELS)

const TYPE_ICONS: Record<string, typeof Globe> = {
  ip: Globe,
  domain: Link2,
  url: Link2,
  md5: Hash,
  sha256: Hash,
}

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

  const { data, isLoading } = useIocs({
    type: iocType || undefined,
    pyramid_tier: tier || undefined,
    tlp: tlp || undefined,
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  })

  const { data: summary, isLoading: summaryLoading } = useDashboardSummary()

  const filtered = (data ?? []).filter(ioc => {
    if (debouncedSearch && !ioc.value.toLowerCase().includes(debouncedSearch.toLowerCase())) return false
    if (source && !ioc.source_url?.includes(source)) return false
    return true
  })

  const totalIocs = summary
    ? Object.values(summary.ioc_by_type).reduce((a, b) => a + b, 0)
    : undefined
  const ipCount = summary?.ioc_by_type['ip'] ?? 0
  const sha256Count = summary?.ioc_by_type['sha256'] ?? 0

  // Pyramid tier distribution from loaded data
  const tierCounts = filtered.reduce<Record<string, number>>((acc, ioc) => {
    acc[ioc.pyramid_tier] = (acc[ioc.pyramid_tier] ?? 0) + 1
    return acc
  }, {})
  const maxTierCount = Math.max(...Object.values(tierCounts), 1)

  const activeFilterCount = [search, iocType, tier, tlp, source].filter(Boolean).length

  function clearFilters() {
    setSearch('')
    setIocType('')
    setTier('')
    setTlp('')
    setSource('')
    setPage(0)
  }

  const stats = [
    { label: 'Total IoCs', value: totalIocs ?? '—', icon: Shield },
    { label: 'IP Addresses', value: ipCount || '—', color: 'text-orange-400', icon: Globe },
    { label: 'SHA256 Hashes', value: sha256Count || '—', color: 'text-red-400', icon: Hash },
    { label: 'Types Tracked', value: IOC_TYPES.length, color: 'text-cyan-400' },
  ]

  const columns = [
    {
      key: 'value',
      header: 'Value',
      render: (ioc: IocSummary) => {
        const Icon = TYPE_ICONS[ioc.type]
        return (
          <span className="flex items-center gap-1.5" title={ioc.value}>
            {Icon && <Icon size={11} className="shrink-0 text-text-muted" />}
            <span className="font-mono text-xs text-text-primary">
              {truncate(ioc.value, 40)}
            </span>
          </span>
        )
      },
    },
    {
      key: 'type',
      header: 'Type',
      sortable: true,
      render: (ioc: IocSummary) => (
        <span className="rounded-md bg-bg-elevated px-2 py-0.5 font-mono text-xs font-medium text-text-primary">
          {ioc.type}
        </span>
      ),
    },
    {
      key: 'actor_name',
      header: 'Actor',
      sortable: true,
      render: (ioc: IocSummary) =>
        ioc.actor_name ? (
          <span
            onClick={e => {
              e.stopPropagation()
              navigate(`/actors/${ioc.actor_id}`)
            }}
            className="cursor-pointer text-xs font-semibold text-accent-bright hover:underline"
          >
            {ioc.actor_name}
          </span>
        ) : (
          <span className="text-xs text-text-muted">—</span>
        ),
    },
    {
      key: 'pyramid_tier',
      header: 'Pyramid',
      sortable: true,
      render: (ioc: IocSummary) => (
        <span
          className={cn(
            'inline-flex rounded-md px-2 py-0.5 text-xs font-medium',
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
        const srcLabel = ADMIRALTY_SOURCE[ioc.confidence_source] ?? ioc.confidence_source
        const infoLabel = ADMIRALTY_ACCURACY[ioc.confidence_info] ?? ioc.confidence_info
        return (
          <span
            title={`Source: ${srcLabel} · Info: ${infoLabel}`}
            className="inline-flex cursor-help items-center rounded-md bg-zinc-800 px-2 py-0.5 font-mono text-xs font-medium text-zinc-300"
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
      <PageHeader
        title="Indicators of Compromise"
        description="Enriched with Pyramid of Pain tiers and Admiralty ratings for source and information reliability."
      />

      <StatStrip stats={stats} loading={summaryLoading} />

      {/* Pyramid of Pain mini-visualization */}
      {filtered.length > 0 && (
        <div className="mb-6 rounded-xl border border-[#2a2a3e] bg-bg-surface px-4 py-3">
          <p className="mb-3 text-xs font-medium text-text-muted">
            Pyramid of Pain distribution{' '}
            <span className="font-normal">(current results)</span>
          </p>
          <div className="space-y-1.5">
            {[...PYRAMID_TIERS].reverse().map(t => {
              const count = tierCounts[t] ?? 0
              const pct = Math.round((count / maxTierCount) * 100)
              return (
                <button
                  key={t}
                  onClick={() => { setTier(tier === t ? '' : t); setPage(0) }}
                  className={cn(
                    'group flex w-full items-center gap-3 rounded px-2 py-1 text-xs transition-colors hover:bg-bg-elevated',
                    tier === t && 'bg-bg-elevated',
                  )}
                >
                  <span
                    className={cn(
                      'w-14 shrink-0 text-right font-medium capitalize',
                      PYRAMID_COLORS[t]?.split(' ')[1] ?? 'text-text-muted',
                    )}
                  >
                    {t}
                  </span>
                  <div className="h-2 flex-1 overflow-hidden rounded-full bg-bg-elevated">
                    <div
                      className={cn(
                        'h-full rounded-full transition-all',
                        PYRAMID_COLORS[t]?.split(' ')[0] ?? 'bg-zinc-700',
                      )}
                      style={{ width: `${pct}%`, opacity: 0.7 }}
                    />
                  </div>
                  <span className="w-8 shrink-0 text-right tabular-nums text-text-muted">
                    {count}
                  </span>
                </button>
              )
            })}
          </div>
        </div>
      )}

      <FilterBar
        activeCount={activeFilterCount}
        onClearFilters={clearFilters}
      >
        <input
          value={search}
          onChange={e => { setSearch(e.target.value); setPage(0) }}
          placeholder="Search value..."
          className="rounded-lg border border-[#2a2a3e] bg-bg-surface px-3 py-1.5 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
        />
        <select
          value={iocType}
          onChange={e => { setIocType(e.target.value); setPage(0) }}
          className="rounded-lg border border-[#2a2a3e] bg-bg-surface px-3 py-1.5 text-xs text-text-primary focus:outline-none"
        >
          <option value="">All types</option>
          {IOC_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        <select
          value={tier}
          onChange={e => { setTier(e.target.value); setPage(0) }}
          className="rounded-lg border border-[#2a2a3e] bg-bg-surface px-3 py-1.5 text-xs text-text-primary focus:outline-none"
        >
          <option value="">All tiers</option>
          {PYRAMID_TIERS.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        <select
          value={tlp}
          onChange={e => { setTlp(e.target.value); setPage(0) }}
          className="rounded-lg border border-[#2a2a3e] bg-bg-surface px-3 py-1.5 text-xs text-text-primary focus:outline-none"
        >
          <option value="">All TLP</option>
          {['WHITE', 'GREEN', 'AMBER', 'RED'].map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        <select
          value={source}
          onChange={e => { setSource(e.target.value); setPage(0) }}
          className="rounded-lg border border-[#2a2a3e] bg-bg-surface px-3 py-1.5 text-xs text-text-primary focus:outline-none"
        >
          <option value="">All sources</option>
          {IOC_SOURCES.map(([key, label]) => <option key={key} value={key}>{label}</option>)}
        </select>
      </FilterBar>

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

      <ResultCount
        page={page}
        pageSize={PAGE_SIZE}
        total={activeFilterCount === 0 ? totalIocs : undefined}
        pageItemCount={filtered.length}
        onPrev={() => setPage(p => Math.max(0, p - 1))}
        onNext={() => setPage(p => p + 1)}
        noun="IoCs"
      />
    </div>
  )
}
