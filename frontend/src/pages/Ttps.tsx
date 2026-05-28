import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Database, LayoutGrid, ShieldCheck } from 'lucide-react'
import { useTTPs } from '@/api/ttps'
import { useDashboardSummary } from '@/api/analytics'
import { DataTable } from '@/components/shared/DataTable'
import { FilterBar } from '@/components/shared/FilterBar'
import { PageHeader } from '@/components/shared/PageHeader'
import { ResultCount } from '@/components/shared/ResultCount'
import { StatStrip } from '@/components/shared/StatStrip'
import { useDebounce } from '@/hooks/useDebounce'
import { cn } from '@/lib/utils'
import type { AttckTechnique } from '@/types/api'

const TACTICS = [
  'reconnaissance', 'resource-development', 'initial-access', 'execution',
  'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
  'discovery', 'lateral-movement', 'collection', 'command-and-control',
  'exfiltration', 'impact',
]

const TACTIC_LABELS: Record<string, string> = {
  'reconnaissance': 'Recon',
  'resource-development': 'Resource Dev',
  'initial-access': 'Initial Access',
  'execution': 'Execution',
  'persistence': 'Persistence',
  'privilege-escalation': 'Priv Esc',
  'defense-evasion': 'Def Evasion',
  'credential-access': 'Cred Access',
  'discovery': 'Discovery',
  'lateral-movement': 'Lateral Move',
  'collection': 'Collection',
  'command-and-control': 'C2',
  'exfiltration': 'Exfiltration',
  'impact': 'Impact',
}

const DOMAINS = [
  { value: '', label: 'All domains' },
  { value: 'enterprise', label: 'Enterprise' },
  { value: 'mobile', label: 'Mobile' },
  { value: 'ics', label: 'ICS' },
]

const PAGE_SIZE = 50

export function Ttps() {
  const navigate = useNavigate()
  const [search, setSearch] = useState('')
  const [tactic, setTactic] = useState('')
  const [domain, setDomain] = useState('')
  const [page, setPage] = useState(0)
  const debouncedSearch = useDebounce(search, 300)

  const { data, isLoading } = useTTPs({
    tactic: tactic || undefined,
    domain: domain || undefined,
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  })

  const { data: summary, isLoading: summaryLoading } = useDashboardSummary()

  const tacticCounts = summary?.ttp_by_tactic ?? {}
  const totalTechniques = summary?.technique_count ?? 0
  const tacticsCovered = Object.keys(tacticCounts).length
  const maxCount = Math.max(...Object.values(tacticCounts), 1)

  const filtered = (data ?? []).filter(t => {
    if (!debouncedSearch) return true
    return (
      t.technique_id.toLowerCase().includes(debouncedSearch.toLowerCase()) ||
      t.name.toLowerCase().includes(debouncedSearch.toLowerCase())
    )
  })

  const activeFilterCount = [search, tactic, domain].filter(Boolean).length

  function clearFilters() {
    setSearch('')
    setTactic('')
    setDomain('')
    setPage(0)
  }

  const stats = [
    {
      label: 'Techniques',
      value: totalTechniques || '—',
      icon: Database,
    },
    {
      label: 'Tactics Covered',
      value: tacticsCovered || '—',
      color: 'text-purple-400',
      icon: LayoutGrid,
    },
    {
      label: 'Domains',
      value: 3,
      color: 'text-cyan-400',
      icon: ShieldCheck,
    },
    {
      label: 'ATT&CK + ATLAS',
      value: 'Enterprise, Mobile, ICS',
      color: 'text-text-muted',
    },
  ]

  const columns = [
    {
      key: 'technique_id',
      header: 'ID',
      sortable: true,
      render: (t: AttckTechnique) => (
        <span
          className={cn(
            'rounded-md px-2 py-0.5 font-mono text-sm font-bold',
            t.technique_id.startsWith('AML')
              ? 'bg-cyan-900/40 text-cyan-300'
              : 'bg-purple-900/40 text-purple-300',
          )}
        >
          {t.technique_id}
        </span>
      ),
    },
    {
      key: 'name',
      header: 'Name',
      sortable: true,
      render: (t: AttckTechnique) => (
        <span className="font-medium text-text-primary">{t.name}</span>
      ),
    },
    {
      key: 'tactics',
      header: 'Tactic(s)',
      render: (t: AttckTechnique) => (
        <div className="flex flex-wrap gap-1">
          {t.tactics.slice(0, 3).map(tc => (
            <span
              key={tc}
              className="rounded bg-bg-elevated px-1.5 py-0.5 text-xs text-text-muted"
            >
              {TACTIC_LABELS[tc] ?? tc}
            </span>
          ))}
          {t.tactics.length > 3 && (
            <span className="text-xs text-text-muted">+{t.tactics.length - 3}</span>
          )}
        </div>
      ),
    },
    {
      key: 'domain',
      header: 'Domain',
      sortable: true,
      render: (t: AttckTechnique) => (
        <span className="rounded bg-bg-elevated px-1.5 py-0.5 text-xs text-text-muted capitalize">
          {t.domain}
        </span>
      ),
    },
  ]

  return (
    <div>
      <PageHeader
        title="ATT&CK Techniques (TTPs)"
        description="MITRE ATT&CK Enterprise, Mobile, and ICS domains plus ATLAS AI adversarial techniques."
      />

      <StatStrip stats={stats} loading={summaryLoading} />

      {/* Tactic heatmap */}
      {Object.keys(tacticCounts).length > 0 && (
        <div className="mb-6 overflow-x-auto rounded-xl border border-[#2a2a3e] bg-bg-surface px-4 py-3">
          <p className="mb-2 text-xs font-medium text-text-muted">Technique density by tactic — click to filter</p>
          <div className="flex flex-wrap gap-2">
            {TACTICS.map(t => {
              const count = tacticCounts[t] ?? 0
              const intensity = count / maxCount
              const isActive = tactic === t
              return (
                <button
                  key={t}
                  onClick={() => { setTactic(isActive ? '' : t); setPage(0) }}
                  title={`${t}: ${count} techniques`}
                  className={cn(
                    'rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors',
                    isActive
                      ? 'border-accent-bright bg-accent-bright/20 text-accent-bright'
                      : intensity > 0.6
                      ? 'border-purple-700 bg-purple-900/60 text-purple-200 hover:border-purple-500'
                      : intensity > 0.3
                      ? 'border-purple-800 bg-purple-900/30 text-purple-300 hover:border-purple-600'
                      : count > 0
                      ? 'border-[#2a2a3e] bg-bg-elevated text-text-muted hover:text-text-primary'
                      : 'border-[#2a2a3e] bg-bg-elevated text-[#3a3a5e] cursor-default',
                  )}
                >
                  {TACTIC_LABELS[t] ?? t}
                  {count > 0 && (
                    <span className="ml-1.5 text-[10px] opacity-70">{count}</span>
                  )}
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
          placeholder="Search ID or name..."
          className="rounded-lg border border-[#2a2a3e] bg-bg-surface px-3 py-1.5 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
        />
        <select
          value={tactic}
          onChange={e => { setTactic(e.target.value); setPage(0) }}
          className="rounded-lg border border-[#2a2a3e] bg-bg-surface px-3 py-1.5 text-xs text-text-primary focus:outline-none"
        >
          <option value="">All tactics</option>
          {TACTICS.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        <select
          value={domain}
          onChange={e => { setDomain(e.target.value); setPage(0) }}
          className="rounded-lg border border-[#2a2a3e] bg-bg-surface px-3 py-1.5 text-xs text-text-primary focus:outline-none"
        >
          {DOMAINS.map(d => <option key={d.value} value={d.value}>{d.label}</option>)}
        </select>
      </FilterBar>

      <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface">
        <DataTable
          columns={columns}
          data={filtered}
          loading={isLoading}
          emptyTitle="No techniques found"
          onRowClick={t => navigate(`/ttps/${t.technique_id}`)}
          keyFn={t => t.technique_id}
        />
      </div>

      <ResultCount
        page={page}
        pageSize={PAGE_SIZE}
        total={activeFilterCount === 0 ? (totalTechniques || undefined) : undefined}
        pageItemCount={filtered.length}
        onPrev={() => setPage(p => Math.max(0, p - 1))}
        onNext={() => setPage(p => p + 1)}
        noun="techniques"
      />
    </div>
  )
}
