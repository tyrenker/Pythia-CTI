import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ChevronLeft, ChevronRight } from 'lucide-react'
import { useTTPs } from '@/api/ttps'
import { DataTable } from '@/components/shared/DataTable'
import { useDebounce } from '@/hooks/useDebounce'
import type { AttckTechnique } from '@/types/api'

const TACTICS = [
  'reconnaissance', 'resource-development', 'initial-access', 'execution',
  'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
  'discovery', 'lateral-movement', 'collection', 'command-and-control',
  'exfiltration', 'impact',
]

// Backend domain values are lowercase; ATLAS is a separate model at /v1/ai-threats/atlas
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

  const filtered = (data ?? []).filter(t => {
    if (!debouncedSearch) return true
    return (
      t.technique_id.toLowerCase().includes(debouncedSearch.toLowerCase()) ||
      t.name.toLowerCase().includes(debouncedSearch.toLowerCase())
    )
  })

  const columns = [
    {
      key: 'technique_id',
      header: 'ID',
      sortable: true,
      render: (t: AttckTechnique) => (
        <span
          className={`font-mono text-xs font-medium ${
            t.technique_id.startsWith('AML') ? 'text-cyan-300' : 'text-purple-300'
          }`}
        >
          {t.technique_id}
        </span>
      ),
    },
    {
      key: 'name',
      header: 'Name',
      sortable: true,
      render: (t: AttckTechnique) => <span className="text-text-primary">{t.name}</span>,
    },
    {
      key: 'tactics',
      header: 'Tactic(s)',
      render: (t: AttckTechnique) => (
        <span className="text-text-muted">{t.tactics.slice(0, 2).join(', ')}</span>
      ),
    },
    {
      key: 'domain',
      header: 'Domain',
      sortable: true,
      render: (t: AttckTechnique) => (
        <span className="text-text-muted">{t.domain}</span>
      ),
    },
  ]

  return (
    <div>
      <div className="mb-6 flex flex-wrap items-center gap-3">
        <h1 className="text-lg font-semibold text-text-primary">Techniques (TTPs)</h1>
        <div className="ml-auto flex flex-wrap items-center gap-3">
          <input
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(0) }}
            placeholder="Search ID or name..."
            className="rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-1.5 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
          />
          <select
            value={tactic}
            onChange={e => { setTactic(e.target.value); setPage(0) }}
            className="rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-1.5 text-xs text-text-primary focus:outline-none"
          >
            <option value="">All tactics</option>
            {TACTICS.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
          <select
            value={domain}
            onChange={e => { setDomain(e.target.value); setPage(0) }}
            className="rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-1.5 text-xs text-text-primary focus:outline-none"
          >
            {DOMAINS.map(d => <option key={d.value} value={d.value}>{d.label}</option>)}
          </select>
        </div>
      </div>

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
