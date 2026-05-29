import { useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Plus, Search, Activity, Archive, CheckCircle, Clock, Target, MoreVertical, Trash2 } from 'lucide-react'
import { useHunts, useCreateHunt, useUpdateHunt, useDeleteHunt } from '@/api/hunts'
import { PageHeader } from '@/components/shared/PageHeader'
import { cn } from '@/lib/utils'
import type { HuntSessionSummary } from '@/types/api'

const STATUS_STYLES: Record<string, string> = {
  active:   'bg-green-900/60 text-green-300 border border-green-700/40',
  closed:   'bg-zinc-800 text-zinc-400 border border-zinc-700/40',
  archived: 'bg-zinc-900 text-zinc-500 border border-zinc-800/40',
}

const STATUS_ICONS: Record<string, typeof Activity> = {
  active: Activity,
  closed: CheckCircle,
  archived: Archive,
}

// ── New Hunt modal ────────────────────────────────────────────────────────────

function NewHuntModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const navigate = useNavigate()
  const create = useCreateHunt()
  const [name, setName] = useState('')
  const [hypothesis, setHypothesis] = useState('')
  const [analyst, setAnalyst] = useState('')
  const [sectors, setSectors] = useState('')
  const [motivations, setMotivations] = useState('')

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!name.trim()) return
    const result = await create.mutateAsync({
      name: name.trim(),
      hypothesis: hypothesis.trim() || undefined,
      analyst: analyst.trim() || undefined,
      sector_focus: sectors.split(',').map(s => s.trim()).filter(Boolean),
      motivation_focus: motivations.split(',').map(m => m.trim()).filter(Boolean),
    })
    onClose()
    navigate(`/hunt/${result.id}`)
  }

  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-md rounded-xl border border-[#2a2a3e] bg-bg-surface p-6 shadow-2xl">
        <h2 className="mb-1 text-sm font-semibold text-text-primary">New Threat Hunt</h2>
        <p className="mb-4 text-xs text-text-muted">Start a new hunt session. Add your initial hypothesis and context.</p>
        <form onSubmit={handleSubmit} className="space-y-3">
          <div>
            <label className="mb-1 block text-xs font-medium text-text-muted">Hunt name *</label>
            <input
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="e.g. Suspected APT lateral movement via WMI"
              required
              className="w-full rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-text-muted">Hypothesis</label>
            <textarea
              value={hypothesis}
              onChange={e => setHypothesis(e.target.value)}
              placeholder="An actor with espionage motivations is using WMI to move laterally within the finance sector..."
              rows={3}
              className="w-full resize-none rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="mb-1 block text-xs font-medium text-text-muted">Analyst name</label>
              <input
                value={analyst}
                onChange={e => setAnalyst(e.target.value)}
                placeholder="Your name"
                className="w-full rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-text-muted">Sectors (comma-separated)</label>
              <input
                value={sectors}
                onChange={e => setSectors(e.target.value)}
                placeholder="finance, healthcare"
                className="w-full rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
              />
            </div>
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-text-muted">Suspected motivations (comma-separated)</label>
            <input
              value={motivations}
              onChange={e => setMotivations(e.target.value)}
              placeholder="espionage, financial"
              className="w-full rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
            />
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg border border-[#2a2a3e] px-4 py-2 text-xs font-medium text-text-muted hover:text-text-primary"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!name.trim() || create.isPending}
              className="rounded-lg bg-accent px-4 py-2 text-xs font-semibold text-white hover:opacity-90 disabled:opacity-50"
            >
              {create.isPending ? 'Creating...' : 'Start Hunt'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Delete confirmation modal ─────────────────────────────────────────────────

function DeleteModal({
  hunt,
  onConfirm,
  onCancel,
  isPending,
}: {
  hunt: HuntSessionSummary
  onConfirm: () => void
  onCancel: () => void
  isPending: boolean
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-sm rounded-xl border border-[#2a2a3e] bg-bg-surface p-6 shadow-2xl">
        <div className="mb-4 flex h-10 w-10 items-center justify-center rounded-full bg-red-900/30">
          <Trash2 size={18} className="text-red-400" />
        </div>
        <h2 className="mb-1 text-sm font-semibold text-text-primary">Delete Hunt Session</h2>
        <p className="mb-1 text-xs text-text-muted">
          This will permanently delete <span className="font-medium text-text-primary">"{hunt.name}"</span> along with all observations, notes, and draft detections.
        </p>
        <p className="mb-5 text-xs font-medium text-red-400">This action cannot be undone.</p>
        <div className="flex justify-end gap-2">
          <button
            onClick={onCancel}
            className="rounded-lg border border-[#2a2a3e] px-4 py-2 text-xs font-medium text-text-muted hover:text-text-primary"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={isPending}
            className="flex items-center gap-1.5 rounded-lg bg-red-700 px-4 py-2 text-xs font-semibold text-white hover:bg-red-600 disabled:opacity-50"
          >
            <Trash2 size={11} />
            {isPending ? 'Deleting...' : 'Delete'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Row actions menu ──────────────────────────────────────────────────────────

const STATUSES = ['active', 'closed', 'archived'] as const

function RowActions({
  hunt,
  onDelete,
}: {
  hunt: HuntSessionSummary
  onDelete: () => void
}) {
  const [open, setOpen] = useState(false)
  const menuRef = useRef<HTMLDivElement>(null)
  const update = useUpdateHunt(hunt.id)

  async function setStatus(s: string) {
    setOpen(false)
    await update.mutateAsync({ status: s })
  }

  return (
    <div className="relative" ref={menuRef}>
      <button
        onClick={e => { e.stopPropagation(); setOpen(v => !v) }}
        className={cn(
          'rounded-md p-1.5 transition-colors',
          open ? 'bg-bg-elevated text-text-primary' : 'text-text-muted hover:text-text-primary hover:bg-bg-elevated',
        )}
        title="Actions"
      >
        <MoreVertical size={14} />
      </button>

      {open && (
        <>
          {/* Backdrop to close on outside click */}
          <div className="fixed inset-0 z-10" onClick={() => setOpen(false)} />
          <div className="absolute right-0 top-full z-20 mt-1 w-44 rounded-lg border border-[#2a2a3e] bg-bg-surface py-1 shadow-xl">
            <p className="px-3 py-1 text-[10px] font-semibold uppercase tracking-wide text-text-muted">Set status</p>
            {STATUSES.filter(s => s !== hunt.status).map(s => {
              const Icon = STATUS_ICONS[s] ?? Clock
              return (
                <button
                  key={s}
                  onClick={e => { e.stopPropagation(); setStatus(s) }}
                  disabled={update.isPending}
                  className="flex w-full items-center gap-2 px-3 py-1.5 text-xs text-text-muted hover:bg-bg-elevated hover:text-text-primary disabled:opacity-50 capitalize"
                >
                  <Icon size={12} />
                  {s}
                </button>
              )
            })}
            <div className="my-1 border-t border-[#2a2a3e]" />
            <button
              onClick={e => { e.stopPropagation(); setOpen(false); onDelete() }}
              className="flex w-full items-center gap-2 px-3 py-1.5 text-xs text-red-400 hover:bg-red-900/20 hover:text-red-300"
            >
              <Trash2 size={12} />
              Delete
            </button>
          </div>
        </>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export function HuntList() {
  const navigate = useNavigate()
  const [statusFilter, setStatusFilter] = useState<string>('')
  const [search, setSearch] = useState('')
  const [newOpen, setNewOpen] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<HuntSessionSummary | null>(null)

  const { data: hunts, isLoading } = useHunts(statusFilter || undefined)
  const deleteHunt = useDeleteHunt()

  const filtered = (hunts ?? []).filter(h => {
    if (!search) return true
    const q = search.toLowerCase()
    return h.name.toLowerCase().includes(q) || h.hypothesis?.toLowerCase().includes(q)
  })

  const activeCt = (hunts ?? []).filter(h => h.status === 'active').length

  async function confirmDelete() {
    if (!deleteTarget) return
    try {
      await deleteHunt.mutateAsync(deleteTarget.id)
    } catch {
      // 404 = already gone; list will refresh via onSettled
    }
    setDeleteTarget(null)
  }

  return (
    <div>
      <PageHeader
        title="Hunt Workbench"
        description="Active threat hunting sessions. Track IOCs, TTPs, and build detections as you hunt."
      />

      {/* Summary strip */}
      <div className="mb-6 grid grid-cols-3 gap-3">
        {[
          { label: 'Active Hunts', value: activeCt, icon: Activity, color: 'text-green-400' },
          { label: 'Total Sessions', value: hunts?.length ?? '—', icon: Target, color: 'text-accent-bright' },
          { label: 'Total Observations', value: (hunts ?? []).reduce((s, h) => s + h.observation_count, 0), icon: Search, color: 'text-amber-400' },
        ].map(stat => (
          <div key={stat.label} className="rounded-xl border border-[#2a2a3e] bg-bg-surface px-4 py-3">
            <div className="flex items-center gap-2">
              <stat.icon size={14} className={stat.color} />
              <span className="text-xs text-text-muted">{stat.label}</span>
            </div>
            <p className={cn('mt-1 text-xl font-bold tabular-nums', stat.color)}>{stat.value}</p>
          </div>
        ))}
      </div>

      {/* Filters + new button */}
      <div className="mb-4 flex items-center gap-3">
        <div className="relative flex-1">
          <Search size={12} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search hunts..."
            className="w-full rounded-lg border border-[#2a2a3e] bg-bg-surface py-2 pl-8 pr-3 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
          />
        </div>
        <select
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value)}
          className="rounded-lg border border-[#2a2a3e] bg-bg-surface px-3 py-2 text-xs text-text-primary focus:outline-none"
        >
          <option value="">All statuses</option>
          <option value="active">Active</option>
          <option value="closed">Closed</option>
          <option value="archived">Archived</option>
        </select>
        <button
          onClick={() => setNewOpen(true)}
          className="flex items-center gap-2 rounded-lg bg-accent px-3 py-2 text-xs font-semibold text-white hover:opacity-90"
        >
          <Plus size={13} />
          New Hunt
        </button>
      </div>

      {/* Hunt list */}
      <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface">
        {isLoading ? (
          <div className="py-12 text-center text-xs text-text-muted">Loading hunts...</div>
        ) : filtered.length === 0 ? (
          <div className="py-12 text-center">
            <Target size={24} className="mx-auto mb-2 text-text-muted" />
            <p className="text-sm font-medium text-text-primary">No hunt sessions yet</p>
            <p className="mt-1 text-xs text-text-muted">Start your first hunt to begin tracking IOCs and TTPs.</p>
            <button
              onClick={() => setNewOpen(true)}
              className="mt-4 inline-flex items-center gap-2 rounded-lg bg-accent px-4 py-2 text-xs font-semibold text-white hover:opacity-90"
            >
              <Plus size={13} />
              New Hunt
            </button>
          </div>
        ) : (
          <div className="divide-y divide-[#2a2a3e]">
            {filtered.map(h => {
              const StatusIcon = STATUS_ICONS[h.status] ?? Clock
              return (
                <div
                  key={h.id}
                  className="group flex w-full items-start gap-4 px-5 py-4 transition-colors hover:bg-bg-elevated"
                >
                  {/* Icon — clicking navigates */}
                  <button
                    onClick={() => navigate(`/hunt/${h.id}`)}
                    className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-bg-elevated group-hover:bg-bg-base"
                    tabIndex={-1}
                  >
                    <StatusIcon size={15} className={h.status === 'active' ? 'text-green-400' : 'text-text-muted'} />
                  </button>

                  {/* Main content — clicking navigates */}
                  <button
                    onClick={() => navigate(`/hunt/${h.id}`)}
                    className="min-w-0 flex-1 text-left"
                  >
                    <div className="flex items-center gap-2">
                      <span className="truncate text-sm font-semibold text-text-primary">{h.name}</span>
                      <span className={cn('shrink-0 rounded-full px-2 py-0.5 text-[10px] font-medium', STATUS_STYLES[h.status])}>
                        {h.status}
                      </span>
                    </div>
                    {h.hypothesis && (
                      <p className="mt-0.5 truncate text-xs text-text-muted">{h.hypothesis}</p>
                    )}
                    <div className="mt-1.5 flex items-center gap-3 text-[11px] text-text-muted">
                      {h.analyst && <span>by {h.analyst}</span>}
                      <span>{h.observation_count} obs</span>
                      <span>{h.detection_count} detections</span>
                      {h.sector_focus.length > 0 && (
                        <span className="truncate">{h.sector_focus.slice(0, 2).join(', ')}</span>
                      )}
                    </div>
                  </button>

                  {/* Right side: date + actions */}
                  <div className="flex shrink-0 items-center gap-2">
                    <time className="text-[11px] text-text-muted">
                      {new Date(h.updated_at).toLocaleDateString()}
                    </time>
                    <RowActions hunt={h} onDelete={() => setDeleteTarget(h)} />
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>

      <NewHuntModal open={newOpen} onClose={() => setNewOpen(false)} />

      {deleteTarget && (
        <DeleteModal
          hunt={deleteTarget}
          onConfirm={confirmDelete}
          onCancel={() => setDeleteTarget(null)}
          isPending={deleteHunt.isPending}
        />
      )}
    </div>
  )
}
