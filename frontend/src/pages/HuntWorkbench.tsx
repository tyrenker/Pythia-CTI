import { useState, useRef, useEffect } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import ReactMarkdown, { type Components } from 'react-markdown'
import remarkGfm from 'remark-gfm'
import {
  ArrowLeft, Plus, Trash2, Sparkles, FileText, Eye, Edit3,
  ChevronDown, ChevronUp, Shield, Target, Wrench,
  CheckCircle, Loader2, Brain, Zap, ExternalLink, Download,
} from 'lucide-react'
import { CodeBlock } from '@/components/shared/CodeBlock'
import {
  useHunt, useUpdateHunt, useAddObservation, useRemoveObservation,
  useHuntNotes, useUpsertNotes, useHuntDetections, useDraftDetection,
  useUpdateDetection, usePromoteDetection, useSuggestActors, useRefineHypothesis,
  useCachedActorSuggestions, useCachedHypothesisRefinement,
  exportHunt,
} from '@/api/hunts'
import { PYRAMID_COLORS, PYRAMID_TIERS, ADMIRALTY_SOURCE, ADMIRALTY_ACCURACY } from '@/lib/constants'
import { cn } from '@/lib/utils'
import type { HuntObservation, ActorSuggestionsResponse, HypothesisRefinement, HuntDraftDetection } from '@/types/api'

// ── Observation type config ───────────────────────────────────────────────────

const OBS_TYPES = [
  { value: 'ioc_ip',       label: 'IP Address',     tier: 'ip' },
  { value: 'ioc_domain',   label: 'Domain',          tier: 'domain' },
  { value: 'ioc_hash',     label: 'File Hash',       tier: 'hash' },
  { value: 'ioc_url',      label: 'URL',             tier: 'artifact' },
  { value: 'ioc_email',    label: 'Email',           tier: 'artifact' },
  { value: 'ioc_mutex',    label: 'Mutex',           tier: 'artifact' },
  { value: 'ioc_registry', label: 'Registry Key',    tier: 'artifact' },
  { value: 'ttp',          label: 'TTP (ATT&CK ID)', tier: 'ttp' },
  { value: 'tool',         label: 'Tool',            tier: 'tool' },
  { value: 'actor',        label: 'Suspected Actor', tier: null },
  { value: 'sector',       label: 'Sector',          tier: null },
  { value: 'motivation',   label: 'Motivation',      tier: null },
]

const RULE_TYPES = ['sigma', 'kql', 'spl', 'eql', 'yara']

// ── Pyramid of Pain strip ─────────────────────────────────────────────────────

function PyramidStrip({ detections }: { detections: HuntDraftDetection[] }) {
  const tierCounts = detections.reduce<Record<string, number>>((acc, d) => {
    acc[d.pyramid_tier] = (acc[d.pyramid_tier] ?? 0) + 1
    return acc
  }, {})
  const max = Math.max(...Object.values(tierCounts), 1)

  return (
    <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface px-4 py-3">
      <div className="mb-2 flex items-center gap-2">
        <Shield size={13} className="text-text-muted" />
        <span className="text-xs font-medium text-text-muted">Pyramid of Pain — detection coverage</span>
      </div>
      <div className="space-y-1">
        {[...PYRAMID_TIERS].reverse().map(tier => {
          const count = tierCounts[tier] ?? 0
          const pct = Math.round((count / max) * 100)
          const colorClasses = PYRAMID_COLORS[tier] ?? 'bg-zinc-800 text-zinc-300'
          const [bgClass, textClass] = colorClasses.split(' ')
          return (
            <div key={tier} className="flex items-center gap-3">
              <span className={cn('w-16 shrink-0 text-right text-[11px] font-medium capitalize', textClass)}>
                {tier}
              </span>
              <div className="h-2 flex-1 overflow-hidden rounded-full bg-bg-elevated">
                {count > 0 && (
                  <div
                    className={cn('h-full rounded-full', bgClass)}
                    style={{ width: `${pct}%`, opacity: 0.75 }}
                  />
                )}
              </div>
              <span className="w-5 shrink-0 text-right text-[11px] tabular-nums text-text-muted">{count}</span>
            </div>
          )
        })}
      </div>
      {detections.length === 0 && (
        <p className="mt-2 text-center text-[11px] text-text-muted">No draft detections yet</p>
      )}
    </div>
  )
}

// ── Observation row ───────────────────────────────────────────────────────────

function ObsRow({
  obs, selected, onToggle, onDelete,
}: {
  obs: HuntObservation
  selected: boolean
  onToggle: () => void
  onDelete: () => void
}) {
  const typeConfig = OBS_TYPES.find(t => t.value === obs.obs_type)
  const admCode = `${obs.confidence_source}${obs.confidence_info}`
  return (
    <div className={cn(
      'group flex items-start gap-2 rounded-lg px-2 py-1.5 transition-colors',
      selected ? 'bg-accent/10 ring-1 ring-accent/30' : 'hover:bg-bg-elevated',
    )}>
      <input
        type="checkbox"
        checked={selected}
        onChange={onToggle}
        className="mt-0.5 h-3.5 w-3.5 accent-accent-bright"
        title="Select for detection drafting"
      />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1.5 flex-wrap">
          <span className="font-mono text-xs font-medium text-text-primary truncate max-w-[180px]" title={obs.value}>
            {obs.value}
          </span>
          {obs.pyramid_tier && (
            <span className={cn(
              'rounded px-1.5 py-0.5 text-[10px] font-medium',
              PYRAMID_COLORS[obs.pyramid_tier] ?? 'bg-zinc-800 text-zinc-300',
            )}>
              {obs.pyramid_tier}
            </span>
          )}
          <span className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-[10px] text-zinc-400">{admCode}</span>
        </div>
        <p className="text-[10px] text-text-muted">{typeConfig?.label ?? obs.obs_type}</p>
        {obs.linked_record_id && (
          <p className="text-[10px] text-green-500">✓ matched in DB</p>
        )}
      </div>
      <button
        onClick={onDelete}
        className="shrink-0 rounded p-1 text-text-muted opacity-0 transition-opacity hover:text-red-400 group-hover:opacity-100"
      >
        <Trash2 size={11} />
      </button>
    </div>
  )
}

// ── Actor suggestion card ─────────────────────────────────────────────────────

function ActorCard({ suggestion, index }: { suggestion: ActorSuggestionsResponse['suggestions'][0]; index: number }) {
  const [expanded, setExpanded] = useState(index === 0)
  const admCode = `${suggestion.confidence_source}${suggestion.confidence_info}`
  const srcLabel = ADMIRALTY_SOURCE[suggestion.confidence_source] ?? suggestion.confidence_source
  const infoLabel = ADMIRALTY_ACCURACY[suggestion.confidence_info] ?? suggestion.confidence_info

  return (
    <div className="rounded-lg border border-[#2a2a3e] bg-bg-elevated">
      <button
        onClick={() => setExpanded(e => !e)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left"
      >
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-text-primary truncate">{suggestion.actor_name}</span>
            <span
              title={`Source: ${srcLabel} · Info: ${infoLabel}`}
              className="cursor-help shrink-0 rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-[10px] font-medium text-zinc-300"
            >
              {admCode}
            </span>
          </div>
          <div className="mt-0.5 flex gap-1 flex-wrap">
            {suggestion.match_types.map(mt => (
              <span key={mt} className="rounded bg-accent/20 px-1.5 py-0.5 text-[9px] font-medium text-accent-bright">
                {mt}
              </span>
            ))}
          </div>
        </div>
        {expanded ? <ChevronUp size={12} className="shrink-0 text-text-muted" /> : <ChevronDown size={12} className="shrink-0 text-text-muted" />}
      </button>
      {expanded && (
        <div className="border-t border-[#2a2a3e] px-3 py-2 space-y-2">
          <p className="text-[11px] text-text-primary leading-relaxed">{suggestion.rationale}</p>
          {suggestion.gaps && (
            <div>
              <p className="text-[10px] font-medium text-amber-400">Gaps</p>
              <p className="text-[11px] text-text-muted">{suggestion.gaps}</p>
            </div>
          )}
          {suggestion.alternative_hypothesis && (
            <div>
              <p className="text-[10px] font-medium text-purple-400">Alternative</p>
              <p className="text-[11px] text-text-muted">{suggestion.alternative_hypothesis}</p>
            </div>
          )}
          {suggestion.actor_id && (
            <Link
              to={`/actors/${suggestion.actor_id}`}
              className="inline-flex items-center gap-1 text-[10px] text-accent-bright hover:underline"
            >
              View actor profile <ExternalLink size={9} />
            </Link>
          )}
        </div>
      )}
    </div>
  )
}

// ── Detection card ────────────────────────────────────────────────────────────

function DetectionCard({
  detection, sessionId,
}: {
  detection: HuntDraftDetection
  sessionId: string
}) {
  const [expanded, setExpanded] = useState(false)
  const updateDetection = useUpdateDetection(sessionId)
  const promoteDetection = usePromoteDetection(sessionId)

  const colorClasses = PYRAMID_COLORS[detection.pyramid_tier] ?? 'bg-zinc-800 text-zinc-300'

  return (
    <div className="rounded-lg border border-[#2a2a3e] bg-bg-elevated">
      <button
        onClick={() => setExpanded(e => !e)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left"
      >
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-text-primary truncate">{detection.title}</span>
            <span className={cn('shrink-0 rounded px-1.5 py-0.5 text-[10px] font-medium', colorClasses)}>
              {detection.pyramid_tier}
            </span>
            <span className="shrink-0 rounded bg-zinc-800 px-1.5 py-0.5 text-[10px] text-zinc-400">
              {detection.rule_type}
            </span>
          </div>
          <p className="mt-0.5 text-[10px] text-text-muted capitalize">{detection.status}</p>
        </div>
        {expanded ? <ChevronUp size={12} className="shrink-0 text-text-muted" /> : <ChevronDown size={12} className="shrink-0 text-text-muted" />}
      </button>
      {expanded && (
        <div className="border-t border-[#2a2a3e] px-3 py-2 space-y-2">
          {detection.rationale && (
            <p className="text-[11px] text-text-muted leading-relaxed italic">{detection.rationale}</p>
          )}
          <CodeBlock
            code={detection.content}
            language={detection.rule_type}
            title={detection.title}
            expandable
          />
          <div className="flex gap-2">
            {detection.status !== 'reviewed' && (
              <button
                onClick={() => updateDetection.mutate({ id: detection.id, status: 'reviewed' })}
                className="flex items-center gap-1 rounded-md bg-green-900/40 px-2 py-1 text-[10px] font-medium text-green-300 hover:bg-green-900/60"
              >
                <CheckCircle size={10} />
                Mark reviewed
              </button>
            )}
            {detection.status === 'reviewed' && (
              <button
                onClick={() => promoteDetection.mutate(detection.id)}
                disabled={promoteDetection.isPending}
                className="flex items-center gap-1 rounded-md bg-accent/20 px-2 py-1 text-[10px] font-medium text-accent-bright hover:bg-accent/30 disabled:opacity-50"
              >
                <Zap size={10} />
                {promoteDetection.isPending ? 'Promoting...' : 'Promote to Rules'}
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Hypothesis refinement panel ───────────────────────────────────────────────

function RefinementPanel({ data }: { data: HypothesisRefinement }) {
  const PRIORITY_COLORS = { high: 'text-red-400', medium: 'text-amber-400', low: 'text-green-400' }

  return (
    <div className="space-y-3 text-xs">
      <div className="rounded-lg border border-[#2a2a3e] bg-bg-elevated p-3">
        <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-text-muted">Assessment</p>
        <p className="text-text-primary leading-relaxed">{data.assessment}</p>
      </div>
      {data.supporting_evidence.length > 0 && (
        <div>
          <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-green-400">Supporting evidence</p>
          <ul className="space-y-0.5">
            {data.supporting_evidence.map((e, i) => <li key={i} className="text-text-muted">• {e}</li>)}
          </ul>
        </div>
      )}
      {data.evidence_gaps.length > 0 && (
        <div>
          <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-amber-400">Evidence gaps</p>
          <ul className="space-y-0.5">
            {data.evidence_gaps.map((g, i) => <li key={i} className="text-text-muted">• {g}</li>)}
          </ul>
        </div>
      )}
      {data.recommended_pivots.length > 0 && (
        <div>
          <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-accent-bright">Recommended pivots</p>
          <div className="space-y-2">
            {data.recommended_pivots.map((p, i) => (
              <div key={i} className="rounded-md border border-[#2a2a3e] p-2">
                <div className="flex items-center gap-1.5 mb-0.5">
                  <span className={cn('text-[10px] font-medium', PRIORITY_COLORS[p.priority as keyof typeof PRIORITY_COLORS] ?? 'text-text-muted')}>
                    {p.priority}
                  </span>
                </div>
                <p className="text-text-primary">{p.action}</p>
                <p className="mt-0.5 text-text-muted text-[11px]">{p.rationale}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Markdown component map ────────────────────────────────────────────────────

const mdComponents: Components = {
  h1: ({ children }) => (
    <h1 className="mb-3 mt-6 text-sm font-bold text-text-primary first:mt-0 border-b border-[#2a2a3e] pb-2">{children}</h1>
  ),
  h2: ({ children }) => (
    <h2 className="mb-2 mt-5 text-xs font-semibold text-text-primary uppercase tracking-wide text-accent-bright">{children}</h2>
  ),
  h3: ({ children }) => (
    <h3 className="mb-1.5 mt-4 text-xs font-semibold text-text-primary">{children}</h3>
  ),
  p: ({ children }) => (
    <p className="mb-3 text-xs leading-relaxed text-text-muted">{children}</p>
  ),
  ul: ({ children }) => (
    <ul className="mb-3 ml-4 space-y-1 list-disc marker:text-text-muted">{children}</ul>
  ),
  ol: ({ children }) => (
    <ol className="mb-3 ml-4 space-y-1 list-decimal marker:text-text-muted">{children}</ol>
  ),
  li: ({ children }) => (
    <li className="text-xs text-text-muted leading-relaxed">{children}</li>
  ),
  strong: ({ children }) => (
    <strong className="font-semibold text-text-primary">{children}</strong>
  ),
  em: ({ children }) => (
    <em className="italic text-text-muted">{children}</em>
  ),
  a: ({ href, children }) => (
    <a href={href} target="_blank" rel="noreferrer" className="text-accent-bright hover:underline">
      {children}
    </a>
  ),
  hr: () => <hr className="my-4 border-[#2a2a3e]" />,
  blockquote: ({ children }) => (
    <blockquote className="my-3 border-l-2 border-accent pl-3 text-xs italic text-text-muted">
      {children}
    </blockquote>
  ),
  pre: ({ children }) => (
    <pre className="mb-3 overflow-x-auto rounded-lg border border-[#2a2a3e] bg-bg-base p-3 text-[11px] leading-relaxed">
      {children}
    </pre>
  ),
  code: ({ className, children }) => {
    const isBlock = /language-/.test(className ?? '')
    return isBlock ? (
      <code className={`font-mono text-text-primary ${className ?? ''}`}>{children}</code>
    ) : (
      <code className="rounded bg-bg-elevated px-1 py-0.5 font-mono text-[11px] text-accent-bright">
        {children}
      </code>
    )
  },
  table: ({ children }) => (
    <div className="mb-3 overflow-x-auto rounded-lg border border-[#2a2a3e]">
      <table className="w-full text-xs border-collapse">{children}</table>
    </div>
  ),
  thead: ({ children }) => (
    <thead className="border-b border-[#2a2a3e] bg-bg-elevated">{children}</thead>
  ),
  tbody: ({ children }) => (
    <tbody className="divide-y divide-[#2a2a3e]">{children}</tbody>
  ),
  tr: ({ children }) => <tr className="transition-colors hover:bg-bg-elevated/50">{children}</tr>,
  th: ({ children }) => (
    <th className="px-3 py-2 text-left text-[10px] font-semibold uppercase tracking-wide text-text-muted">
      {children}
    </th>
  ),
  td: ({ children }) => (
    <td className="px-3 py-2 text-text-muted">{children}</td>
  ),
}

// ── Export menu ───────────────────────────────────────────────────────────────

function ExportMenu({ sessionId }: { sessionId: string }) {
  const [open, setOpen] = useState(false)
  const [exporting, setExporting] = useState(false)
  const menuRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    function onClickOutside(e: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onClickOutside)
    return () => document.removeEventListener('mousedown', onClickOutside)
  }, [])

  async function doExport(format: 'markdown' | 'stix' | 'pdf', template?: 'executive' | 'technical') {
    setOpen(false)
    setExporting(true)
    try {
      await exportHunt(sessionId, format, template)
    } finally {
      setExporting(false)
    }
  }

  const items: { label: string; desc: string; fn: () => void }[] = [
    { label: 'Markdown (.md)', desc: 'Full hunt notes + IOCs', fn: () => doExport('markdown') },
    { label: 'STIX Bundle (.json)', desc: 'STIX 2.1 indicators & TTPs', fn: () => doExport('stix') },
    { label: 'PDF — Executive', desc: 'High-level summary report', fn: () => doExport('pdf', 'executive') },
    { label: 'PDF — Technical', desc: 'Full IOC/detection detail', fn: () => doExport('pdf', 'technical') },
  ]

  return (
    <div className="relative" ref={menuRef}>
      <button
        onClick={() => setOpen(v => !v)}
        disabled={exporting}
        className="flex items-center gap-1.5 rounded-lg border border-[#2a2a3e] bg-bg-surface px-3 py-1.5 text-xs font-medium text-text-primary hover:bg-bg-elevated disabled:opacity-40"
      >
        {exporting ? <Loader2 size={11} className="animate-spin" /> : <Download size={11} className="text-green-400" />}
        Export
        <ChevronDown size={10} className={cn('text-text-muted transition-transform', open && 'rotate-180')} />
      </button>

      {open && (
        <div className="absolute right-0 top-full z-30 mt-1 w-52 rounded-xl border border-[#2a2a3e] bg-bg-surface shadow-lg">
          {items.map(item => (
            <button
              key={item.label}
              onClick={item.fn}
              className="flex w-full flex-col items-start gap-0.5 px-3 py-2.5 text-left first:rounded-t-xl last:rounded-b-xl hover:bg-bg-elevated"
            >
              <span className="text-xs font-medium text-text-primary">{item.label}</span>
              <span className="text-[10px] text-text-muted">{item.desc}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Main workbench ────────────────────────────────────────────────────────────

export function HuntWorkbench() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()

  const { data: hunt, isLoading } = useHunt(id!)
  const { data: noteData } = useHuntNotes(id!)
  const { data: detections = [] } = useHuntDetections(id!)

  const addObs = useAddObservation(id!)
  const removeObs = useRemoveObservation(id!)
  const upsertNotes = useUpsertNotes(id!)
  const draftDetection = useDraftDetection(id!)
  const suggestActors = useSuggestActors(id!)
  const refineHypo = useRefineHypothesis(id!)
  const updateHunt = useUpdateHunt(id!)

  // Cached Claude results — survive navigation via React Query cache
  const { data: actorSuggestions = null } = useCachedActorSuggestions(id!)
  const { data: refinement = null } = useCachedHypothesisRefinement(id!)

  // Observation input state
  const [obsType, setObsType] = useState('ioc_ip')
  const [obsValue, setObsValue] = useState('')
  const [obsNote, setObsNote] = useState('')
  const [selectedObs, setSelectedObs] = useState<Set<string>>(new Set())

  // Notes state
  const [noteContent, setNoteContent] = useState('')
  const [noteMode, setNoteMode] = useState<'edit' | 'preview'>('edit')
  const noteSaveTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Right panel state — default to suggestions if cached results exist
  const [rightPanel, setRightPanel] = useState<'suggestions' | 'refine' | 'detections'>(() =>
    actorSuggestions ? 'suggestions' : 'detections'
  )
  const [draftRuleType, setDraftRuleType] = useState('sigma')

  // Hypothesis editing
  const [editingHypo, setEditingHypo] = useState(false)
  const [hypoValue, setHypoValue] = useState('')

  useEffect(() => {
    if (noteData) setNoteContent(noteData.content)
  }, [noteData])

  // Autosave notes with debounce
  function handleNoteChange(value: string) {
    setNoteContent(value)
    if (noteSaveTimer.current) clearTimeout(noteSaveTimer.current)
    noteSaveTimer.current = setTimeout(() => {
      upsertNotes.mutate(value)
    }, 1500)
  }

  function toggleObs(obsId: string) {
    setSelectedObs(prev => {
      const next = new Set(prev)
      if (next.has(obsId)) next.delete(obsId)
      else next.add(obsId)
      return next
    })
  }

  async function handleAddObs(e: React.FormEvent) {
    e.preventDefault()
    if (!obsValue.trim()) return
    await addObs.mutateAsync({ obs_type: obsType, value: obsValue.trim(), notes: obsNote.trim() || undefined })
    setObsValue('')
    setObsNote('')
  }

  async function handleSuggestActors() {
    setRightPanel('suggestions')
    await suggestActors.mutateAsync()
  }

  async function handleRefine() {
    setRightPanel('refine')
    await refineHypo.mutateAsync()
  }

  async function handleDraftDetection() {
    if (selectedObs.size === 0) return
    await draftDetection.mutateAsync({ obs_ids: [...selectedObs], rule_type: draftRuleType })
    setSelectedObs(new Set())
    setRightPanel('detections')
  }

  async function saveHypothesis() {
    await updateHunt.mutateAsync({ hypothesis: hypoValue })
    setEditingHypo(false)
  }

  if (isLoading) {
    return (
      <div className="flex min-h-[60vh] items-center justify-center">
        <Loader2 size={20} className="animate-spin text-text-muted" />
      </div>
    )
  }

  if (!hunt) {
    return <div className="py-12 text-center text-sm text-text-muted">Hunt session not found.</div>
  }

  const allObs = hunt.observations ?? []
  const hasSelectedObs = selectedObs.size > 0

  return (
    <div className="flex min-h-screen flex-col">
      {/* Header */}
      <div className="mb-4 flex items-start gap-3">
        <button onClick={() => navigate('/hunt')} className="mt-1 rounded-md p-1 text-text-muted hover:text-text-primary">
          <ArrowLeft size={15} />
        </button>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 flex-wrap">
            <h1 className="text-base font-bold text-text-primary">{hunt.name}</h1>
            <span className={cn(
              'rounded-full px-2 py-0.5 text-[10px] font-medium',
              hunt.status === 'active' ? 'bg-green-900/60 text-green-300 border border-green-700/40'
                : 'bg-zinc-800 text-zinc-400',
            )}>
              {hunt.status}
            </span>
            {hunt.analyst && <span className="text-xs text-text-muted">by {hunt.analyst}</span>}
          </div>

          {/* Hypothesis */}
          <div className="mt-1">
            {editingHypo ? (
              <div className="flex items-start gap-2">
                <textarea
                  value={hypoValue}
                  onChange={e => setHypoValue(e.target.value)}
                  rows={2}
                  autoFocus
                  className="flex-1 resize-none rounded-md border border-accent/50 bg-bg-elevated px-2 py-1 text-xs text-text-primary focus:outline-none"
                />
                <button onClick={saveHypothesis} className="rounded-md bg-accent px-2 py-1 text-[11px] font-medium text-white">Save</button>
                <button onClick={() => setEditingHypo(false)} className="rounded-md px-2 py-1 text-[11px] text-text-muted">Cancel</button>
              </div>
            ) : (
              <button
                onClick={() => { setHypoValue(hunt.hypothesis ?? ''); setEditingHypo(true) }}
                className="group flex items-center gap-1 text-xs text-text-muted hover:text-text-primary"
              >
                <span className="italic">{hunt.hypothesis || 'Add hypothesis...'}</span>
                <Edit3 size={11} className="opacity-0 group-hover:opacity-100" />
              </button>
            )}
          </div>
        </div>

        {/* Claude action buttons + Export */}
        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={handleSuggestActors}
            disabled={suggestActors.isPending || allObs.length === 0}
            className="flex items-center gap-1.5 rounded-lg border border-[#2a2a3e] bg-bg-surface px-3 py-1.5 text-xs font-medium text-text-primary hover:bg-bg-elevated disabled:opacity-40"
          >
            {suggestActors.isPending ? <Loader2 size={11} className="animate-spin" /> : <Sparkles size={11} className="text-purple-400" />}
            Suggest Actors
          </button>
          <button
            onClick={handleRefine}
            disabled={refineHypo.isPending || allObs.length === 0}
            className="flex items-center gap-1.5 rounded-lg border border-[#2a2a3e] bg-bg-surface px-3 py-1.5 text-xs font-medium text-text-primary hover:bg-bg-elevated disabled:opacity-40"
          >
            {refineHypo.isPending ? <Loader2 size={11} className="animate-spin" /> : <Brain size={11} className="text-blue-400" />}
            Refine Hypothesis
          </button>
          <ExportMenu sessionId={id!} />
        </div>
      </div>

      {/* Three-panel layout */}
      <div className="grid flex-1 gap-4" style={{ gridTemplateColumns: '280px 1fr 320px' }}>

        {/* LEFT: Observations */}
        <div className="flex flex-col gap-3">
          <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface">
            <div className="border-b border-[#2a2a3e] px-3 py-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-text-primary">Observations</span>
                <span className="text-[11px] text-text-muted">{allObs.length}</span>
              </div>
            </div>

            {/* Add form */}
            <form onSubmit={handleAddObs} className="border-b border-[#2a2a3e] p-3 space-y-2">
              <select
                value={obsType}
                onChange={e => setObsType(e.target.value)}
                className="w-full rounded-md border border-[#2a2a3e] bg-bg-elevated px-2 py-1.5 text-xs text-text-primary focus:outline-none"
              >
                {OBS_TYPES.map(t => (
                  <option key={t.value} value={t.value}>{t.label}</option>
                ))}
              </select>
              <input
                value={obsValue}
                onChange={e => setObsValue(e.target.value)}
                placeholder="Value..."
                className="w-full rounded-md border border-[#2a2a3e] bg-bg-elevated px-2 py-1.5 font-mono text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
              />
              <input
                value={obsNote}
                onChange={e => setObsNote(e.target.value)}
                placeholder="Note (optional)"
                className="w-full rounded-md border border-[#2a2a3e] bg-bg-elevated px-2 py-1.5 text-xs text-text-primary placeholder-text-muted focus:outline-none"
              />
              <button
                type="submit"
                disabled={!obsValue.trim() || addObs.isPending}
                className="flex w-full items-center justify-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-white hover:opacity-90 disabled:opacity-50"
              >
                {addObs.isPending ? <Loader2 size={11} className="animate-spin" /> : <Plus size={11} />}
                Add
              </button>
            </form>

            {/* Obs list */}
            <div className="max-h-[380px] overflow-y-auto p-2 space-y-0.5">
              {allObs.length === 0 ? (
                <p className="py-4 text-center text-[11px] text-text-muted">No observations yet</p>
              ) : (
                allObs.map(obs => (
                  <ObsRow
                    key={obs.id}
                    obs={obs}
                    selected={selectedObs.has(obs.id)}
                    onToggle={() => toggleObs(obs.id)}
                    onDelete={() => removeObs.mutate(obs.id)}
                  />
                ))
              )}
            </div>
          </div>

          {/* Draft detection from selection */}
          {hasSelectedObs && (
            <div className="rounded-xl border border-accent/30 bg-accent/5 p-3 space-y-2">
              <p className="text-xs font-medium text-accent-bright">
                {selectedObs.size} selected — draft a detection
              </p>
              <div className="flex gap-2">
                <select
                  value={draftRuleType}
                  onChange={e => setDraftRuleType(e.target.value)}
                  className="flex-1 rounded-md border border-[#2a2a3e] bg-bg-elevated px-2 py-1.5 text-xs text-text-primary focus:outline-none"
                >
                  {RULE_TYPES.map(rt => <option key={rt} value={rt}>{rt.toUpperCase()}</option>)}
                </select>
                <button
                  onClick={handleDraftDetection}
                  disabled={draftDetection.isPending}
                  className="flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-xs font-semibold text-white hover:opacity-90 disabled:opacity-50"
                >
                  {draftDetection.isPending ? <Loader2 size={11} className="animate-spin" /> : <Zap size={11} />}
                  {draftDetection.isPending ? 'Drafting...' : 'Draft'}
                </button>
              </div>
            </div>
          )}

          {/* Pyramid of Pain */}
          <PyramidStrip detections={detections} />
        </div>

        {/* CENTER: Notes */}
        <div className="flex flex-col rounded-xl border border-[#2a2a3e] bg-bg-surface">
          <div className="flex items-center justify-between border-b border-[#2a2a3e] px-4 py-2">
            <div className="flex items-center gap-2">
              <FileText size={13} className="text-text-muted" />
              <span className="text-xs font-semibold text-text-primary">Hunt Notes</span>
              {upsertNotes.isPending && <span className="text-[10px] text-text-muted">saving...</span>}
            </div>
            <div className="flex items-center gap-1 rounded-md border border-[#2a2a3e] p-0.5">
              <button
                onClick={() => setNoteMode('edit')}
                className={cn(
                  'flex items-center gap-1 rounded px-2 py-1 text-[11px] transition-colors',
                  noteMode === 'edit' ? 'bg-bg-elevated text-text-primary' : 'text-text-muted hover:text-text-primary',
                )}
              >
                <Edit3 size={10} /> Edit
              </button>
              <button
                onClick={() => setNoteMode('preview')}
                className={cn(
                  'flex items-center gap-1 rounded px-2 py-1 text-[11px] transition-colors',
                  noteMode === 'preview' ? 'bg-bg-elevated text-text-primary' : 'text-text-muted hover:text-text-primary',
                )}
              >
                <Eye size={10} /> Preview
              </button>
            </div>
          </div>

          {noteMode === 'edit' ? (
            <textarea
              value={noteContent}
              onChange={e => handleNoteChange(e.target.value)}
              placeholder={'# Hunt notes\n\nStart documenting your findings...\n\n## Pivot 1\n\n'}
              className="flex-1 resize-none bg-transparent p-4 font-mono text-xs text-text-primary placeholder-text-muted focus:outline-none"
              style={{ minHeight: '500px' }}
            />
          ) : (
            <div className="flex-1 overflow-y-auto p-4">
              {noteContent ? (
                <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents}>
                  {noteContent}
                </ReactMarkdown>
              ) : (
                <p className="text-xs italic text-text-muted">Nothing written yet. Switch to Edit to start.</p>
              )}
            </div>
          )}
        </div>

        {/* RIGHT: Actor suggestions / refinement / detections */}
        <div className="flex flex-col gap-3">
          {/* Panel tabs */}
          <div className="flex items-center gap-1 rounded-xl border border-[#2a2a3e] bg-bg-surface p-1">
            {[
              { key: 'detections', label: 'Detections', icon: Shield },
              { key: 'suggestions', label: 'Actors', icon: Target },
              { key: 'refine', label: 'Analysis', icon: Brain },
            ].map(tab => (
              <button
                key={tab.key}
                onClick={() => setRightPanel(tab.key as typeof rightPanel)}
                className={cn(
                  'flex flex-1 items-center justify-center gap-1.5 rounded-lg py-1.5 text-[11px] font-medium transition-colors',
                  rightPanel === tab.key
                    ? 'bg-bg-elevated text-text-primary'
                    : 'text-text-muted hover:text-text-primary',
                )}
              >
                <tab.icon size={11} />
                {tab.label}
                {tab.key === 'detections' && detections.length > 0 && (
                  <span className="rounded-full bg-accent/30 px-1.5 text-[9px] text-accent-bright">{detections.length}</span>
                )}
              </button>
            ))}
          </div>

          {/* Detections panel */}
          {rightPanel === 'detections' && (
            <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface">
              <div className="border-b border-[#2a2a3e] px-3 py-2">
                <span className="text-xs font-semibold text-text-primary">Draft Detections</span>
                <p className="mt-0.5 text-[10px] text-text-muted">
                  Select observations on the left, then click Draft.
                </p>
              </div>
              <div className="max-h-[560px] overflow-y-auto p-2 space-y-2">
                {detections.length === 0 ? (
                  <div className="py-8 text-center">
                    <Wrench size={20} className="mx-auto mb-2 text-text-muted" />
                    <p className="text-xs text-text-muted">No detections yet</p>
                    <p className="mt-1 text-[11px] text-text-muted">Select observations and click Draft.</p>
                  </div>
                ) : (
                  detections.map(d => (
                    <DetectionCard key={d.id} detection={d} sessionId={id!} />
                  ))
                )}
              </div>
            </div>
          )}

          {/* Actor suggestions panel */}
          {rightPanel === 'suggestions' && (
            <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface">
              <div className="border-b border-[#2a2a3e] px-3 py-2 flex items-center justify-between">
                <div>
                  <span className="text-xs font-semibold text-text-primary">Actor Suggestions</span>
                  <p className="mt-0.5 text-[10px] text-text-muted">Powered by Claude + Pythia actor DB</p>
                </div>
                <button
                  onClick={handleSuggestActors}
                  disabled={suggestActors.isPending || allObs.length === 0}
                  className="flex items-center gap-1 rounded-md bg-accent/20 px-2 py-1 text-[10px] font-medium text-accent-bright hover:bg-accent/30 disabled:opacity-50"
                >
                  {suggestActors.isPending ? <Loader2 size={10} className="animate-spin" /> : <Sparkles size={10} />}
                  Refresh
                </button>
              </div>
              <div className="max-h-[560px] overflow-y-auto p-2 space-y-2">
                {suggestActors.isPending ? (
                  <div className="flex flex-col items-center gap-2 py-12">
                    <Loader2 size={18} className="animate-spin text-accent-bright" />
                    <p className="text-xs text-text-muted">Claude is analyzing your observations...</p>
                  </div>
                ) : actorSuggestions ? (
                  <>
                    {actorSuggestions.suggestions.length === 0 ? (
                      <p className="py-4 text-center text-xs text-text-muted">
                        Not enough observations for attribution.
                      </p>
                    ) : (
                      actorSuggestions.suggestions.map((s, i) => (
                        <ActorCard key={i} suggestion={s} index={i} />
                      ))
                    )}
                    {actorSuggestions.analyst_notes && (
                      <div className="rounded-md border border-[#2a2a3e] bg-bg-elevated p-2 mt-2">
                        <p className="text-[10px] font-medium text-text-muted mb-0.5">Analyst notes</p>
                        <p className="text-[11px] text-text-primary">{actorSuggestions.analyst_notes}</p>
                      </div>
                    )}
                  </>
                ) : (
                  <div className="flex flex-col items-center gap-2 py-12">
                    <Sparkles size={20} className="text-text-muted" />
                    <p className="text-xs text-text-muted text-center">
                      Click "Suggest Actors" to get AI-powered attribution analysis based on your observations.
                    </p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Hypothesis refinement panel */}
          {rightPanel === 'refine' && (
            <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface">
              <div className="border-b border-[#2a2a3e] px-3 py-2 flex items-center justify-between">
                <div>
                  <span className="text-xs font-semibold text-text-primary">Hypothesis Analysis</span>
                  <p className="mt-0.5 text-[10px] text-text-muted">Claude stress-tests your hypothesis</p>
                </div>
                <button
                  onClick={handleRefine}
                  disabled={refineHypo.isPending || allObs.length === 0}
                  className="flex items-center gap-1 rounded-md bg-blue-900/40 px-2 py-1 text-[10px] font-medium text-blue-300 hover:bg-blue-900/60 disabled:opacity-50"
                >
                  {refineHypo.isPending ? <Loader2 size={10} className="animate-spin" /> : <Brain size={10} />}
                  Refresh
                </button>
              </div>
              <div className="max-h-[560px] overflow-y-auto p-3">
                {refineHypo.isPending ? (
                  <div className="flex flex-col items-center gap-2 py-12">
                    <Loader2 size={18} className="animate-spin text-blue-400" />
                    <p className="text-xs text-text-muted">Claude is analyzing your hypothesis...</p>
                  </div>
                ) : refinement ? (
                  <RefinementPanel data={refinement} />
                ) : (
                  <div className="flex flex-col items-center gap-2 py-12">
                    <Brain size={20} className="text-text-muted" />
                    <p className="text-xs text-text-muted text-center">
                      Click "Refine Hypothesis" to get an AI critique with gap analysis and recommended pivots.
                    </p>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
