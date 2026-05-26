import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { Pencil, Trash2, X, Check } from 'lucide-react'
import { useRule, useUpdateRule, useDeleteRule } from '@/api/rules'
import { SeverityBadge } from '@/components/shared/SeverityBadge'
import { TechniqueTag } from '@/components/shared/TechniqueTag'
import { CodeBlock } from '@/components/shared/CodeBlock'
import { Breadcrumb } from '@/components/layout/Breadcrumb'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational']
const STATUSES = ['stable', 'test', 'experimental', 'deprecated']

export function RuleDetail() {
  const { type, id } = useParams<{ type: string; id: string }>()
  const navigate = useNavigate()
  const { data: rule, isLoading, error } = useRule(type ?? '', id ?? '')
  const updateMutation = useUpdateRule(id ?? '')
  const deleteMutation = useDeleteRule()

  const [editing, setEditing] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState(false)
  const [editError, setEditError] = useState<string | null>(null)

  // Edit form state — seeded from rule when edit opens
  const [editTitle, setEditTitle] = useState('')
  const [editContent, setEditContent] = useState('')
  const [editSeverity, setEditSeverity] = useState('')
  const [editStatus, setEditStatus] = useState('')
  const [editTechniqueIds, setEditTechniqueIds] = useState('')
  const [editSourceUrl, setEditSourceUrl] = useState('')

  useEffect(() => {
    if (rule && editing) {
      setEditTitle(rule.title)
      setEditContent(rule.content ?? '')
      setEditSeverity(rule.severity ?? '')
      setEditStatus(rule.status ?? '')
      setEditTechniqueIds(rule.technique_ids.join(', '))
      setEditSourceUrl(rule.source_url ?? '')
    }
  }, [rule, editing])

  if (isLoading) return <div className="py-16 text-center text-sm text-text-muted">Loading…</div>
  if (error || !rule) return <div className="py-16 text-center text-sm text-red-400">Rule not found.</div>

  function handleSave() {
    if (!editTitle.trim()) { setEditError('Title is required.'); return }
    if (!editContent.trim()) { setEditError('Content is required.'); return }
    setEditError(null)

    const techniqueList = editTechniqueIds
      .split(/[\s,]+/)
      .map(t => t.trim().toUpperCase())
      .filter(Boolean)

    updateMutation.mutate(
      {
        title: editTitle.trim(),
        content: editContent,
        severity: editSeverity || undefined,
        status: editStatus || undefined,
        technique_ids: techniqueList,
        source_url: editSourceUrl.trim() || undefined,
      },
      {
        onSuccess: () => setEditing(false),
        onError: (e: Error) => setEditError(e.message),
      },
    )
  }

  function handleDelete() {
    deleteMutation.mutate(rule!.id, {
      onSuccess: () => navigate('/rules'),
      onError: (e: Error) => setEditError(e.message),
    })
  }

  // ── View mode ──────────────────────────────────────────────────────────────
  if (!editing) {
    return (
      <div>
        <Breadcrumb crumbs={[{ label: 'Rules', to: '/rules' }, { label: rule.title }]} />

        <div className="mb-6 rounded-xl border border-[#2a2a3e] bg-bg-surface p-6">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="flex-1">
              <h1 className="text-lg font-semibold text-text-primary">{rule.title}</h1>
              <div className="mt-2 flex flex-wrap items-center gap-2">
                {rule.severity && <SeverityBadge severity={rule.severity} />}
                <span className="rounded bg-bg-elevated px-2 py-0.5 text-xs font-mono text-text-muted uppercase">
                  {rule.rule_type}
                </span>
                {rule.status && (
                  <span className="text-xs text-text-muted">{rule.status}</span>
                )}
                {rule.source_url && (
                  <a href={rule.source_url} target="_blank" rel="noreferrer"
                    className="text-xs text-accent-bright hover:underline">
                    Source ↗
                  </a>
                )}
              </div>
              {rule.technique_ids.length > 0 && (
                <div className="mt-3 flex flex-wrap gap-1">
                  {rule.technique_ids.map(tid => <TechniqueTag key={tid} id={tid} />)}
                </div>
              )}
            </div>

            {/* Actions */}
            <div className="flex items-center gap-2">
              <button
                onClick={() => { setEditing(true); setConfirmDelete(false) }}
                className="flex items-center gap-1.5 rounded-lg border border-[#2a2a3e] px-3 py-1.5 text-xs text-text-muted hover:text-text-primary transition-colors"
              >
                <Pencil size={13} /> Edit
              </button>

              {confirmDelete ? (
                <div className="flex items-center gap-2 rounded-lg border border-red-900 bg-red-900/20 px-3 py-1.5">
                  <span className="text-xs text-red-400">Delete rule?</span>
                  <button
                    onClick={handleDelete}
                    disabled={deleteMutation.isPending}
                    className="text-xs font-medium text-red-400 hover:text-red-300 disabled:opacity-50"
                  >
                    {deleteMutation.isPending ? 'Deleting…' : 'Yes, delete'}
                  </button>
                  <button
                    onClick={() => setConfirmDelete(false)}
                    className="text-text-muted hover:text-text-primary"
                  >
                    <X size={13} />
                  </button>
                </div>
              ) : (
                <button
                  onClick={() => setConfirmDelete(true)}
                  className="flex items-center gap-1.5 rounded-lg border border-[#2a2a3e] px-3 py-1.5 text-xs text-text-muted hover:text-red-400 hover:border-red-900 transition-colors"
                >
                  <Trash2 size={13} /> Delete
                </button>
              )}
            </div>
          </div>
        </div>

        {rule.content ? (
          <CodeBlock
            code={rule.content}
            language={rule.rule_type === 'sigma' ? 'yaml' : 'text'}
          />
        ) : (
          <div className="py-8 text-center text-xs text-text-muted">No rule content available.</div>
        )}
      </div>
    )
  }

  // ── Edit mode ──────────────────────────────────────────────────────────────
  return (
    <div>
      <Breadcrumb crumbs={[{ label: 'Rules', to: '/rules' }, { label: rule.title }, { label: 'Edit' }]} />

      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-base font-semibold text-text-primary">Edit Rule</h1>
        <div className="flex items-center gap-2">
          <button
            onClick={() => { setEditing(false); setEditError(null) }}
            className="flex items-center gap-1.5 rounded-lg border border-[#2a2a3e] px-3 py-1.5 text-xs text-text-muted hover:text-text-primary transition-colors"
          >
            <X size={13} /> Cancel
          </button>
          <button
            onClick={handleSave}
            disabled={updateMutation.isPending}
            className="flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-xs font-medium text-white hover:opacity-90 transition-opacity disabled:opacity-50"
          >
            <Check size={13} /> {updateMutation.isPending ? 'Saving…' : 'Save changes'}
          </button>
        </div>
      </div>

      <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface p-5">
        <div className="grid gap-4 lg:grid-cols-[1fr_2fr]">
          {/* Left — metadata */}
          <div className="space-y-3">
            <div>
              <label className="block mb-1 text-xs text-text-muted">Type</label>
              <span className="inline-block rounded bg-bg-elevated px-2 py-1 text-xs font-mono text-text-muted uppercase">
                {rule.rule_type}
              </span>
            </div>

            <div>
              <label className="block mb-1 text-xs text-text-muted">Title <span className="text-red-400">*</span></label>
              <input
                value={editTitle}
                onChange={e => setEditTitle(e.target.value)}
                className="w-full rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2 text-xs text-text-primary focus:outline-none focus:ring-1 focus:ring-accent-bright"
              />
            </div>

            <div>
              <label className="block mb-1 text-xs text-text-muted">Severity</label>
              <select
                value={editSeverity}
                onChange={e => setEditSeverity(e.target.value)}
                className="w-full rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2 text-xs text-text-primary focus:outline-none"
              >
                <option value="">— none —</option>
                {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>

            <div>
              <label className="block mb-1 text-xs text-text-muted">Status</label>
              <select
                value={editStatus}
                onChange={e => setEditStatus(e.target.value)}
                className="w-full rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2 text-xs text-text-primary focus:outline-none"
              >
                <option value="">— none —</option>
                {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>

            <div>
              <label className="block mb-1 text-xs text-text-muted">
                ATT&CK Technique IDs
                <span className="ml-1 font-normal text-text-muted">(comma separated)</span>
              </label>
              <input
                value={editTechniqueIds}
                onChange={e => setEditTechniqueIds(e.target.value)}
                placeholder="T1059.001, T1027"
                className="w-full rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
              />
            </div>

            <div>
              <label className="block mb-1 text-xs text-text-muted">Source URL</label>
              <input
                value={editSourceUrl}
                onChange={e => setEditSourceUrl(e.target.value)}
                placeholder="https://github.com/..."
                className="w-full rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
              />
            </div>

            {editError && <p className="text-xs text-red-400">{editError}</p>}
          </div>

          {/* Right — content */}
          <div>
            <label className="block mb-1 text-xs text-text-muted">
              Rule content <span className="text-red-400">*</span>
              <span className="ml-1 font-normal">({rule.rule_type === 'sigma' ? 'YAML' : 'YARA'})</span>
            </label>
            <textarea
              value={editContent}
              onChange={e => setEditContent(e.target.value)}
              rows={24}
              spellCheck={false}
              className="w-full rounded-lg border border-[#2a2a3e] bg-[#0d0d14] px-3 py-2 font-mono text-xs text-text-primary focus:outline-none focus:ring-1 focus:ring-accent-bright resize-y leading-relaxed"
            />
          </div>
        </div>
      </div>
    </div>
  )
}
