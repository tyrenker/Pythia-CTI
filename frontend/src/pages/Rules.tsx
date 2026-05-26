import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Plus, X, Trash2 } from 'lucide-react'
import { useRules, useCreateRule, useDeleteRule } from '@/api/rules'
import { SeverityBadge } from '@/components/shared/SeverityBadge'
import { TechniqueTag } from '@/components/shared/TechniqueTag'
import { DataTable } from '@/components/shared/DataTable'
import { RULE_SOURCE_LABELS } from '@/lib/constants'
import type { DetectionRule } from '@/types/api'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational']
const STATUSES = ['stable', 'test', 'experimental', 'deprecated']
const RULE_SOURCES = Object.entries(RULE_SOURCE_LABELS)

const SIGMA_PLACEHOLDER = `title: Suspicious PowerShell Encoded Command
status: experimental
description: Detects suspicious use of encoded PowerShell commands
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '-EncodedCommand'
    condition: selection
falsepositives:
    - Legitimate administrative scripts
level: high
tags:
    - attack.execution
    - attack.t1059.001`

const YARA_PLACEHOLDER = `rule SuspiciousPowerShell {
    meta:
        description = "Detects suspicious PowerShell patterns"
        severity = "high"
    strings:
        $enc = "-EncodedCommand" nocase
        $bypass = "bypass" nocase
    condition:
        any of them
}`

export function Rules() {
  const navigate = useNavigate()
  const [ruleType, setRuleType] = useState('')
  const [severity, setSeverity] = useState('')
  const [techniqueId, setTechniqueId] = useState('')
  const [ruleSource, setRuleSource] = useState('')
  const [showForm, setShowForm] = useState(false)

  // Form state
  const [formType, setFormType] = useState<'sigma' | 'yara'>('sigma')
  const [formTitle, setFormTitle] = useState('')
  const [formContent, setFormContent] = useState('')
  const [formSeverity, setFormSeverity] = useState('')
  const [formStatus, setFormStatus] = useState('')
  const [formTechniqueIds, setFormTechniqueIds] = useState('')
  const [formSourceUrl, setFormSourceUrl] = useState('')
  const [formError, setFormError] = useState<string | null>(null)
  const [successMsg, setSuccessMsg] = useState<string | null>(null)

  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null)

  const { data: rawData, isLoading } = useRules({
    rule_type: ruleType || undefined,
    severity: severity || undefined,
    technique_id: techniqueId || undefined,
  })

  const data = ruleSource
    ? (rawData ?? []).filter(r => r.source_url?.includes(ruleSource))
    : rawData

  const createMutation = useCreateRule()
  const deleteMutation = useDeleteRule()

  function resetForm() {
    setFormTitle('')
    setFormContent('')
    setFormSeverity('')
    setFormStatus('')
    setFormTechniqueIds('')
    setFormSourceUrl('')
    setFormError(null)
  }

  function handleCreate() {
    if (!formTitle.trim()) { setFormError('Title is required.'); return }
    if (!formContent.trim()) { setFormError('Rule content is required.'); return }
    setFormError(null)

    const techniqueList = formTechniqueIds
      .split(/[\s,]+/)
      .map(t => t.trim().toUpperCase())
      .filter(Boolean)

    createMutation.mutate(
      {
        rule_type: formType,
        title: formTitle.trim(),
        content: formContent,
        severity: formSeverity || undefined,
        status: formStatus || undefined,
        technique_ids: techniqueList,
        source_url: formSourceUrl.trim() || undefined,
      },
      {
        onSuccess: (rule) => {
          setSuccessMsg(`Rule "${rule.title}" created.`)
          setTimeout(() => setSuccessMsg(null), 4000)
          resetForm()
          setShowForm(false)
          navigate(`/rules/${rule.rule_type}/${rule.id}`)
        },
        onError: (e: Error) => setFormError(e.message),
      },
    )
  }

  const columns = [
    {
      key: 'title',
      header: 'Title',
      sortable: true,
      render: (r: DetectionRule) => (
        <span className="font-medium text-text-primary">{r.title}</span>
      ),
    },
    {
      key: 'rule_type',
      header: 'Type',
      sortable: true,
      render: (r: DetectionRule) => (
        <span className="font-mono text-xs text-text-muted uppercase">{r.rule_type}</span>
      ),
    },
    {
      key: 'severity',
      header: 'Severity',
      sortable: true,
      render: (r: DetectionRule) =>
        r.severity ? <SeverityBadge severity={r.severity} /> : <span className="text-text-muted">—</span>,
    },
    {
      key: 'source_url',
      header: 'Source',
      render: (r: DetectionRule) => {
        const label = Object.entries(RULE_SOURCE_LABELS).find(([key]) => r.source_url?.includes(key))?.[1] ?? (r.source_url ? 'local' : '—')
        return <span className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-400">{label}</span>
      },
    },
    {
      key: 'technique_ids',
      header: 'Techniques',
      render: (r: DetectionRule) => (
        <div className="flex flex-wrap gap-1" onClick={e => e.stopPropagation()}>
          {r.technique_ids.slice(0, 3).map(id => (
            <TechniqueTag key={id} id={id} />
          ))}
          {r.technique_ids.length > 3 && (
            <span className="text-xs text-text-muted">+{r.technique_ids.length - 3}</span>
          )}
        </div>
      ),
    },
    {
      key: 'actions',
      header: '',
      className: 'w-28 text-right',
      render: (r: DetectionRule) => (
        <div className="flex items-center justify-end gap-1" onClick={e => e.stopPropagation()}>
          {deleteConfirmId === r.id ? (
            <>
              <button
                onClick={() => deleteMutation.mutate(r.id, { onSuccess: () => setDeleteConfirmId(null) })}
                disabled={deleteMutation.isPending}
                className="text-xs text-red-400 hover:text-red-300 disabled:opacity-50"
              >
                Confirm
              </button>
              <button onClick={() => setDeleteConfirmId(null)} className="text-text-muted hover:text-text-primary ml-1">
                <X size={12} />
              </button>
            </>
          ) : (
            <button
              onClick={() => setDeleteConfirmId(r.id)}
              className="rounded p-1 text-text-muted hover:text-red-400 transition-colors"
              title="Delete rule"
            >
              <Trash2 size={13} />
            </button>
          )}
        </div>
      ),
    },
  ]

  return (
    <div>
      {/* Header */}
      <div className="mb-6 flex flex-wrap items-center gap-3">
        <h1 className="text-lg font-semibold text-text-primary">Detection Rules</h1>
        <div className="ml-auto flex flex-wrap items-center gap-3">
          <input
            value={techniqueId}
            onChange={e => setTechniqueId(e.target.value)}
            placeholder="Technique ID..."
            className="rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-1.5 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
          />
          <select
            value={ruleType}
            onChange={e => setRuleType(e.target.value)}
            className="rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-1.5 text-xs text-text-primary focus:outline-none"
          >
            <option value="">All types</option>
            <option value="sigma">Sigma</option>
            <option value="yara">YARA</option>
          </select>
          <select
            value={severity}
            onChange={e => setSeverity(e.target.value)}
            className="rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-1.5 text-xs text-text-primary focus:outline-none"
          >
            <option value="">All severities</option>
            {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <select
            value={ruleSource}
            onChange={e => setRuleSource(e.target.value)}
            className="rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-1.5 text-xs text-text-primary focus:outline-none"
          >
            <option value="">All sources</option>
            {RULE_SOURCES.map(([key, label]) => <option key={key} value={key}>{label}</option>)}
          </select>
          <button
            onClick={() => setShowForm(v => !v)}
            className="flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-xs font-medium text-white hover:opacity-90 transition-opacity"
          >
            {showForm ? <X size={13} /> : <Plus size={13} />}
            {showForm ? 'Cancel' : 'Add Rule'}
          </button>
        </div>
      </div>

      {/* Create form */}
      {showForm && (
        <div className="mb-6 rounded-xl border border-[#2a2a3e] bg-bg-surface p-5">
          <h2 className="mb-4 text-sm font-semibold text-text-primary">New Detection Rule</h2>

          <div className="grid gap-4 lg:grid-cols-[1fr_2fr]">
            {/* Left column — metadata */}
            <div className="space-y-3">
              <div>
                <label className="block mb-1 text-xs text-text-muted">Rule type <span className="text-red-400">*</span></label>
                <div className="flex gap-2">
                  {(['sigma', 'yara'] as const).map(t => (
                    <button
                      key={t}
                      onClick={() => { setFormType(t); setFormContent('') }}
                      className={`rounded-lg px-4 py-1.5 text-xs font-medium uppercase transition-colors ${
                        formType === t
                          ? 'bg-accent text-white'
                          : 'border border-[#2a2a3e] text-text-muted hover:text-text-primary'
                      }`}
                    >
                      {t}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="block mb-1 text-xs text-text-muted">Title <span className="text-red-400">*</span></label>
                <input
                  value={formTitle}
                  onChange={e => setFormTitle(e.target.value)}
                  placeholder="Suspicious PowerShell Encoded Command"
                  className="w-full rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
                />
              </div>

              <div>
                <label className="block mb-1 text-xs text-text-muted">Severity</label>
                <select
                  value={formSeverity}
                  onChange={e => setFormSeverity(e.target.value)}
                  className="w-full rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2 text-xs text-text-primary focus:outline-none"
                >
                  <option value="">— select —</option>
                  {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
                </select>
              </div>

              <div>
                <label className="block mb-1 text-xs text-text-muted">Status</label>
                <select
                  value={formStatus}
                  onChange={e => setFormStatus(e.target.value)}
                  className="w-full rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2 text-xs text-text-primary focus:outline-none"
                >
                  <option value="">— select —</option>
                  {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
                </select>
              </div>

              <div>
                <label className="block mb-1 text-xs text-text-muted">
                  ATT&CK Technique IDs
                  <span className="ml-1 text-text-muted font-normal">(comma or space separated)</span>
                </label>
                <input
                  value={formTechniqueIds}
                  onChange={e => setFormTechniqueIds(e.target.value)}
                  placeholder="T1059.001, T1027"
                  className="w-full rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
                />
              </div>

              <div>
                <label className="block mb-1 text-xs text-text-muted">Source URL</label>
                <input
                  value={formSourceUrl}
                  onChange={e => setFormSourceUrl(e.target.value)}
                  placeholder="https://github.com/..."
                  className="w-full rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
                />
              </div>

              {formError && (
                <p className="text-xs text-red-400">{formError}</p>
              )}

              <button
                onClick={handleCreate}
                disabled={createMutation.isPending}
                className="w-full rounded-lg bg-accent py-2 text-xs font-medium text-white hover:opacity-90 transition-opacity disabled:opacity-50"
              >
                {createMutation.isPending ? 'Saving…' : 'Create Rule'}
              </button>
            </div>

            {/* Right column — content editor */}
            <div>
              <label className="block mb-1 text-xs text-text-muted">
                Rule content <span className="text-red-400">*</span>
                <span className="ml-1 font-normal">({formType === 'sigma' ? 'YAML' : 'YARA'})</span>
              </label>
              <textarea
                value={formContent}
                onChange={e => setFormContent(e.target.value)}
                placeholder={formType === 'sigma' ? SIGMA_PLACEHOLDER : YARA_PLACEHOLDER}
                rows={22}
                spellCheck={false}
                className="w-full rounded-lg border border-[#2a2a3e] bg-[#0d0d14] px-3 py-2 font-mono text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright resize-y leading-relaxed"
              />
            </div>
          </div>
        </div>
      )}

      {/* Table */}
      <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface">
        <DataTable
          columns={columns}
          data={data ?? []}
          loading={isLoading}
          emptyTitle="No rules found"
          emptyDescription="Adjust filters or create your first rule using the Add Rule button."
          onRowClick={r => navigate(`/rules/${r.rule_type}/${r.id}`)}
          keyFn={r => r.id}
        />
      </div>

      {/* Success toast */}
      {successMsg && (
        <div className="fixed bottom-6 right-6 rounded-lg bg-green-800 px-4 py-2 text-xs font-medium text-green-200 shadow-lg">
          {successMsg}
        </div>
      )}
    </div>
  )
}
