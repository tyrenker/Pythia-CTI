import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Plus, X, Trash2, Edit2, Shield } from 'lucide-react'
import { useRules, useCreateRule, useDeleteRule } from '@/api/rules'
import { useCoverage } from '@/api/analytics'
import { SeverityBadge } from '@/components/shared/SeverityBadge'
import { TechniqueTag } from '@/components/shared/TechniqueTag'
import { DataTable } from '@/components/shared/DataTable'
import { FilterBar } from '@/components/shared/FilterBar'
import { PageHeader } from '@/components/shared/PageHeader'
import { StatStrip } from '@/components/shared/StatStrip'
import { RULE_SOURCE_LABELS, SEVERITY_COLORS } from '@/lib/constants'
import { cn } from '@/lib/utils'
import type { DetectionRule } from '@/types/api'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational']
const STATUSES = ['stable', 'test', 'experimental', 'deprecated']
const RULE_SOURCES = Object.entries(RULE_SOURCE_LABELS)

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'informational']

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
  const [showDrawer, setShowDrawer] = useState(false)

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

  const { data: coverage } = useCoverage(1)

  const data = ruleSource
    ? (rawData ?? []).filter(r => r.source_url?.includes(ruleSource))
    : rawData

  // Severity distribution from loaded data
  const severityCounts = (rawData ?? []).reduce<Record<string, number>>((acc, r) => {
    const s = r.severity ?? 'informational'
    acc[s] = (acc[s] ?? 0) + 1
    return acc
  }, {})
  const totalLoaded = rawData?.length ?? 0
  const sigmaCount = (rawData ?? []).filter(r => r.rule_type === 'sigma').length
  const yaraCount = (rawData ?? []).filter(r => r.rule_type === 'yara').length

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
          setShowDrawer(false)
          navigate(`/rules/${rule.rule_type}/${rule.id}`)
        },
        onError: (e: Error) => setFormError(e.message),
      },
    )
  }

  const activeFilterCount = [techniqueId, ruleType, severity, ruleSource].filter(Boolean).length

  function clearFilters() {
    setTechniqueId('')
    setRuleType('')
    setSeverity('')
    setRuleSource('')
  }

  const stats = [
    {
      label: 'Total Rules',
      value: coverage?.rule_count ?? (totalLoaded || '—'),
      icon: Shield,
    },
    {
      label: 'Sigma',
      value: sigmaCount || '—',
      color: 'text-blue-400',
    },
    {
      label: 'YARA',
      value: yaraCount || '—',
      color: 'text-orange-400',
    },
    {
      label: 'Critical',
      value: severityCounts['critical'] || '—',
      color: 'text-red-400',
    },
  ]

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
        <span
          className={cn(
            'inline-flex rounded-md px-2.5 py-1 text-xs font-bold uppercase tracking-wide',
            r.rule_type === 'sigma'
              ? 'bg-blue-900/50 text-blue-300'
              : 'bg-orange-900/50 text-orange-300',
          )}
        >
          {r.rule_type}
        </span>
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
        const label =
          Object.entries(RULE_SOURCE_LABELS).find(([key]) => r.source_url?.includes(key))?.[1] ??
          (r.source_url ? 'local' : '—')
        return (
          <span className="rounded-md bg-zinc-800 px-2 py-0.5 text-xs text-zinc-400">{label}</span>
        )
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
          <button
            onClick={() => navigate(`/rules/${r.rule_type}/${r.id}`)}
            className="rounded p-1 text-text-muted transition-colors hover:text-accent-bright"
            title="View rule"
          >
            <Edit2 size={13} />
          </button>
          {deleteConfirmId === r.id ? (
            <>
              <button
                onClick={() => deleteMutation.mutate(r.id, { onSuccess: () => setDeleteConfirmId(null) })}
                disabled={deleteMutation.isPending}
                className="text-xs text-red-400 hover:text-red-300 disabled:opacity-50"
              >
                Confirm
              </button>
              <button onClick={() => setDeleteConfirmId(null)} className="ml-1 text-text-muted hover:text-text-primary">
                <X size={12} />
              </button>
            </>
          ) : (
            <button
              onClick={() => setDeleteConfirmId(r.id)}
              className="rounded p-1 text-text-muted transition-colors hover:text-red-400"
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
      <PageHeader
        title="Detection Rules"
        description="Sigma and YARA signatures mapped to MITRE ATT&CK techniques."
        actions={
          <button
            onClick={() => setShowDrawer(true)}
            className="flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-xs font-medium text-white transition-opacity hover:opacity-90"
          >
            <Plus size={13} />
            Add Rule
          </button>
        }
      />

      <StatStrip stats={stats} />

      {/* Severity distribution bar */}
      {totalLoaded > 0 && (
        <div className="mb-6 rounded-xl border border-[#2a2a3e] bg-bg-surface px-4 py-3">
          <p className="mb-3 text-xs font-medium text-text-muted">
            Severity distribution{' '}
            <span className="font-normal">(loaded results)</span>
          </p>
          <div className="space-y-2">
            {SEVERITY_ORDER.filter(s => severityCounts[s]).map(s => {
              const count = severityCounts[s] ?? 0
              const pct = Math.round((count / totalLoaded) * 100)
              const colorClass = {
                critical: 'bg-red-600',
                high: 'bg-orange-500',
                medium: 'bg-amber-500',
                low: 'bg-green-600',
                informational: 'bg-zinc-600',
              }[s] ?? 'bg-zinc-600'
              return (
                <button
                  key={s}
                  onClick={() => setSeverity(severity === s ? '' : s)}
                  className={cn(
                    'group flex w-full items-center gap-3 rounded px-2 py-1 text-xs transition-colors hover:bg-bg-elevated',
                    severity === s && 'bg-bg-elevated',
                  )}
                >
                  <span
                    className={cn(
                      'w-24 shrink-0 text-right capitalize font-medium',
                      SEVERITY_COLORS[s]?.split(' ')[1] ?? 'text-text-muted',
                    )}
                  >
                    {s}
                  </span>
                  <div className="h-2 flex-1 overflow-hidden rounded-full bg-bg-elevated">
                    <div
                      className={cn('h-full rounded-full transition-all', colorClass)}
                      style={{ width: `${pct}%`, opacity: 0.8 }}
                    />
                  </div>
                  <span className="w-8 shrink-0 text-right tabular-nums text-text-muted">{count}</span>
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
          value={techniqueId}
          onChange={e => setTechniqueId(e.target.value)}
          placeholder="Technique ID..."
          className="rounded-lg border border-[#2a2a3e] bg-bg-surface px-3 py-1.5 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
        />
        <select
          value={ruleType}
          onChange={e => setRuleType(e.target.value)}
          className="rounded-lg border border-[#2a2a3e] bg-bg-surface px-3 py-1.5 text-xs text-text-primary focus:outline-none"
        >
          <option value="">All types</option>
          <option value="sigma">Sigma</option>
          <option value="yara">YARA</option>
        </select>
        <select
          value={severity}
          onChange={e => setSeverity(e.target.value)}
          className="rounded-lg border border-[#2a2a3e] bg-bg-surface px-3 py-1.5 text-xs text-text-primary focus:outline-none"
        >
          <option value="">All severities</option>
          {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select
          value={ruleSource}
          onChange={e => setRuleSource(e.target.value)}
          className="rounded-lg border border-[#2a2a3e] bg-bg-surface px-3 py-1.5 text-xs text-text-primary focus:outline-none"
        >
          <option value="">All sources</option>
          {RULE_SOURCES.map(([key, label]) => <option key={key} value={key}>{label}</option>)}
        </select>
      </FilterBar>

      <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface">
        <DataTable
          columns={columns}
          data={data ?? []}
          loading={isLoading}
          emptyTitle="No rules found"
          emptyDescription="Adjust filters or create your first rule."
          onRowClick={r => navigate(`/rules/${r.rule_type}/${r.id}`)}
          keyFn={r => r.id}
        />
      </div>

      {/* Success toast */}
      {successMsg && (
        <div className="fixed bottom-6 right-6 z-50 rounded-lg bg-green-800 px-4 py-2 text-xs font-medium text-green-200 shadow-lg">
          {successMsg}
        </div>
      )}

      {/* Drawer backdrop */}
      {showDrawer && (
        <div
          className="fixed inset-0 z-40 bg-bg-base/60"
          onClick={() => setShowDrawer(false)}
        />
      )}

      {/* Create rule drawer */}
      {showDrawer && (
        <div className="fixed right-0 top-0 z-50 flex h-full w-[520px] flex-col border-l border-[#2a2a3e] bg-bg-surface shadow-2xl">
          <div className="flex shrink-0 items-center justify-between border-b border-[#2a2a3e] px-5 py-4">
            <h2 className="text-sm font-semibold text-text-primary">New Detection Rule</h2>
            <button
              onClick={() => setShowDrawer(false)}
              className="rounded p-1 text-text-muted transition-colors hover:text-text-primary"
            >
              <X size={16} />
            </button>
          </div>

          <div className="flex-1 overflow-y-auto px-5 py-4">
            <div className="space-y-4">
              <div>
                <label className="mb-1 block text-xs text-text-muted">
                  Rule type <span className="text-red-400">*</span>
                </label>
                <div className="flex gap-2">
                  {(['sigma', 'yara'] as const).map(t => (
                    <button
                      key={t}
                      onClick={() => { setFormType(t); setFormContent('') }}
                      className={cn(
                        'rounded-lg px-4 py-1.5 text-xs font-bold uppercase tracking-wide transition-colors',
                        formType === t
                          ? t === 'sigma'
                            ? 'bg-blue-900/60 text-blue-300'
                            : 'bg-orange-900/60 text-orange-300'
                          : 'border border-[#2a2a3e] text-text-muted hover:text-text-primary',
                      )}
                    >
                      {t}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="mb-1 block text-xs text-text-muted">
                  Title <span className="text-red-400">*</span>
                </label>
                <input
                  value={formTitle}
                  onChange={e => setFormTitle(e.target.value)}
                  placeholder="Suspicious PowerShell Encoded Command"
                  className="w-full rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="mb-1 block text-xs text-text-muted">Severity</label>
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
                  <label className="mb-1 block text-xs text-text-muted">Status</label>
                  <select
                    value={formStatus}
                    onChange={e => setFormStatus(e.target.value)}
                    className="w-full rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2 text-xs text-text-primary focus:outline-none"
                  >
                    <option value="">— select —</option>
                    {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
                  </select>
                </div>
              </div>

              <div>
                <label className="mb-1 block text-xs text-text-muted">
                  ATT&CK Technique IDs{' '}
                  <span className="font-normal text-text-muted">(comma or space separated)</span>
                </label>
                <input
                  value={formTechniqueIds}
                  onChange={e => setFormTechniqueIds(e.target.value)}
                  placeholder="T1059.001, T1027"
                  className="w-full rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
                />
              </div>

              <div>
                <label className="mb-1 block text-xs text-text-muted">Source URL</label>
                <input
                  value={formSourceUrl}
                  onChange={e => setFormSourceUrl(e.target.value)}
                  placeholder="https://github.com/..."
                  className="w-full rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
                />
              </div>

              <div>
                <label className="mb-1 block text-xs text-text-muted">
                  Rule content <span className="text-red-400">*</span>{' '}
                  <span className="font-normal">({formType === 'sigma' ? 'YAML' : 'YARA'})</span>
                </label>
                <textarea
                  value={formContent}
                  onChange={e => setFormContent(e.target.value)}
                  placeholder={formType === 'sigma' ? SIGMA_PLACEHOLDER : YARA_PLACEHOLDER}
                  rows={18}
                  spellCheck={false}
                  className="w-full resize-y rounded-lg border border-[#2a2a3e] bg-[#0d0d14] px-3 py-2 font-mono text-xs leading-relaxed text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
                />
              </div>

              {formError && (
                <p className="text-xs text-red-400">{formError}</p>
              )}
            </div>
          </div>

          <div className="shrink-0 border-t border-[#2a2a3e] px-5 py-4">
            <div className="flex gap-3">
              <button
                onClick={() => setShowDrawer(false)}
                className="flex-1 rounded-lg border border-[#2a2a3e] py-2 text-xs font-medium text-text-muted transition-colors hover:text-text-primary"
              >
                Cancel
              </button>
              <button
                onClick={handleCreate}
                disabled={createMutation.isPending}
                className="flex-1 rounded-lg bg-accent py-2 text-xs font-medium text-white transition-opacity hover:opacity-90 disabled:opacity-50"
              >
                {createMutation.isPending ? 'Saving…' : 'Create Rule'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
