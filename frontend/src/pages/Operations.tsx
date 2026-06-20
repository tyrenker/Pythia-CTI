import { useState } from 'react'
import { Shield, Activity, CheckCircle, XCircle, AlertCircle, ChevronDown, ChevronUp } from 'lucide-react'
import {
  useSiemStatus,
  useSiemAlerts,
  useAlertStats,
  useDeployRule,
  useDeployAllRules,
  useTriageAlert,
  type SiemAlert,
} from '@/api/siem'
import { useHoneypotCampaigns } from '@/api/honeypot'
import { useRules } from '@/api/rules'
import type { DetectionRule } from '@/types/api'
import { timeAgo } from '@/lib/utils'
import { cn } from '@/lib/utils'

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-900/50 text-red-300 border border-red-700/40',
  high: 'bg-orange-900/40 text-orange-300 border border-orange-700/40',
  medium: 'bg-yellow-900/40 text-yellow-300 border border-yellow-700/40',
  low: 'bg-blue-900/40 text-blue-300 border border-blue-700/40',
  info: 'bg-[#2a2a3e] text-[#6b7280] border border-[#3a3a5e]',
}

const TRIAGE_STYLES: Record<string, string> = {
  new: 'bg-red-900/40 text-red-300 border border-red-700/40 animate-pulse',
  investigating: 'bg-yellow-900/40 text-yellow-300 border border-yellow-700/40',
  true_positive: 'bg-green-900/40 text-green-300 border border-green-700/40',
  false_positive: 'bg-[#2a2a3e] text-[#6b7280] border border-[#3a3a5e]',
  closed: 'bg-[#2a2a3e] text-[#6b7280] border border-[#3a3a5e]',
}

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={cn('rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide', SEVERITY_COLORS[severity] ?? 'bg-[#2a2a3e] text-[#6b7280]')}>
      {severity}
    </span>
  )
}

function TriageBadge({ status }: { status: string }) {
  return (
    <span className={cn('rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide', TRIAGE_STYLES[status] ?? 'bg-[#2a2a3e] text-[#6b7280]')}>
      {status.replace('_', ' ')}
    </span>
  )
}

// ── SIEM Status Bar ───────────────────────────────────────────────────────────

function SiemStatusBar() {
  const { data: status } = useSiemStatus()

  return (
    <div className="flex items-center gap-3 rounded-lg border border-[#2a2a3e] bg-bg-surface px-4 py-2.5 text-xs">
      <span className="font-mono uppercase tracking-[0.15em] text-[#6b7280]">SIEM</span>
      {status ? (
        <>
          <span className="font-semibold text-text-primary">{status.siem_type || 'Unknown'}</span>
          <span className="mx-1 text-[#3a3a5e]">|</span>
          {status.configured ? (
            status.connected ? (
              <span className="flex items-center gap-1.5 text-green-400">
                <span className="h-1.5 w-1.5 rounded-full bg-green-400" />
                Connected
              </span>
            ) : (
              <span className="flex items-center gap-1.5 text-yellow-400">
                <span className="h-1.5 w-1.5 rounded-full bg-yellow-400" />
                Configured / Not Connected
              </span>
            )
          ) : (
            <span className="flex items-center gap-1.5 text-[#6b7280]">
              <span className="h-1.5 w-1.5 rounded-full bg-[#6b7280]" />
              Not Configured
            </span>
          )}
        </>
      ) : (
        <span className="text-[#6b7280]">Loading...</span>
      )}
    </div>
  )
}

// ── Alert Queue ───────────────────────────────────────────────────────────────

type TriageFilter = 'all' | 'new' | 'investigating'

function AlertQueue() {
  const [filter, setFilter] = useState<TriageFilter>('all')
  const [expanded, setExpanded] = useState<string | null>(null)
  const [noteValues, setNoteValues] = useState<Record<string, string>>({})

  const { data: alerts = [], isLoading } = useSiemAlerts(
    filter !== 'all' ? { triage_status: filter } : {},
  )
  const { data: stats } = useAlertStats()
  const triage = useTriageAlert()

  function handleTriage(alertId: string, status: string) {
    triage.mutate({ id: alertId, triage_status: status, analyst_notes: noteValues[alertId] })
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-3">
        <p className="font-mono text-xs uppercase tracking-[0.2em] text-[#6b7280]/90">// Alert Queue</p>
        <div className="flex items-center gap-2">
          {stats && (
            <span className="font-mono text-xs text-[#6b7280]">
              Total: <span className="text-text-primary">{stats.total}</span>
            </span>
          )}
          <div className="flex gap-1 rounded-lg border border-[#2a2a3e] p-0.5">
            {(['all', 'new', 'investigating'] as TriageFilter[]).map(f => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={cn(
                  'rounded px-3 py-1 font-mono text-[10px] uppercase tracking-wider transition-colors',
                  filter === f
                    ? 'bg-[#00ff88]/10 text-[#00ff88]'
                    : 'text-[#6b7280] hover:text-text-primary',
                )}
              >
                {f}
              </button>
            ))}
          </div>
        </div>
      </div>

      {stats && (
        <div className="flex flex-wrap gap-2">
          {Object.entries(stats.by_severity).map(([sev, count]) => (
            <div key={sev} className="flex items-center gap-1.5 rounded border border-[#2a2a3e] bg-bg-surface px-2 py-1">
              <SeverityBadge severity={sev} />
              <span className="font-mono text-xs text-text-primary">{String(count)}</span>
            </div>
          ))}
        </div>
      )}

      {isLoading && <p className="text-sm text-[#6b7280]">Loading alerts...</p>}
      {!isLoading && alerts.length === 0 && (
        <p className="text-sm text-[#6b7280]">No alerts found.</p>
      )}

      <div className="space-y-2">
        {alerts.map((alert: SiemAlert) => (
          <div key={alert.id} className="rounded-lg border border-[#2a2a3e] bg-bg-surface">
            <div
              className="flex cursor-pointer flex-wrap items-center gap-3 px-4 py-3 hover:bg-bg-elevated"
              onClick={() => setExpanded(expanded === alert.id ? null : alert.id)}
            >
              <SeverityBadge severity={alert.severity} />
              <TriageBadge status={alert.triage_status} />
              <span className="flex-1 font-medium text-text-primary">{alert.title}</span>
              {alert.attacker_ip && (
                <span className="font-mono text-xs text-[#6b7280]">{alert.attacker_ip}</span>
              )}
              <span className="text-xs text-[#6b7280]">{timeAgo(alert.received_at)}</span>
              {expanded === alert.id ? <ChevronUp size={14} className="shrink-0 text-[#6b7280]" /> : <ChevronDown size={14} className="shrink-0 text-[#6b7280]" />}
            </div>

            {expanded === alert.id && (
              <div className="border-t border-[#2a2a3e] px-4 py-3 space-y-3">
                {alert.mitre_techniques.length > 0 && (
                  <div>
                    <p className="mb-1 text-[10px] uppercase tracking-[0.15em] text-[#6b7280]">MITRE Techniques</p>
                    <div className="flex flex-wrap gap-1">
                      {alert.mitre_techniques.map(t => (
                        <span key={t} className="rounded bg-purple-900/30 px-1.5 py-0.5 font-mono text-[10px] text-purple-300">{t}</span>
                      ))}
                    </div>
                  </div>
                )}

                <div>
                  <p className="mb-1 text-[10px] uppercase tracking-[0.15em] text-[#6b7280]">Analyst Notes</p>
                  <textarea
                    value={noteValues[alert.id] ?? alert.analyst_notes ?? ''}
                    onChange={e => setNoteValues(prev => ({ ...prev, [alert.id]: e.target.value }))}
                    rows={2}
                    className="w-full resize-none rounded border border-[#2a2a3e] bg-[#12121a] px-3 py-2 font-mono text-xs text-[#e0e0e0] placeholder-[#6b7280]/60 focus:border-[#00ff88] focus:outline-none"
                    placeholder="Add notes..."
                  />
                </div>

                <div className="flex flex-wrap gap-2">
                  <button
                    onClick={() => handleTriage(alert.id, 'true_positive')}
                    disabled={triage.isPending}
                    className="flex items-center gap-1.5 rounded border border-green-700/40 bg-green-900/20 px-3 py-1.5 text-[11px] text-green-300 hover:bg-green-900/40 disabled:opacity-50"
                  >
                    <CheckCircle size={11} />
                    True Positive
                  </button>
                  <button
                    onClick={() => handleTriage(alert.id, 'false_positive')}
                    disabled={triage.isPending}
                    className="flex items-center gap-1.5 rounded border border-[#2a2a3e] bg-bg-elevated px-3 py-1.5 text-[11px] text-[#6b7280] hover:text-text-primary disabled:opacity-50"
                  >
                    <XCircle size={11} />
                    False Positive
                  </button>
                  <button
                    onClick={() => handleTriage(alert.id, 'investigating')}
                    disabled={triage.isPending}
                    className="flex items-center gap-1.5 rounded border border-yellow-700/40 bg-yellow-900/20 px-3 py-1.5 text-[11px] text-yellow-300 hover:bg-yellow-900/40 disabled:opacity-50"
                  >
                    <AlertCircle size={11} />
                    Investigating
                  </button>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Rule Deployment ───────────────────────────────────────────────────────────

function RuleDeployment() {
  const { data: rules = [], isLoading } = useRules({ limit: 100 })
  const deployRule = useDeployRule()
  const deployAll = useDeployAllRules()
  const [deployMsg, setDeployMsg] = useState<string | null>(null)

  function handleDeployAll() {
    setDeployMsg(null)
    deployAll.mutate(undefined, {
      onSuccess: (results) => setDeployMsg(`Deployed ${results.length} rule${results.length === 1 ? '' : 's'}`),
      onError: (err: Error) => setDeployMsg(err.message),
    })
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-3">
        <p className="font-mono text-xs uppercase tracking-[0.2em] text-[#6b7280]/90">// Rule Deployment</p>
        <div className="flex items-center gap-2">
          {deployMsg && (
            <span className="text-xs text-[#00ff88]">{deployMsg}</span>
          )}
          <button
            onClick={handleDeployAll}
            disabled={deployAll.isPending}
            className="flex items-center gap-2 rounded-md bg-[#00ff88]/10 border border-[#00ff88]/30 px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider text-[#00ff88] hover:bg-[#00ff88]/20 disabled:opacity-50"
          >
            Deploy All
          </button>
        </div>
      </div>

      {isLoading && <p className="text-sm text-[#6b7280]">Loading rules...</p>}

      <div className="overflow-x-auto rounded-lg border border-[#2a2a3e]">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[#2a2a3e] bg-bg-surface text-left text-[11px] uppercase tracking-wide text-[#6b7280]">
              <th className="px-4 py-2">Status</th>
              <th className="px-4 py-2">Title</th>
              <th className="px-4 py-2">Type</th>
              <th className="px-4 py-2">Severity</th>
              <th className="px-4 py-2">TTPs</th>
              <th className="px-4 py-2">Action</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((rule: DetectionRule) => {
              const deployed = !!(rule as DetectionRule & { siem_rule_id?: string }).siem_rule_id
              return (
                <tr key={rule.id} className="border-b border-[#2a2a3e] hover:bg-bg-elevated">
                  <td className="px-4 py-2">
                    <span
                      className={cn('inline-block h-2 w-2 rounded-full', deployed ? 'bg-green-400' : 'bg-[#6b7280]')}
                      title={deployed ? 'Deployed' : 'Not deployed'}
                    />
                  </td>
                  <td className="px-4 py-2 font-medium text-text-primary">{rule.title}</td>
                  <td className="px-4 py-2 font-mono text-xs text-[#6b7280]">{rule.rule_type}</td>
                  <td className="px-4 py-2">
                    {rule.severity ? <SeverityBadge severity={rule.severity} /> : <span className="text-[#6b7280]">—</span>}
                  </td>
                  <td className="px-4 py-2 text-text-primary">{rule.technique_ids.length}</td>
                  <td className="px-4 py-2">
                    <button
                      onClick={() => deployRule.mutate(rule.id)}
                      disabled={deployRule.isPending}
                      className="rounded border border-[#2a2a3e] bg-bg-elevated px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-[#6b7280] hover:border-[#00ff88]/30 hover:text-[#00ff88] disabled:opacity-50"
                    >
                      Deploy
                    </button>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── Active Campaigns Miniview ─────────────────────────────────────────────────

function ActiveCampaigns() {
  const { data: campaigns = [] } = useHoneypotCampaigns({ status: 'active', limit: 5 })

  return (
    <div className="space-y-2">
      <p className="font-mono text-xs uppercase tracking-[0.2em] text-[#6b7280]/90">// Active Campaigns</p>
      {campaigns.length === 0 && (
        <p className="text-sm text-[#6b7280]">No active campaigns.</p>
      )}
      <div className="space-y-1.5">
        {campaigns.map(c => (
          <div key={c.id} className="flex items-center justify-between gap-3 rounded border border-[#2a2a3e] bg-bg-surface px-3 py-2">
            <span className="font-medium text-text-primary">{c.name}</span>
            <div className="flex items-center gap-3 text-xs text-[#6b7280]">
              <span>{c.event_count} events</span>
              <span>{timeAgo(c.last_seen)}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export function Operations() {
  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Shield size={18} className="text-[#00ff88]" />
            <h1 className="text-lg font-semibold text-text-primary">Operations</h1>
          </div>
          <p className="mt-0.5 text-sm text-[#6b7280]">
            SOC alert triage, rule deployment, and active campaign tracking
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Activity size={14} className="text-[#6b7280]" />
        </div>
      </div>

      <SiemStatusBar />

      <div className="grid gap-6 xl:grid-cols-3">
        <div className="xl:col-span-2 space-y-6">
          <div className="rounded-lg border border-[#2a2a3e] bg-bg-surface p-4">
            <AlertQueue />
          </div>
          <div className="rounded-lg border border-[#2a2a3e] bg-bg-surface p-4">
            <RuleDeployment />
          </div>
        </div>

        <div className="space-y-4">
          <div className="rounded-lg border border-[#2a2a3e] bg-bg-surface p-4">
            <ActiveCampaigns />
          </div>
        </div>
      </div>
    </div>
  )
}
