import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useThreat, useSuggestRules, useSaveRule } from '@/api/threats'
import { TlpBadge } from '@/components/shared/TlpBadge'
import { TechniqueTag } from '@/components/shared/TechniqueTag'
import { CodeBlock } from '@/components/shared/CodeBlock'
import { Breadcrumb } from '@/components/layout/Breadcrumb'
import { timeAgo } from '@/lib/utils'
import type { SuggestedRule, SuggestedRulesResponse, SuggestedQuery } from '@/types/api'

type Tab = 'summary' | 'ttps' | 'iocs' | 'actors' | 'rules' | 'raw'

// ── Severity badge ───────────────────────────────────────────────────────────

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'border-[#ff3366] text-[#ff3366] shadow-[0_0_6px_rgba(255,51,102,0.3)]',
  high:     'border-[#f59e0b] text-[#f59e0b] shadow-[0_0_6px_rgba(245,158,11,0.3)]',
  medium:   'border-[#3b82f6] text-[#3b82f6]',
  low:      'border-[#6b7280] text-[#6b7280]',
}

function RuleSeverityBadge({ severity }: { severity: string }) {
  const s = severity.toLowerCase()
  return (
    <span className={`inline-block border px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wider ${SEVERITY_COLORS[s] ?? SEVERITY_COLORS.medium}`}>
      {severity}
    </span>
  )
}

const TIER_COLORS: Record<string, string> = {
  ttp:      'border-[#00ff88] text-[#00ff88]',
  tool:     'border-[#8b5cf6] text-[#8b5cf6]',
  artifact: 'border-[#3b82f6] text-[#3b82f6]',
  domain:   'border-[#f59e0b] text-[#f59e0b]',
  ip:       'border-[#f59e0b] text-[#f59e0b]',
  hash:     'border-[#6b7280] text-[#6b7280]',
}

function PyramidTierBadge({ tier }: { tier: string }) {
  const t = tier.toLowerCase()
  return (
    <span className={`inline-block border px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wider ${TIER_COLORS[t] ?? TIER_COLORS.hash}`}>
      ◆ {tier}
    </span>
  )
}

// ── Single Rule Card ─────────────────────────────────────────────────────────

function RuleCard({
  rule,
  ruleType,
}: {
  rule: SuggestedRule
  ruleType: 'sigma' | 'yara'
}) {
  const saveRule = useSaveRule()
  const [saved, setSaved] = useState(false)

  const handleSave = () => {
    saveRule.mutate(
      {
        rule_type: ruleType,
        title: rule.title,
        content: rule.content,
        severity: rule.severity,
        technique_ids: rule.linked_ttps,
      },
      { onSuccess: () => setSaved(true) },
    )
  }

  return (
    <div className="border border-[#2a2a3e] bg-[#0d0d14] transition-all hover:border-[#2a2a4e]">
      {/* Header */}
      <div className="flex flex-wrap items-center gap-2 border-b border-[#2a2a3e] px-4 py-3">
        <span className="font-mono text-[9px] uppercase tracking-[0.12em] text-[#00ff88]/60">
          {ruleType}
        </span>
        <h3 className="flex-1 font-mono text-xs font-medium text-[#e0e0e0]">
          {rule.title}
        </h3>
        <RuleSeverityBadge severity={rule.severity} />
        <PyramidTierBadge tier={rule.pyramid_tier} />
      </div>

      {/* Description */}
      {rule.description && (
        <div className="border-b border-[#2a2a3e] px-4 py-2">
          <p className="text-xs leading-relaxed text-[#9ca3af]">{rule.description}</p>
        </div>
      )}

      {/* Linked TTPs */}
      {rule.linked_ttps.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 border-b border-[#2a2a3e] px-4 py-2">
          <span className="font-mono text-[9px] uppercase tracking-wider text-[#6b7280]">TTPs:</span>
          {rule.linked_ttps.map(id => (
            <TechniqueTag key={id} id={id} />
          ))}
        </div>
      )}

      {/* Code */}
      <CodeBlock
        code={rule.content}
        language={ruleType === 'sigma' ? 'yaml' : 'yara'}
        maxLines={20}
        expandable
      />

      {/* Actions */}
      <div className="flex items-center justify-end gap-2 border-t border-[#2a2a3e] px-4 py-2">
        {saved ? (
          <span className="font-mono text-[9px] uppercase tracking-wider text-[#00ff88]">
            ✓ SAVED TO LIBRARY
          </span>
        ) : (
          <button
            onClick={handleSave}
            disabled={saveRule.isPending}
            className="border border-[#00ff88]/50 px-3 py-1 font-mono text-[9px] uppercase tracking-wider text-[#00ff88] transition-all hover:bg-[#00ff88]/10 disabled:opacity-40"
          >
            {saveRule.isPending ? 'SAVING…' : 'SAVE TO LIBRARY'}
          </button>
        )}
      </div>
    </div>
  )
}

// ── Single Query Card ────────────────────────────────────────────────────────

function QueryCard({
  query,
  queryType,
}: {
  query: SuggestedQuery
  queryType: 'spl' | 'kql'
}) {
  return (
    <div className="border border-[#2a2a3e] bg-[#0d0d14] transition-all hover:border-[#2a2a4e]">
      {/* Header */}
      <div className="flex flex-wrap items-center gap-2 border-b border-[#2a2a3e] px-4 py-3">
        <span className="font-mono text-[9px] uppercase tracking-[0.12em] text-[#00ff88]/60">
          {queryType}
        </span>
        <h3 className="flex-1 font-mono text-xs font-medium text-[#e0e0e0]">
          {query.title}
        </h3>
      </div>

      {/* Description */}
      {query.description && (
        <div className="border-b border-[#2a2a3e] px-4 py-2">
          <p className="text-xs leading-relaxed text-[#9ca3af]">{query.description}</p>
        </div>
      )}

      {/* Code */}
      <CodeBlock
        code={query.content}
        language={queryType === 'spl' ? 'splunk' : 'kql'}
        maxLines={20}
        expandable
      />
    </div>
  )
}

// ── Detection Rules Tab ──────────────────────────────────────────────────────

function DetectionRulesTab({ threatId, initialRules }: { threatId: string; initialRules?: SuggestedRulesResponse | null }) {
  const suggest = useSuggestRules()
  const [result, setResult] = useState<SuggestedRulesResponse | null>(initialRules ?? null)

  const handleGenerate = () => {
    suggest.mutate(threatId, {
      onSuccess: (data) => setResult(data),
    })
  }

  if (!result && !suggest.isPending && !suggest.isError) {
    return (
      <div className="flex flex-col items-center justify-center py-16">
        <div className="mb-4 font-mono text-[10px] uppercase tracking-wider text-[#6b7280]">
          Generate AI-suggested detection rules from this report's TTPs, IoCs, and actors
        </div>
        <button
          onClick={handleGenerate}
          className="bg-[#00ff88] px-6 py-2 font-mono text-[10px] font-bold uppercase tracking-wider text-[#0a0a0f] transition-all hover:shadow-[0_0_20px_rgba(0,255,136,0.4)]"
        >
          GENERATE DETECTION RULES
        </button>
      </div>
    )
  }

  if (suggest.isPending) {
    return (
      <div className="flex flex-col items-center justify-center py-16">
        <div className="mb-3 h-1 w-48 overflow-hidden border border-[#2a2a3a] bg-[#0a0a0f]">
          <div className="h-full w-1/3 animate-pulse bg-[#00ff88]/60" style={{ animation: 'shimmer 1.5s ease-in-out infinite' }} />
        </div>
        <div className="font-mono text-[10px] uppercase tracking-wider text-[#00ff88] animate-pulse">
          GENERATING SIGMA &amp; YARA RULES…
        </div>
        <div className="mt-2 font-mono text-[9px] text-[#6b7280]">
          Claude is analyzing TTPs and crafting detection logic
        </div>
        <style>{`
          @keyframes shimmer {
            0% { transform: translateX(-100%); }
            100% { transform: translateX(400%); }
          }
        `}</style>
      </div>
    )
  }

  if (suggest.isError) {
    return (
      <div className="py-10 text-center">
        <p className="mb-3 font-mono text-xs text-[#ff3366]">
          {suggest.error?.message ?? 'Rule generation failed'}
        </p>
        <button
          onClick={handleGenerate}
          className="border border-[#ff3366]/50 px-4 py-1.5 font-mono text-[9px] uppercase tracking-wider text-[#ff3366] transition-all hover:bg-[#ff3366]/10"
        >
          RETRY
        </button>
      </div>
    )
  }

  if (!result) return null

  const hasSigma = result.sigma_rules?.length > 0
  const hasYara = result.yara_rules?.length > 0
  const hasSplunk = result.splunk_queries?.length > 0
  const hasElastic = result.elastic_queries?.length > 0
  const hasPlaybook = !!result.playbook

  return (
    <div className="space-y-6">
      {/* Generation notes */}
      {result.generation_notes && (
        <div className="border border-[#2a2a3e] bg-[#0a0a0f] px-4 py-3">
          <span className="font-mono text-[9px] uppercase tracking-wider text-[#00ff88]/60">
            // ANALYST NOTES
          </span>
          <p className="mt-1 text-xs leading-relaxed text-[#9ca3af]">
            {result.generation_notes}
          </p>
        </div>
      )}

      {/* Summary stats */}
      <div className="flex items-center gap-4">
        <span className="font-mono text-[10px] uppercase tracking-wider text-[#6b7280]">
          {result.sigma_rules?.length || 0} Sigma
        </span>
        <span className="h-3 w-px bg-[#2a2a3e]" />
        <span className="font-mono text-[10px] uppercase tracking-wider text-[#6b7280]">
          {result.yara_rules?.length || 0} YARA
        </span>
        <span className="h-3 w-px bg-[#2a2a3e]" />
        <span className="font-mono text-[10px] uppercase tracking-wider text-[#6b7280]">
          {result.splunk_queries?.length || 0} SPL
        </span>
        <span className="h-3 w-px bg-[#2a2a3e]" />
        <span className="font-mono text-[10px] uppercase tracking-wider text-[#6b7280]">
          {result.elastic_queries?.length || 0} KQL
        </span>
        <div className="flex-1" />
        <button
          onClick={handleGenerate}
          disabled={suggest.isPending}
          className="border border-[#2a2a3e] px-3 py-1 font-mono text-[9px] uppercase tracking-wider text-[#6b7280] transition-all hover:border-[#00ff88]/40 hover:text-[#00ff88] disabled:opacity-40"
        >
          REGENERATE
        </button>
      </div>

      {/* Playbook */}
      {hasPlaybook && (
        <div className="space-y-3">
          <h3 className="font-mono text-[10px] uppercase tracking-[0.15em] text-[#3b82f6]/70">
            ▸ IR PLAYBOOK
          </h3>
          <div className="border border-[#2a2a3e] bg-[#0d0d14] px-4 py-4 prose-sm prose-invert max-w-none text-[#d1d5db]">
            <CodeBlock code={result.playbook} language="markdown" maxLines={40} expandable />
          </div>
        </div>
      )}

      {/* Sigma Rules */}
      {hasSigma && (
        <div className="space-y-3">
          <h3 className="font-mono text-[10px] uppercase tracking-[0.15em] text-[#00ff88]/70">
            ▸ SIGMA RULES
          </h3>
          {result.sigma_rules.map((rule, i) => (
            <RuleCard key={`sigma-${i}`} rule={rule} ruleType="sigma" />
          ))}
        </div>
      )}

      {/* YARA Rules */}
      {hasYara && (
        <div className="space-y-3">
          <h3 className="font-mono text-[10px] uppercase tracking-[0.15em] text-[#8b5cf6]/70">
            ▸ YARA RULES
          </h3>
          {result.yara_rules.map((rule, i) => (
            <RuleCard key={`yara-${i}`} rule={rule} ruleType="yara" />
          ))}
        </div>
      )}

      {/* Splunk Queries */}
      {hasSplunk && (
        <div className="space-y-3">
          <h3 className="font-mono text-[10px] uppercase tracking-[0.15em] text-[#f59e0b]/70">
            ▸ SPLUNK QUERIES
          </h3>
          {result.splunk_queries.map((query, i) => (
            <QueryCard key={`spl-${i}`} query={query} queryType="spl" />
          ))}
        </div>
      )}

      {/* Elastic Queries */}
      {hasElastic && (
        <div className="space-y-3">
          <h3 className="font-mono text-[10px] uppercase tracking-[0.15em] text-[#3b82f6]/70">
            ▸ ELASTIC KQL QUERIES
          </h3>
          {result.elastic_queries.map((query, i) => (
            <QueryCard key={`kql-${i}`} query={query} queryType="kql" />
          ))}
        </div>
      )}

      {!hasSigma && !hasYara && !hasSplunk && !hasElastic && !hasPlaybook && (
        <div className="py-10 text-center font-mono text-xs text-[#6b7280]">
          No rules were generated. The report may lack sufficient TTPs or IoCs.
        </div>
      )}
    </div>
  )
}

// ── Main Component ───────────────────────────────────────────────────────────

export function ThreatDetail() {
  const { id } = useParams<{ id: string }>()
  const { data, isLoading, error } = useThreat(id ?? '')
  const [tab, setTab] = useState<Tab>('summary')

  if (isLoading) return <div className="py-16 text-center text-sm text-text-muted">Loading…</div>
  if (error || !data) return <div className="py-16 text-center text-sm text-red-400">Report not found.</div>

  const pd = data.parsed_data
  const iocs = (pd.iocs as Array<{ value: string; type: string; pyramid_tier?: string; id?: string }>) ?? []
  const ttps = data.ttps ?? []
  const actors = data.actors ?? []

  const TABS: { key: Tab; label: string }[] = [
    { key: 'summary', label: 'Summary' },
    { key: 'ttps', label: `TTPs (${ttps.length})` },
    { key: 'iocs', label: `IoCs (${iocs.length})` },
    { key: 'actors', label: `Actors (${actors.length})` },
    { key: 'rules', label: 'Detection Rules' },
    { key: 'raw', label: 'Raw JSON' },
  ]

  return (
    <div>
      <Breadcrumb crumbs={[{ label: 'Intel', to: '/intel' }, { label: data.title ?? 'Report' }]} />

      {/* Hero */}
      <div className="mb-6 rounded-xl border border-[#2a2a3e] bg-bg-surface p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-lg font-semibold text-text-primary">{data.title ?? 'Untitled Report'}</h1>
            <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-text-muted">
              {data.url && (
                <a href={data.url} target="_blank" rel="noreferrer" className="text-[#00ff88] hover:underline">
                  Source ↗
                </a>
              )}
              <span>Ingested {timeAgo(data.publication_date)}</span>
              <span className="capitalize">{data.status.replace('_', ' ')}</span>
            </div>
          </div>
          <TlpBadge tlp={data.tlp} className="text-sm px-2 py-1" />
        </div>
      </div>

      {/* Tabs */}
      <div className="mb-4 flex border-b border-[#2a2a3e]">
        {TABS.map(t => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`px-4 py-2 text-xs font-medium transition-colors ${
              tab === t.key
                ? 'border-b-2 border-[#00ff88] text-text-primary -mb-px'
                : 'text-text-muted hover:text-text-primary'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface p-6">
        {tab === 'summary' && (
          <div className="prose-sm max-w-none text-text-primary">
            <p className="text-sm leading-relaxed">
              {(pd.business_impact as string) ?? (pd.summary as string) ?? 'No summary available.'}
            </p>
            {Array.isArray(pd.sectors_targeted) && (
              <div className="mt-4">
                <p className="text-xs font-medium text-text-muted mb-2">Sectors Targeted</p>
                <div className="flex flex-wrap gap-1">
                  {(pd.sectors_targeted as string[]).map(s => (
                    <span key={s} className="rounded bg-bg-elevated px-2 py-0.5 text-xs text-text-primary">
                      {s}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {tab === 'ttps' && (
          <div>
            {ttps.length === 0 ? (
              <p className="text-xs text-text-muted">No techniques extracted.</p>
            ) : (
              <div className="flex flex-wrap gap-2">
                {ttps.map(id => (
                  <TechniqueTag key={id} id={id} />
                ))}
              </div>
            )}
          </div>
        )}

        {tab === 'iocs' && (
          <div className="overflow-x-auto">
            {iocs.length === 0 ? (
              <p className="text-xs text-text-muted">No IoCs extracted.</p>
            ) : (
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-[#2a2a3e]">
                    <th className="px-3 py-2 text-left text-text-muted font-medium">Type</th>
                    <th className="px-3 py-2 text-left text-text-muted font-medium">Value</th>
                    <th className="px-3 py-2 text-left text-text-muted font-medium">Tier</th>
                  </tr>
                </thead>
                <tbody>
                  {iocs.map((ioc, i) => (
                    <tr key={i} className="border-b border-[#2a2a3e]">
                      <td className="px-3 py-2 text-text-muted">{ioc.type}</td>
                      <td className="px-3 py-2 font-mono text-text-primary">
                        {ioc.id ? (
                          <Link to={`/iocs/${ioc.id}`} className="text-[#00ff88] hover:underline">
                            {ioc.value}
                          </Link>
                        ) : (
                          ioc.value
                        )}
                      </td>
                      <td className="px-3 py-2 text-text-muted">{ioc.pyramid_tier ?? '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {tab === 'actors' && (
          <div>
            {actors.length === 0 ? (
              <p className="text-xs text-text-muted">No actors extracted.</p>
            ) : (
              <div className="flex flex-wrap gap-2">
                {actors.map(name => (
                  <Link
                    key={name}
                    to={`/actors/${encodeURIComponent(name)}`}
                    className="rounded bg-bg-elevated px-2 py-1 text-xs text-[#00ff88] hover:opacity-80"
                  >
                    {name}
                  </Link>
                ))}
              </div>
            )}
          </div>
        )}

        {tab === 'rules' && (
          <DetectionRulesTab threatId={id ?? ''} initialRules={pd.suggested_rules as SuggestedRulesResponse | undefined} />
        )}

        {tab === 'raw' && (
          <CodeBlock
            code={JSON.stringify(pd, null, 2)}
            language="json"
            maxLines={100}
          />
        )}
      </div>
    </div>
  )
}

