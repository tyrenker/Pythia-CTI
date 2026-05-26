import { useParams } from 'react-router-dom'
import { useIoc } from '@/api/iocs'
import { TlpBadge } from '@/components/shared/TlpBadge'
import { Breadcrumb } from '@/components/layout/Breadcrumb'
import { cn } from '@/lib/utils'
import { PYRAMID_COLORS, ADMIRALTY_SOURCE, ADMIRALTY_ACCURACY } from '@/lib/constants'

export function IocDetail() {
  const { id } = useParams<{ id: string }>()
  const { data: ioc, isLoading } = useIoc(id ?? '')

  if (isLoading) return <div className="py-16 text-center text-sm text-text-muted">Loading…</div>
  if (!ioc) return <div className="py-16 text-center text-sm text-red-400">IoC not found.</div>

  const admiraltyLabel = [
    ADMIRALTY_SOURCE[ioc.confidence_source] && `Source: ${ADMIRALTY_SOURCE[ioc.confidence_source]}`,
    ADMIRALTY_ACCURACY[ioc.confidence_info] && `Info: ${ADMIRALTY_ACCURACY[ioc.confidence_info]}`,
  ].filter(Boolean).join(' · ')

  const fields: { label: string; value: React.ReactNode }[] = [
    { label: 'Type', value: ioc.type },
    { label: 'Value', value: <span className="font-mono break-all">{ioc.value}</span> },
    { label: 'Pyramid Tier', value: ioc.pyramid_tier },
    {
      label: 'Admiralty',
      value: (
        <span title={admiraltyLabel} className="font-mono cursor-help">
          {ioc.confidence_source}{ioc.confidence_info}
        </span>
      ),
    },
    { label: 'TLP', value: <TlpBadge tlp={ioc.tlp} /> },
    { label: 'Actor', value: ioc.actor_id ?? '—' },
    { label: 'Source URL', value: ioc.source_url ? (
      <a href={ioc.source_url} target="_blank" rel="noreferrer" className="text-accent-bright hover:underline">
        {ioc.source_url}
      </a>
    ) : '—' },
  ]

  return (
    <div>
      <Breadcrumb crumbs={[{ label: 'IoCs', to: '/iocs' }, { label: ioc.value.slice(0, 32) }]} />

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface p-6">
          <div className="mb-4 flex items-center gap-2">
            <span
              className={cn(
                'rounded px-2 py-0.5 text-xs font-medium',
                PYRAMID_COLORS[ioc.pyramid_tier] ?? 'bg-zinc-800 text-zinc-300',
              )}
            >
              {ioc.pyramid_tier}
            </span>
            <h1 className="font-mono text-sm text-text-primary break-all">{ioc.value}</h1>
          </div>

          <dl className="space-y-3">
            {fields.map(({ label, value }) => (
              <div key={label} className="flex items-start gap-4">
                <dt className="w-28 shrink-0 text-xs text-text-muted">{label}</dt>
                <dd className="text-xs text-text-primary">{value}</dd>
              </div>
            ))}
          </dl>

          {ioc.context && (
            <div className="mt-4">
              <p className="mb-1 text-xs text-text-muted">Context</p>
              <p className="text-xs text-text-primary">{ioc.context}</p>
            </div>
          )}

          {ioc.technique_ids.length > 0 && (
            <div className="mt-4">
              <p className="mb-1 text-xs text-text-muted">Techniques</p>
              <div className="flex flex-wrap gap-1">
                {ioc.technique_ids.map(t => (
                  <span key={t} className="font-mono rounded bg-purple-900 px-1.5 py-0.5 text-xs text-purple-300">{t}</span>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface p-6">
          <p className="text-xs font-medium text-text-muted mb-3">STIX 2.1 (preview)</p>
          <pre className="text-xs text-text-muted overflow-x-auto leading-relaxed">
            {JSON.stringify(
              {
                type: 'indicator',
                spec_version: '2.1',
                id: `indicator--${ioc.id}`,
                pattern: ioc.type === 'ip'
                  ? `[ipv4-addr:value = '${ioc.value}']`
                  : ioc.type === 'domain'
                  ? `[domain-name:value = '${ioc.value}']`
                  : ioc.type === 'hash'
                  ? `[file:hashes.'SHA-256' = '${ioc.value}']`
                  : `[artifact:payload_bin = '${ioc.value}']`,
                labels: [ioc.pyramid_tier],
                tlp: ioc.tlp,
                confidence_source: ioc.confidence_source,
                confidence_info: ioc.confidence_info,
              },
              null,
              2,
            )}
          </pre>
        </div>
      </div>
    </div>
  )
}
