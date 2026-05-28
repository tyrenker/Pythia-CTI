import { useState } from 'react'
import { Bell, Trash2, Zap } from 'lucide-react'
import { useWatchlist, useCreateSubscription, useDeleteSubscription, useTestSubscription } from '@/api/watchlist'
import { PageHeader } from '@/components/shared/PageHeader'
import { timeAgo } from '@/lib/utils'
import { cn } from '@/lib/utils'

const WEBHOOK_TYPES = ['slack', 'discord', 'generic'] as const

const WEBHOOK_COLORS: Record<string, string> = {
  slack: 'bg-green-900/40 text-green-300',
  discord: 'bg-indigo-900/40 text-indigo-300',
  generic: 'bg-zinc-800 text-zinc-300',
}

type FilterTab = 'actor' | 'ttp' | 'sector'

export function Watchlist() {
  const { data: subs, isLoading } = useWatchlist()
  const createMutation = useCreateSubscription()
  const deleteMutation = useDeleteSubscription()
  const testMutation = useTestSubscription()

  const [name, setName] = useState('')
  const [webhookUrl, setWebhookUrl] = useState('')
  const [webhookType, setWebhookType] = useState<typeof WEBHOOK_TYPES[number]>('slack')
  const [filterTab, setFilterTab] = useState<FilterTab>('actor')
  const [filterActor, setFilterActor] = useState('')
  const [filterTtp, setFilterTtp] = useState('')
  const [filterSector, setFilterSector] = useState('')
  const [formError, setFormError] = useState<string | null>(null)
  const [toast, setToast] = useState<{ msg: string; type: 'success' | 'error' } | null>(null)

  function showToast(msg: string, type: 'success' | 'error') {
    setToast({ msg, type })
    setTimeout(() => setToast(null), 4000)
  }

  function handleCreate() {
    const filterValue =
      filterTab === 'actor' ? filterActor : filterTab === 'ttp' ? filterTtp : filterSector
    if (!filterValue.trim()) {
      setFormError('At least one filter field is required.')
      return
    }
    if (!webhookUrl.trim()) {
      setFormError('Webhook URL is required.')
      return
    }
    setFormError(null)

    createMutation.mutate(
      {
        name: name.trim() || `${filterTab}: ${filterValue}`,
        webhook_url: webhookUrl,
        webhook_type: webhookType,
        filter_actor: filterTab === 'actor' ? filterActor : undefined,
        filter_ttp: filterTab === 'ttp' ? filterTtp : undefined,
        filter_sector: filterTab === 'sector' ? filterSector : undefined,
      },
      {
        onSuccess: () => {
          showToast('Subscription created.', 'success')
          setName('')
          setWebhookUrl('')
          setFilterActor('')
          setFilterTtp('')
          setFilterSector('')
        },
        onError: (e: Error) => showToast(e.message, 'error'),
      },
    )
  }

  const isEmpty = !isLoading && (!subs || subs.length === 0)

  return (
    <div>
      <PageHeader
        title="Watchlist & Alerting"
        description="Monitor threat actors, ATT&CK techniques, or sectors. Get instant alerts when Pythia ingests matching intelligence."
      />

      {/* Feature explainer — shown only when no subscriptions */}
      {isEmpty && (
        <div className="mb-6 rounded-xl border border-accent/30 bg-accent/5 p-6">
          <div className="flex items-start gap-4">
            <div className="rounded-lg bg-accent/20 p-3">
              <Bell size={20} className="text-accent-bright" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-text-primary">No subscriptions yet</h3>
              <p className="mt-1 text-xs text-text-muted leading-relaxed">
                Monitor specific threat actors, ATT&CK techniques, or industry sectors. Get instant
                alerts when Pythia ingests matching intelligence — delivered to Slack, Discord, or
                any webhook endpoint.
              </p>
              <p className="mt-3 text-xs text-text-muted">
                Use the form below to create your first alert subscription.
              </p>
            </div>
          </div>
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-[1fr_320px]">
        {/* Subscriptions — cards when data, loading state otherwise */}
        <div>
          {isLoading ? (
            <div className="space-y-3">
              {[1, 2, 3].map(i => (
                <div key={i} className="h-24 animate-pulse rounded-xl bg-bg-surface" />
              ))}
            </div>
          ) : subs && subs.length > 0 ? (
            <div className="grid gap-3 sm:grid-cols-2">
              {subs.map(sub => {
                const trigger = sub.filter_actor
                  ? `Actor: ${sub.filter_actor}`
                  : sub.filter_ttp
                  ? `TTP: ${sub.filter_ttp}`
                  : sub.filter_sector
                  ? `Sector: ${sub.filter_sector}`
                  : '—'
                return (
                  <div
                    key={sub.id}
                    className="rounded-xl border border-[#2a2a3e] bg-bg-surface p-4"
                  >
                    <div className="mb-2 flex items-start justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="h-2 w-2 rounded-full bg-green-500" title="Active" />
                        <span className="text-sm font-medium text-text-primary">{sub.name}</span>
                      </div>
                      <span
                        className={cn(
                          'rounded px-1.5 py-0.5 text-xs',
                          WEBHOOK_COLORS[sub.webhook_type] ?? 'bg-zinc-800 text-zinc-300',
                        )}
                      >
                        {sub.webhook_type}
                      </span>
                    </div>
                    <p className="text-xs text-text-muted">{trigger}</p>
                    <p
                      className="mt-1 max-w-full truncate text-xs text-text-muted"
                      title={sub.webhook_url}
                    >
                      {sub.webhook_url}
                    </p>
                    <div className="mt-3 flex items-center justify-between">
                      <span className="text-xs text-text-muted">
                        Created {timeAgo(sub.created_at)}
                      </span>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() =>
                            testMutation.mutate(sub.id, {
                              onSuccess: () => showToast('Test sent!', 'success'),
                              onError: (e: Error) => showToast(e.message, 'error'),
                            })
                          }
                          title="Test webhook"
                          className="rounded p-1 text-text-muted transition-colors hover:text-accent-bright"
                        >
                          <Zap size={14} />
                        </button>
                        <button
                          onClick={() =>
                            deleteMutation.mutate(sub.id, {
                              onSuccess: () => showToast('Deleted.', 'success'),
                            })
                          }
                          title="Delete"
                          className="rounded p-1 text-text-muted transition-colors hover:text-red-400"
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          ) : null}
        </div>

        {/* Create form */}
        <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface p-5">
          <h2 className="mb-4 text-sm font-semibold text-text-primary">Create Subscription</h2>

          <div className="space-y-3">
            <div>
              <label className="mb-1 block text-xs text-text-muted">Name</label>
              <input
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="Lazarus Watch"
                className="w-full rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
              />
            </div>

            <div>
              <label className="mb-1 block text-xs text-text-muted">Filter type</label>
              <div className="mb-2 flex gap-1 rounded-lg border border-[#2a2a3e] bg-bg-elevated p-0.5">
                {(['actor', 'ttp', 'sector'] as FilterTab[]).map(t => (
                  <button
                    key={t}
                    onClick={() => setFilterTab(t)}
                    className={cn(
                      'flex-1 rounded-md px-2 py-1 text-xs capitalize transition-colors',
                      filterTab === t
                        ? 'bg-accent text-white'
                        : 'text-text-muted hover:text-text-primary',
                    )}
                  >
                    {t}
                  </button>
                ))}
              </div>
              {filterTab === 'actor' && (
                <input
                  value={filterActor}
                  onChange={e => setFilterActor(e.target.value)}
                  placeholder="lazarus"
                  className="w-full rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
                />
              )}
              {filterTab === 'ttp' && (
                <input
                  value={filterTtp}
                  onChange={e => setFilterTtp(e.target.value)}
                  placeholder="T1566"
                  className="w-full rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
                />
              )}
              {filterTab === 'sector' && (
                <input
                  value={filterSector}
                  onChange={e => setFilterSector(e.target.value)}
                  placeholder="finance"
                  className="w-full rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
                />
              )}
            </div>

            <div>
              <label className="mb-1 block text-xs text-text-muted">Webhook URL</label>
              <input
                value={webhookUrl}
                onChange={e => setWebhookUrl(e.target.value)}
                placeholder="https://hooks.slack.com/..."
                className="w-full rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
              />
            </div>

            <div>
              <label className="mb-1 block text-xs text-text-muted">Webhook type</label>
              <select
                value={webhookType}
                onChange={e => setWebhookType(e.target.value as typeof WEBHOOK_TYPES[number])}
                className="w-full rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2 text-xs text-text-primary focus:outline-none"
              >
                {WEBHOOK_TYPES.map(t => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
            </div>

            {formError && <p className="text-xs text-red-400">{formError}</p>}

            <button
              onClick={handleCreate}
              disabled={createMutation.isPending}
              className="w-full rounded-lg bg-accent py-2 text-xs font-medium text-white transition-opacity hover:opacity-90 disabled:opacity-50"
            >
              {createMutation.isPending ? 'Creating…' : 'Create Subscription'}
            </button>
          </div>
        </div>
      </div>

      {/* Toast */}
      {toast && (
        <div
          className={cn(
            'fixed bottom-6 right-6 z-50 rounded-lg px-4 py-2 text-xs font-medium shadow-lg',
            toast.type === 'success' ? 'bg-green-800 text-green-200' : 'bg-red-800 text-red-200',
          )}
        >
          {toast.msg}
        </div>
      )}
    </div>
  )
}
