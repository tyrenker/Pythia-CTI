import { useState } from 'react'
import { Trash2, Zap } from 'lucide-react'
import { useWatchlist, useCreateSubscription, useDeleteSubscription, useTestSubscription } from '@/api/watchlist'
import { timeAgo } from '@/lib/utils'
import { cn } from '@/lib/utils'

const WEBHOOK_TYPES = ['slack', 'discord', 'generic'] as const
const WEBHOOK_COLORS: Record<string, string> = {
  slack: 'bg-green-900 text-green-300',
  discord: 'bg-indigo-900 text-indigo-300',
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
    const filterValue = filterTab === 'actor' ? filterActor : filterTab === 'ttp' ? filterTtp : filterSector
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

  return (
    <div>
      <h1 className="mb-6 text-lg font-semibold text-text-primary">Watchlist & Alerting</h1>

      <div className="grid gap-6 lg:grid-cols-[1fr_320px]">
        {/* Subscriptions table */}
        <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface">
          {isLoading ? (
            <div className="p-4 space-y-2">
              {[1, 2, 3].map(i => <div key={i} className="h-10 animate-pulse rounded bg-bg-elevated" />)}
            </div>
          ) : !subs?.length ? (
            <div className="py-16 text-center text-xs text-text-muted">
              No subscriptions yet. Create one using the form.
            </div>
          ) : (
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-[#2a2a3e]">
                  {['Name', 'Trigger', 'Webhook', 'Type', 'Created', ''].map(h => (
                    <th key={h} className="px-3 py-2 text-left font-medium text-text-muted">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {subs.map(sub => {
                  const trigger = sub.filter_actor
                    ? `Actor: ${sub.filter_actor}`
                    : sub.filter_ttp
                    ? `TTP: ${sub.filter_ttp}`
                    : sub.filter_sector
                    ? `Sector: ${sub.filter_sector}`
                    : '—'
                  return (
                    <tr key={sub.id} className="border-b border-[#2a2a3e]">
                      <td className="px-3 py-2 font-medium text-text-primary">{sub.name}</td>
                      <td className="px-3 py-2 text-text-muted">{trigger}</td>
                      <td className="px-3 py-2 text-text-muted max-w-[160px] truncate">{sub.webhook_url}</td>
                      <td className="px-3 py-2">
                        <span className={cn('rounded px-1.5 py-0.5 text-xs', WEBHOOK_COLORS[sub.webhook_type] ?? 'bg-zinc-800 text-zinc-300')}>
                          {sub.webhook_type}
                        </span>
                      </td>
                      <td className="px-3 py-2 text-text-muted">{timeAgo(sub.created_at)}</td>
                      <td className="px-3 py-2">
                        <div className="flex gap-2">
                          <button
                            onClick={() =>
                              testMutation.mutate(sub.id, {
                                onSuccess: () => showToast('Test sent!', 'success'),
                                onError: (e: Error) => showToast(e.message, 'error'),
                              })
                            }
                            title="Test webhook"
                            className="text-text-muted hover:text-accent-bright"
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
                            className="text-text-muted hover:text-red-400"
                          >
                            <Trash2 size={14} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* Create form */}
        <div className="rounded-xl border border-[#2a2a3e] bg-bg-surface p-5">
          <h2 className="mb-4 text-sm font-semibold text-text-primary">Create Subscription</h2>

          <div className="space-y-3">
            <div>
              <label className="block mb-1 text-xs text-text-muted">Name</label>
              <input
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="Lazarus Watch"
                className="w-full rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
              />
            </div>

            <div>
              <label className="block mb-1 text-xs text-text-muted">Filter type</label>
              <div className="flex gap-2 mb-2">
                {(['actor', 'ttp', 'sector'] as FilterTab[]).map(t => (
                  <button
                    key={t}
                    onClick={() => setFilterTab(t)}
                    className={`rounded px-2.5 py-1 text-xs capitalize transition-colors ${
                      filterTab === t ? 'bg-accent text-white' : 'text-text-muted hover:text-text-primary'
                    }`}
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
              <label className="block mb-1 text-xs text-text-muted">Webhook URL</label>
              <input
                value={webhookUrl}
                onChange={e => setWebhookUrl(e.target.value)}
                placeholder="https://hooks.slack.com/..."
                className="w-full rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
              />
            </div>

            <div>
              <label className="block mb-1 text-xs text-text-muted">Webhook type</label>
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

            {formError && (
              <p className="text-xs text-red-400">{formError}</p>
            )}

            <button
              onClick={handleCreate}
              disabled={createMutation.isPending}
              className="w-full rounded-lg bg-accent py-2 text-xs font-medium text-white hover:opacity-90 transition-opacity disabled:opacity-50"
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
            'fixed bottom-6 right-6 rounded-lg px-4 py-2 text-xs font-medium shadow-lg',
            toast.type === 'success' ? 'bg-green-800 text-green-200' : 'bg-red-800 text-red-200',
          )}
        >
          {toast.msg}
        </div>
      )}
    </div>
  )
}
