import { X } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/api/client'

interface SyncSourceStatus {
  last_run: string | null
  status: string
}

interface SyncStatusResponse {
  sources: Record<string, SyncSourceStatus>
  scheduler_enabled: boolean
}

const FEED_LABELS: Record<string, { label: string; schedule: string }> = {
  attck:          { label: 'ATT&CK',        schedule: 'Manual' },
  misp_galaxy:    { label: 'MISP Galaxy',   schedule: 'Manual' },
  apt_sheet:      { label: 'APT Sheet',     schedule: 'Weekly' },
  abuse_ch:       { label: 'abuse.ch',      schedule: 'Daily 02h' },
  ipsum:          { label: 'IPsum',         schedule: 'Daily 03h' },
  phishtank:      { label: 'PhishTank',     schedule: 'Daily 03h' },
  malpedia:       { label: 'Malpedia',      schedule: 'Weekly' },
  yara_rules:     { label: 'Yara-Rules',    schedule: 'Weekly' },
  icewater:       { label: 'Icewater',      schedule: 'Weekly' },
  signature_base: { label: 'signature-base', schedule: 'Weekly' },
}

function statusIcon(status: string) {
  if (status === 'ok')     return <span className="text-green-400">✓ ok</span>
  if (status === 'no_key') return <span className="text-amber-400">⚠ no key</span>
  return <span className="text-zinc-500">— {status}</span>
}

function formatDate(ts: string | null) {
  if (!ts) return '—'
  return ts.slice(0, 10)
}

interface Props {
  open: boolean
  onClose: () => void
}

export function SyncStatus({ open, onClose }: Props) {
  const { data } = useQuery<SyncStatusResponse>({
    queryKey: ['sync-status'],
    queryFn: () => apiFetch<SyncStatusResponse>('/sync/status'),
    enabled: open,
    refetchInterval: open ? 30_000 : false,
  })

  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-lg rounded-xl border border-[#2a2a3e] bg-bg-surface p-6 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-text-primary">Sync Status</h2>
          <button onClick={onClose} className="text-text-muted hover:text-text-primary">
            <X size={16} />
          </button>
        </div>

        {data ? (
          <>
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-[#2a2a3e] text-left text-text-muted">
                  <th className="pb-2 font-medium">Feed</th>
                  <th className="pb-2 font-medium">Last Run</th>
                  <th className="pb-2 font-medium">Schedule</th>
                  <th className="pb-2 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(FEED_LABELS).map(([key, { label, schedule }]) => {
                  const src = data.sources[key]
                  return (
                    <tr key={key} className="border-b border-[#2a2a3e]">
                      <td className="py-2 text-text-primary">{label}</td>
                      <td className="py-2 text-text-muted">{src ? formatDate(src.last_run) : '—'}</td>
                      <td className="py-2 text-text-muted">{schedule}</td>
                      <td className="py-2">{src ? statusIcon(src.status) : <span className="text-zinc-500">—</span>}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
            {data.scheduler_enabled && (
              <p className="mt-3 text-xs text-green-400">Scheduler is active.</p>
            )}
          </>
        ) : (
          <p className="py-8 text-center text-xs text-text-muted">
            Loading sync status… (requires <code className="font-mono">GET /v1/sync/status</code>)
          </p>
        )}
      </div>
    </div>
  )
}
