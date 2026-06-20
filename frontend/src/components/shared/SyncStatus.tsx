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
  attck:          { label: 'ATT&CK',           schedule: 'Manual' },
  misp_galaxy:    { label: 'MISP Galaxy',       schedule: 'Manual' },
  mitre_malware:  { label: 'ATT&CK Malware',    schedule: 'Manual' },
  misp_malware:   { label: 'MISP Malpedia',     schedule: 'Manual' },
  apt_sheet:      { label: 'APT Sheet',         schedule: 'Weekly' },
  abuse_ch:       { label: 'abuse.ch',          schedule: 'Daily 02h' },
  ipsum:          { label: 'IPsum',             schedule: 'Daily 03h' },
  phishtank:      { label: 'PhishTank',         schedule: 'Daily 03h' },
  yara_rules:     { label: 'Yara-Rules',        schedule: 'Weekly' },
  icewater:       { label: 'Icewater',          schedule: 'Weekly' },
  signature_base: { label: 'signature-base',    schedule: 'Weekly' },
}

function statusIcon(status: string) {
  if (status === 'ok')     return <span className="font-mono text-[#00ff88]">[OK]</span>
  if (status === 'no_key') return <span className="font-mono text-[#f59e0b]">[NO_KEY]</span>
  return <span className="font-mono text-[#6b7280]">[{status}]</span>
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
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75">
      <div className="w-full max-w-lg border border-[#2a2a3a] bg-[#0a0a0f] p-6 shadow-[0_0_40px_rgba(0,0,0,0.8)] relative">
        <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-[#00ff88]/40 to-transparent" />

        <div className="mb-5 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="font-mono text-[#00ff88]/50 text-[10px] select-none">{'// '}</span>
            <h2 className="font-mono text-xs font-bold uppercase tracking-[0.15em] text-[#e0e0e0]">
              SYNC_STATUS
            </h2>
          </div>
          <button
            onClick={onClose}
            className="text-[#6b7280] hover:text-[#ff3366] transition-colors p-0.5 border border-transparent hover:border-[#ff3366]/40"
          >
            <X size={14} strokeWidth={1.5} />
          </button>
        </div>

        {data ? (
          <>
            <table className="w-full">
              <thead>
                <tr className="border-b-2 border-[#2a2a3a]">
                  <th className="pb-2 text-left font-mono text-[9px] uppercase tracking-[0.15em] text-[#6b7280]">Feed</th>
                  <th className="pb-2 text-left font-mono text-[9px] uppercase tracking-[0.15em] text-[#6b7280]">Last Run</th>
                  <th className="pb-2 text-left font-mono text-[9px] uppercase tracking-[0.15em] text-[#6b7280]">Schedule</th>
                  <th className="pb-2 text-left font-mono text-[9px] uppercase tracking-[0.15em] text-[#6b7280]">Status</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(FEED_LABELS).map(([key, { label, schedule }]) => {
                  const src = data.sources[key]
                  return (
                    <tr key={key} className="border-b border-[#2a2a3a]/60 hover:bg-[#00ff88]/[0.02] transition-colors">
                      <td className="py-2 font-mono text-[10px] text-[#e0e0e0]">{label}</td>
                      <td className="py-2 font-mono text-[10px] text-[#6b7280]">{src ? formatDate(src.last_run) : '—'}</td>
                      <td className="py-2 font-mono text-[10px] text-[#6b7280]">{schedule}</td>
                      <td className="py-2 font-mono text-[10px]">{src ? statusIcon(src.status) : <span className="text-[#6b7280]">—</span>}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
            {data.scheduler_enabled && (
              <p className="mt-3 font-mono text-[10px] text-[#00ff88]">
                {'> '} SCHEDULER_ACTIVE
              </p>
            )}
          </>
        ) : (
          <p className="py-8 text-center font-mono text-[10px] uppercase tracking-widest text-[#6b7280]">
            Loading sync status...
          </p>
        )}
      </div>
    </div>
  )
}
