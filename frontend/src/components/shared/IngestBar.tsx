import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { X, Loader2, Lock } from 'lucide-react'
import { useParse } from '@/api/parse'
import { useApiKey } from '@/hooks/useApiKey'
import { ApiKeyModal } from '../settings/ApiKeyModal'

interface Props {
  open: boolean
  onClose: () => void
  defaultTab?: 'url' | 'text'
}

export function IngestBar({ open, onClose, defaultTab = 'url' }: Props) {
  const navigate = useNavigate()
  const { apiKey } = useApiKey()
  const [tab, setTab] = useState<'url' | 'text'>(defaultTab)

  useEffect(() => {
    if (open) setTab(defaultTab)
  }, [open, defaultTab])
  const [url, setUrl] = useState('')
  const [rawText, setRawText] = useState('')
  const [showKeyModal, setShowKeyModal] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const { mutate: parse, isPending } = useParse()

  if (!open) return null

  function handleSubmit() {
    if (!apiKey) {
      setShowKeyModal(true)
      return
    }
    setError(null)
    const params = tab === 'url' ? { url } : { raw_text: rawText }
    parse(params, {
      onSuccess: (data) => {
        onClose()
        navigate(`/intel/${data.report_id}`)
      },
      onError: (err: Error) => setError(err.message),
    })
  }

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/75" onClick={onClose} />
      <div className="fixed inset-x-4 top-16 z-50 mx-auto max-w-2xl bg-[#0a0a0f] border border-[#00ff88]/40 p-5 shadow-[0_0_40px_rgba(0,255,136,0.1),0_0_80px_rgba(0,0,0,0.8)]">
        {/* Terminal header bar */}
        <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-[#00ff88]/50 to-transparent" />

        <div className="mb-1 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="font-mono text-[#00ff88]/60 text-xs select-none">{'>'}</span>
            <h2 className="font-mono text-xs font-bold uppercase tracking-[0.15em] text-[#00ff88]">
              ANALYZE_INTEL.EXE
            </h2>
            <span className="font-mono text-[10px] text-[#00ff88]/40 animate-blink">_</span>
          </div>
          <button
            onClick={onClose}
            className="text-[#6b7280] hover:text-[#ff3366] transition-colors p-0.5 border border-transparent hover:border-[#ff3366]/40"
          >
            <X size={14} strokeWidth={1.5} />
          </button>
        </div>
        <p className="mb-4 font-mono text-[11px] text-[#9ca3af] tracking-wide">
          Claude extracts IOCs, TTPs, threat actors, and malware families automatically.
        </p>

        {/* Tab selector */}
        <div className="mb-3 flex gap-1">
          {(['url', 'text'] as const).map(t => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`px-3 py-1 font-mono text-[10px] font-medium uppercase tracking-wider transition-all duration-100 border ${
                tab === t
                  ? 'border-[#00ff88] text-[#00ff88] bg-[#00ff88]/10 shadow-[0_0_8px_rgba(0,255,136,0.2)]'
                  : 'border-[#2a2a3a] text-[#6b7280] hover:border-[#6b7280] hover:text-[#e0e0e0]'
              }`}
            >
              [{t === 'url' ? 'URL' : 'TEXT'}]
            </button>
          ))}
        </div>

        {tab === 'url' ? (
          <div className="relative">
            <span className="absolute left-3 top-1/2 -translate-y-1/2 font-mono text-xs text-[#00ff88]/60 select-none">{'>'}</span>
            <input
              autoFocus
              value={url}
              onChange={e => setUrl(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleSubmit()}
              placeholder="https://..."
              className="w-full border border-[#2a2a3a] bg-[#12121a] pl-7 pr-3 py-2 font-mono text-sm text-[#00ff88] placeholder-[#6b7280]/50 focus:outline-none focus:border-[#00ff88] focus:shadow-[0_0_10px_rgba(0,255,136,0.1)] transition-all"
            />
          </div>
        ) : (
          <div className="relative">
            <span className="absolute left-3 top-3 font-mono text-xs text-[#00ff88]/60 select-none">{'>'}</span>
            <textarea
              autoFocus
              value={rawText}
              onChange={e => setRawText(e.target.value)}
              placeholder="Paste raw threat intel text here..."
              rows={5}
              className="w-full border border-[#2a2a3a] bg-[#12121a] pl-7 pr-3 py-2 font-mono text-sm text-[#00ff88] placeholder-[#6b7280]/50 focus:outline-none focus:border-[#00ff88] focus:shadow-[0_0_10px_rgba(0,255,136,0.1)] transition-all resize-none"
            />
          </div>
        )}

        {error && (
          <div className="mt-3 border border-[#ff3366] bg-[#ff3366]/10 px-3 py-2 font-mono text-xs text-[#ff3366]">
            <span className="text-[#ff3366]/60">ERR: </span>{error}
          </div>
        )}

        <div className="mt-4 flex items-center justify-between">
          <button
            onClick={handleSubmit}
            disabled={isPending || (!url && !rawText)}
            className="flex items-center gap-2 bg-[#00ff88] px-5 py-2 font-mono text-xs font-bold uppercase tracking-wider text-[#0a0a0f] cyber-chamfer-sm transition-all hover:shadow-[0_0_20px_rgba(0,255,136,0.5)] disabled:opacity-40 disabled:cursor-not-allowed active:scale-[0.98]"
          >
            {isPending ? (
              <>
                <Loader2 size={12} className="animate-spin" strokeWidth={2} />
                ANALYZING...
              </>
            ) : (
              <>PARSE_WITH_CLAUDE</>
            )}
          </button>
          {!apiKey && (
            <button
              onClick={() => setShowKeyModal(true)}
              className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-wider text-[#6b7280] hover:text-[#f59e0b] transition-colors"
            >
              <Lock size={11} strokeWidth={1.5} />
              SET_API_KEY
            </button>
          )}
        </div>
      </div>

      <ApiKeyModal open={showKeyModal} onClose={() => setShowKeyModal(false)} />
    </>
  )
}
