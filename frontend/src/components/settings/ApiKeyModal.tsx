import { useState } from 'react'
import { X } from 'lucide-react'
import { useApiKey } from '@/hooks/useApiKey'

const CLAUDE_KEY = 'pythia_claude_api_key'

interface Props {
  open: boolean
  onClose: () => void
}

export function ApiKeyModal({ open, onClose }: Props) {
  // pythia_api_key → sent as X-API-Key to authenticate write endpoints
  const { apiKey: serverKey, setApiKey: setServerKey } = useApiKey()
  const [serverDraft, setServerDraft] = useState('')

  // Claude API key stored separately (used by the backend via .env, shown here for reference)
  const [claudeDraft, setClaudeDraft] = useState('')
  const storedClaudeKey = localStorage.getItem(CLAUDE_KEY) ?? ''

  if (!open) return null

  const maskedServer = serverKey
    ? `${'•'.repeat(Math.max(0, serverKey.length - 4))}${serverKey.slice(-4)}`
    : 'Not set'

  const maskedClaude = storedClaudeKey
    ? `sk-ant-${'•'.repeat(14)} (last 4: ${storedClaudeKey.slice(-4)})`
    : 'Not set'

  function handleSave() {
    if (serverDraft.trim()) setServerKey(serverDraft.trim())
    if (claudeDraft.trim()) localStorage.setItem(CLAUDE_KEY, claudeDraft.trim())
    setServerDraft('')
    setClaudeDraft('')
    onClose()
  }

  function handleClear() {
    setServerKey('')
    localStorage.removeItem(CLAUDE_KEY)
    setServerDraft('')
    setClaudeDraft('')
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75">
      <div className="w-full max-w-md bg-[#0a0a0f] border border-[#2a2a3a] p-6 shadow-[0_0_40px_rgba(0,0,0,0.8)] relative">
        {/* top accent line */}
        <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-[#00ff88]/40 to-transparent" />

        <div className="mb-5 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="font-mono text-[#00ff88]/50 text-xs select-none">{'// '}</span>
            <h2 className="font-mono text-xs font-bold uppercase tracking-[0.15em] text-[#e0e0e0]">
              API_KEY_SETTINGS
            </h2>
          </div>
          <button
            onClick={onClose}
            className="text-[#6b7280] hover:text-[#ff3366] transition-colors p-0.5 border border-transparent hover:border-[#ff3366]/40"
          >
            <X size={14} strokeWidth={1.5} />
          </button>
        </div>

        {/* Pythia server key */}
        <div className="mb-5">
          <label className="block mb-1 font-mono text-[10px] uppercase tracking-[0.12em] text-[#b0b0c8]">
            Pythia API Key
          </label>
          <p className="mb-2 font-mono text-[11px] text-[#9ca3af]">{maskedServer}</p>
          <div className="relative">
            <span className="absolute left-3 top-1/2 -translate-y-1/2 font-mono text-[10px] text-[#00ff88]/50 select-none">{'>'}</span>
            <input
              type="password"
              value={serverDraft}
              onChange={e => setServerDraft(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleSave()}
              placeholder="Value of PYTHIA_API_KEY in your .env"
              className="w-full border border-[#2a2a3a] bg-[#12121a] pl-7 pr-3 py-2 font-mono text-xs text-[#e0e0e0] placeholder-[#6b7280]/50 focus:outline-none focus:border-[#00ff88] transition-colors"
            />
          </div>
          <p className="mt-1.5 font-mono text-[10px] text-[#9ca3af]">
            Required to use write endpoints (ingest, poll feeds, watchlist).
          </p>
        </div>

        <div className="mb-5 border-t border-[#2a2a3a] pt-5">
          <div className="mb-5">
            <label className="block mb-1 font-mono text-[10px] uppercase tracking-[0.12em] text-[#b0b0c8]">
              Claude (Anthropic) API Key
            </label>
            <p className="mb-2 font-mono text-[11px] text-[#9ca3af]">{maskedClaude}</p>
            <div className="relative">
              <span className="absolute left-3 top-1/2 -translate-y-1/2 font-mono text-[10px] text-[#00ff88]/50 select-none">{'>'}</span>
              <input
                type="password"
                value={claudeDraft}
                onChange={e => setClaudeDraft(e.target.value)}
                placeholder="sk-ant-..."
                className="w-full border border-[#2a2a3a] bg-[#12121a] pl-7 pr-3 py-2 font-mono text-xs text-[#e0e0e0] placeholder-[#6b7280]/50 focus:outline-none focus:border-[#00ff88] transition-colors"
              />
            </div>
            <p className="mt-1.5 font-mono text-[10px] text-[#9ca3af]">
              Used by the backend for AI ingestion. Set{' '}
              <code className="text-[#00ff88]">ANTHROPIC_API_KEY</code> in{' '}
              <code className="text-[#00ff88]">.env</code> — storing it here is optional.
            </p>
          </div>

          <p className="font-mono text-[10px] uppercase tracking-[0.12em] text-[#b0b0c8] mb-1.5">
            Other feed keys (server-side only)
          </p>
          <p className="font-mono text-[10px] text-[#9ca3af]">
            Set <code className="text-[#00ff88]">MALPEDIA_API_KEY</code> and{' '}
            <code className="text-[#00ff88]">PHISHTANK_API_KEY</code> in your{' '}
            <code className="text-[#00ff88]">.env</code> file.
          </p>
        </div>

        <div className="flex gap-2">
          <button
            onClick={handleSave}
            className="flex-1 bg-[#00ff88] py-2 font-mono text-xs font-bold uppercase tracking-wider text-[#0a0a0f] cyber-chamfer-sm transition-all hover:shadow-[0_0_15px_rgba(0,255,136,0.4)] active:scale-[0.98]"
          >
            SAVE
          </button>
          <button
            onClick={handleClear}
            className="border border-[#ff3366]/50 px-4 py-2 font-mono text-xs font-medium uppercase tracking-wider text-[#ff3366] transition-all hover:bg-[#ff3366]/10 hover:shadow-[0_0_8px_rgba(255,51,102,0.2)]"
          >
            CLEAR
          </button>
          <button
            onClick={onClose}
            className="border border-[#2a2a3a] px-4 py-2 font-mono text-xs font-medium uppercase tracking-wider text-[#6b7280] transition-all hover:border-[#6b7280] hover:text-[#e0e0e0]"
          >
            ESC
          </button>
        </div>
      </div>
    </div>
  )
}
