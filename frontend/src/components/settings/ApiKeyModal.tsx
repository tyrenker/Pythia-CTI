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
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-md rounded-xl border border-[#2a2a3e] bg-bg-surface p-6 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-text-primary">API Key Settings</h2>
          <button onClick={onClose} className="text-text-muted hover:text-text-primary">
            <X size={16} />
          </button>
        </div>

        {/* Pythia server key */}
        <div className="mb-4">
          <label className="block mb-1 text-xs font-medium text-text-primary">
            Pythia API Key
          </label>
          <p className="mb-1.5 font-mono text-xs text-text-muted">{maskedServer}</p>
          <input
            type="password"
            value={serverDraft}
            onChange={e => setServerDraft(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleSave()}
            placeholder="Value of PYTHIA_API_KEY in your .env"
            className="w-full rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
          />
          <p className="mt-1 text-xs text-text-muted">
            Required to use write endpoints (ingest, poll feeds, watchlist).
          </p>
        </div>

        <div className="mb-5 border-t border-[#2a2a3e] pt-4">
          {/* Claude key — informational, backend reads from .env */}
          <div className="mb-4">
            <label className="block mb-1 text-xs font-medium text-text-primary">
              Claude (Anthropic) API Key
            </label>
            <p className="mb-1.5 font-mono text-xs text-text-muted">{maskedClaude}</p>
            <input
              type="password"
              value={claudeDraft}
              onChange={e => setClaudeDraft(e.target.value)}
              placeholder="sk-ant-..."
              className="w-full rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
            />
            <p className="mt-1 text-xs text-text-muted">
              Used by the backend for AI ingestion. Set <code className="font-mono">ANTHROPIC_API_KEY</code> in <code className="font-mono">.env</code> — storing it here is optional.
            </p>
          </div>

          <p className="text-xs font-semibold text-text-muted mb-2">Other feed keys (server-side only)</p>
          <p className="text-xs text-text-muted">
            Set <code className="font-mono">MALPEDIA_API_KEY</code> and{' '}
            <code className="font-mono">PHISHTANK_API_KEY</code> in your <code className="font-mono">.env</code> file.
          </p>
        </div>

        <div className="flex gap-2">
          <button
            onClick={handleSave}
            className="flex-1 rounded-lg bg-accent py-2 text-xs font-medium text-white hover:opacity-90 transition-opacity"
          >
            Save
          </button>
          <button
            onClick={handleClear}
            className="rounded-lg border border-[#2a2a3e] px-4 py-2 text-xs text-text-muted hover:text-text-primary transition-colors"
          >
            Clear
          </button>
          <button
            onClick={onClose}
            className="rounded-lg border border-[#2a2a3e] px-4 py-2 text-xs text-text-muted hover:text-text-primary transition-colors"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  )
}
