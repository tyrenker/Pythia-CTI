import { useState } from 'react'
import { X } from 'lucide-react'
import { useApiKey } from '@/hooks/useApiKey'

interface Props {
  open: boolean
  onClose: () => void
}

export function ApiKeyModal({ open, onClose }: Props) {
  const { apiKey, setApiKey } = useApiKey()
  const [draft, setDraft] = useState('')

  if (!open) return null

  const masked = apiKey
    ? `sk-ant-${'•'.repeat(14)} (last 4: ${apiKey.slice(-4)})`
    : 'Not configured'

  function handleSave() {
    if (draft.trim()) {
      setApiKey(draft.trim())
      setDraft('')
      onClose()
    }
  }

  function handleClear() {
    setApiKey('')
    setDraft('')
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

        <div className="mb-4">
          <label className="block mb-1 text-xs text-text-muted">Current key</label>
          <p className="font-mono text-xs text-text-primary">{masked}</p>
        </div>

        <div className="mb-4">
          <label className="block mb-1 text-xs text-text-muted">New key</label>
          <input
            type="password"
            value={draft}
            onChange={e => setDraft(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleSave()}
            placeholder="sk-ant-..."
            className="w-full rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2 text-xs text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
          />
        </div>

        <p className="mb-4 text-xs text-text-muted">
          Your key is stored only in this browser and never sent to any server other than your local Pythia instance.
        </p>

        <div className="mb-5 border-t border-[#2a2a3e] pt-4">
          <p className="mb-3 text-xs font-semibold text-text-muted">Feed API Keys (optional)</p>
          <div className="space-y-3">
            <div>
              <p className="text-xs font-medium text-text-primary">Malpedia API Key</p>
              <p className="mt-0.5 text-xs text-text-muted">Enables full family-actor associations on sync.</p>
            </div>
            <div>
              <p className="text-xs font-medium text-text-primary">PhishTank App Key</p>
              <p className="mt-0.5 text-xs text-text-muted">Required for the PhishTank phishing URL feed.</p>
            </div>
          </div>
          <p className="mt-3 text-xs text-text-muted">
            Set these in your <code className="font-mono">.env</code> file as{' '}
            <code className="font-mono">MALPEDIA_API_KEY</code> and{' '}
            <code className="font-mono">PHISHTANK_API_KEY</code>.
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
