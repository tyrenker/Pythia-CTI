import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { X, Loader2, Lock } from 'lucide-react'
import { useParse } from '@/api/parse'
import { useApiKey } from '@/hooks/useApiKey'
import { ApiKeyModal } from '../settings/ApiKeyModal'

interface Props {
  open: boolean
  onClose: () => void
}

export function IngestBar({ open, onClose }: Props) {
  const navigate = useNavigate()
  const { apiKey } = useApiKey()
  const [tab, setTab] = useState<'url' | 'text'>('url')
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
      <div className="fixed inset-0 z-40 bg-black/60" onClick={onClose} />
      <div className="fixed inset-x-4 top-16 z-50 mx-auto max-w-2xl rounded-xl border border-[#2a2a3e] bg-bg-surface p-5 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-text-primary">⬡ Ingest Intel</h2>
          <button onClick={onClose} className="text-text-muted hover:text-text-primary">
            <X size={16} />
          </button>
        </div>

        <div className="mb-3 flex gap-2">
          {(['url', 'text'] as const).map(t => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`rounded px-3 py-1 text-xs font-medium transition-colors ${
                tab === t
                  ? 'bg-accent text-white'
                  : 'text-text-muted hover:text-text-primary'
              }`}
            >
              {t === 'url' ? 'URL' : 'Raw Text'}
            </button>
          ))}
        </div>

        {tab === 'url' ? (
          <input
            autoFocus
            value={url}
            onChange={e => setUrl(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleSubmit()}
            placeholder="https://..."
            className="w-full rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright"
          />
        ) : (
          <textarea
            autoFocus
            value={rawText}
            onChange={e => setRawText(e.target.value)}
            placeholder="Paste raw threat intel text here..."
            rows={5}
            className="w-full rounded-lg border border-[#2a2a3e] bg-bg-elevated px-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:ring-1 focus:ring-accent-bright resize-none"
          />
        )}

        {error && (
          <div className="mt-3 rounded-lg border border-red-900 bg-red-900/20 px-3 py-2 text-xs text-red-400">
            {error}
          </div>
        )}

        <div className="mt-4 flex items-center justify-between">
          <button
            onClick={handleSubmit}
            disabled={isPending || (!url && !rawText)}
            className="flex items-center gap-2 rounded-lg bg-accent px-4 py-2 text-xs font-medium text-white hover:opacity-90 transition-opacity disabled:opacity-50"
          >
            {isPending ? (
              <>
                <Loader2 size={12} className="animate-spin" />
                Claude is analyzing...
              </>
            ) : (
              'Parse with Claude'
            )}
          </button>
          {!apiKey && (
            <button
              onClick={() => setShowKeyModal(true)}
              className="flex items-center gap-1 text-xs text-text-muted hover:text-text-primary"
            >
              <Lock size={12} />
              Set API key first
            </button>
          )}
        </div>
      </div>

      <ApiKeyModal open={showKeyModal} onClose={() => setShowKeyModal(false)} />
    </>
  )
}
