import { useState } from 'react'
import { Maximize2, X } from 'lucide-react'
import { CopyButton } from './CopyButton'

interface Props {
  code: string
  language?: string
  maxLines?: number
  expandable?: boolean
  title?: string
  className?: string
}

export function CodeBlock({ code, language = 'text', maxLines, expandable, title, className }: Props) {
  const [modalOpen, setModalOpen] = useState(false)
  const lines = code.split('\n')
  const display = maxLines ? lines.slice(0, maxLines).join('\n') : code
  const truncated = maxLines && lines.length > maxLines

  return (
    <>
      <div className={`relative rounded-lg border border-[#2a2a3e] bg-[#0d0d14] ${className ?? ''}`}>
        <div className="flex items-center justify-between border-b border-[#2a2a3e] px-3 py-1.5">
          <span className="text-xs font-mono text-text-muted">{language}</span>
          <div className="flex items-center gap-1">
            <CopyButton text={code} />
            {expandable && (
              <button
                onClick={() => setModalOpen(true)}
                className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-text-muted hover:text-text-primary transition-colors"
                title="Expand"
              >
                <Maximize2 size={12} />
                Expand
              </button>
            )}
          </div>
        </div>
        <pre className="overflow-x-auto p-4 text-xs leading-relaxed font-mono text-text-primary">
          <code>{display}</code>
          {truncated && (
            <span className="block mt-2 text-text-muted">… {lines.length - maxLines!} more lines</span>
          )}
        </pre>
      </div>

      {modalOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-6"
          onClick={() => setModalOpen(false)}
        >
          <div
            className="flex w-full max-w-4xl flex-col rounded-xl border border-[#2a2a3e] bg-[#0d0d14] shadow-2xl"
            style={{ maxHeight: '85vh' }}
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-[#2a2a3e] px-4 py-2.5">
              <div className="flex items-center gap-3">
                <span className="font-mono text-xs text-text-muted">{language}</span>
                {title && <span className="text-xs font-medium text-text-primary">{title}</span>}
              </div>
              <div className="flex items-center gap-1">
                <CopyButton text={code} />
                <button
                  onClick={() => setModalOpen(false)}
                  className="rounded p-1.5 text-text-muted hover:text-text-primary transition-colors"
                  title="Close"
                >
                  <X size={14} />
                </button>
              </div>
            </div>
            <pre className="flex-1 overflow-auto p-5 text-xs leading-relaxed font-mono text-text-primary">
              <code>{code}</code>
            </pre>
          </div>
        </div>
      )}
    </>
  )
}
