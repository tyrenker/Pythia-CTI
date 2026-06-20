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
      <div className={`relative border border-[#2a2a3a] bg-[#0a0a0f] ${className ?? ''}`}>
        <div className="flex items-center justify-between border-b border-[#2a2a3a] bg-[#12121a] px-3 py-1.5">
          <div className="flex items-center gap-2">
            <span className="font-mono text-[9px] uppercase tracking-[0.12em] text-[#00ff88]/60">{language}</span>
            {title && <span className="font-mono text-[9px] text-[#6b7280]">// {title}</span>}
          </div>
          <div className="flex items-center gap-1">
            <CopyButton text={code} />
            {expandable && (
              <button
                onClick={() => setModalOpen(true)}
                className="inline-flex items-center gap-1 border border-[#2a2a3a] px-2 py-1 font-mono text-[9px] uppercase tracking-wider text-[#6b7280] transition-all hover:border-[#00ff88]/40 hover:text-[#00ff88]"
                title="Expand"
              >
                <Maximize2 size={10} strokeWidth={1.5} /> EXPAND
              </button>
            )}
          </div>
        </div>
        <pre className="overflow-x-auto p-4 font-mono text-xs leading-relaxed text-[#e0e0e0]">
          <code>{display}</code>
          {truncated && (
            <span className="block mt-2 font-mono text-[10px] text-[#6b7280]">
              {'... '}{lines.length - maxLines!} more lines
            </span>
          )}
        </pre>
      </div>

      {modalOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-6"
          onClick={() => setModalOpen(false)}
        >
          <div
            className="flex w-full max-w-4xl flex-col border border-[#2a2a3a] bg-[#0a0a0f] shadow-[0_0_60px_rgba(0,0,0,0.9)]"
            style={{ maxHeight: '85vh' }}
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-[#2a2a3a] bg-[#12121a] px-4 py-2.5">
              <div className="flex items-center gap-3">
                <span className="font-mono text-[9px] uppercase tracking-[0.12em] text-[#00ff88]/60">{language}</span>
                {title && <span className="font-mono text-[10px] text-[#6b7280]">// {title}</span>}
              </div>
              <div className="flex items-center gap-2">
                <CopyButton text={code} />
                <button
                  onClick={() => setModalOpen(false)}
                  className="p-1 text-[#6b7280] hover:text-[#ff3366] transition-colors border border-transparent hover:border-[#ff3366]/40"
                  title="Close"
                >
                  <X size={13} strokeWidth={1.5} />
                </button>
              </div>
            </div>
            <pre className="flex-1 overflow-auto p-5 font-mono text-xs leading-relaxed text-[#e0e0e0]">
              <code>{code}</code>
            </pre>
          </div>
        </div>
      )}
    </>
  )
}
