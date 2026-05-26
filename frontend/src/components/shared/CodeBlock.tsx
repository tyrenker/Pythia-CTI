import { CopyButton } from './CopyButton'

interface Props {
  code: string
  language?: string
  maxLines?: number
  className?: string
}

export function CodeBlock({ code, language = 'text', maxLines, className }: Props) {
  const lines = code.split('\n')
  const display = maxLines ? lines.slice(0, maxLines).join('\n') : code
  const truncated = maxLines && lines.length > maxLines

  return (
    <div className={`relative rounded-lg border border-[#2a2a3e] bg-[#0d0d14] ${className ?? ''}`}>
      <div className="flex items-center justify-between border-b border-[#2a2a3e] px-3 py-1.5">
        <span className="text-xs font-mono text-text-muted">{language}</span>
        <CopyButton text={code} />
      </div>
      <pre className="overflow-x-auto p-4 text-xs leading-relaxed font-mono text-text-primary">
        <code>{display}</code>
        {truncated && (
          <span className="block mt-2 text-text-muted">… {lines.length - maxLines!} more lines</span>
        )}
      </pre>
    </div>
  )
}
