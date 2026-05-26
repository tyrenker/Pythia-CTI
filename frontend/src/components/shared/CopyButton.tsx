import { Check, Copy } from 'lucide-react'
import { useCopyToClipboard } from '@/hooks/useCopyToClipboard'
import { cn } from '@/lib/utils'

interface Props {
  text: string
  className?: string
}

export function CopyButton({ text, className }: Props) {
  const { copy, copied } = useCopyToClipboard()
  return (
    <button
      onClick={() => copy(text)}
      className={cn(
        'inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-text-muted hover:text-text-primary transition-colors',
        className,
      )}
      title="Copy to clipboard"
    >
      {copied ? <Check size={12} className="text-green-400" /> : <Copy size={12} />}
      {copied ? 'Copied' : 'Copy'}
    </button>
  )
}
