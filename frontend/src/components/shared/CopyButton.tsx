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
        'inline-flex items-center gap-1 border border-[#2a2a3a] px-2 py-1 font-mono text-[9px] uppercase tracking-wider text-[#6b7280] transition-all hover:border-[#00ff88]/40 hover:text-[#00ff88]',
        copied && 'border-[#00ff88]/40 text-[#00ff88]',
        className,
      )}
      title="Copy to clipboard"
    >
      {copied
        ? <><Check size={10} strokeWidth={2} /> COPIED</>
        : <><Copy size={10} strokeWidth={1.5} /> COPY</>
      }
    </button>
  )
}
