import { cn } from '@/lib/utils'
import { TLP_COLORS } from '@/lib/constants'

interface Props {
  tlp: string
  className?: string
}

export function TlpBadge({ tlp, className }: Props) {
  const color = TLP_COLORS[tlp.toUpperCase()] ?? 'bg-zinc-700 text-zinc-200'
  return (
    <span className={cn('inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium font-mono', color, className)}>
      TLP:{tlp.toUpperCase()}
    </span>
  )
}
