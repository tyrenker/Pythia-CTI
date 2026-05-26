import { cn } from '@/lib/utils'
import { SEVERITY_COLORS } from '@/lib/constants'

interface Props {
  severity: string
  className?: string
}

export function SeverityBadge({ severity, className }: Props) {
  const color = SEVERITY_COLORS[severity.toLowerCase()] ?? 'bg-zinc-800 text-zinc-300'
  return (
    <span className={cn('inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium capitalize', color, className)}>
      {severity}
    </span>
  )
}
