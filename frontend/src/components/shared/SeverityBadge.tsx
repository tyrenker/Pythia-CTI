import { cn } from '@/lib/utils'
import { SEVERITY_COLORS } from '@/lib/constants'

interface Props {
  severity: string
  className?: string
}

export function SeverityBadge({ severity, className }: Props) {
  const color = SEVERITY_COLORS[severity.toLowerCase()] ?? 'border border-[#6b7280] text-[#9ca3af] bg-[#6b7280]/10'
  return (
    <span className={cn(
      'inline-flex items-center px-1.5 py-0.5 text-[10px] font-mono font-medium uppercase tracking-wider rounded-none',
      color,
      className,
    )}>
      {severity}
    </span>
  )
}
