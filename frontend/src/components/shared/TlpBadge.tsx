import { cn } from '@/lib/utils'
import { TLP_COLORS } from '@/lib/constants'

interface Props {
  tlp: string
  className?: string
}

export function TlpBadge({ tlp, className }: Props) {
  const color = TLP_COLORS[tlp.toUpperCase()] ?? 'border border-[#6b7280] text-[#9ca3af] bg-[#6b7280]/10'
  return (
    <span className={cn(
      'inline-flex items-center px-1.5 py-0.5 text-[10px] font-mono font-medium tracking-wider rounded-none',
      color,
      className,
    )}>
      TLP:{tlp.toUpperCase()}
    </span>
  )
}
