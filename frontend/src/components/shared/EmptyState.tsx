import { cn } from '@/lib/utils'

interface Props {
  title: string
  description?: string
  className?: string
}

export function EmptyState({ title, description, className }: Props) {
  return (
    <div className={cn('flex flex-col items-center justify-center py-16 text-center', className)}>
      <div className="mb-4 font-mono text-3xl text-[#2a2a3a] select-none">
        <span className="text-[#00ff88]/30">[ </span>
        <span className="text-[#6b7280]/40">NULL</span>
        <span className="text-[#00ff88]/30"> ]</span>
      </div>
      <p className="font-mono text-xs uppercase tracking-[0.15em] text-[#6b7280]">{title}</p>
      {description && (
        <p className="mt-2 font-mono text-[11px] text-[#6b7280]/60 max-w-xs leading-relaxed">{description}</p>
      )}
      <p className="mt-3 font-mono text-[10px] text-[#2a2a3a]">
        <span className="text-[#00ff88]/40 blink">_</span>
      </p>
    </div>
  )
}
