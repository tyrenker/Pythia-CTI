import type { LucideIcon } from 'lucide-react'
import { cn } from '@/lib/utils'

export interface Stat {
  label: string
  value: string | number
  color?: string
  icon?: LucideIcon
}

interface StatStripProps {
  stats: Stat[]
  loading?: boolean
}

export function StatStrip({ stats, loading }: StatStripProps) {
  if (loading) {
    return (
      <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="h-[4.5rem] animate-pulse bg-[#12121a] border border-[#2a2a3a]" />
        ))}
      </div>
    )
  }

  return (
    <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
      {stats.map(stat => {
        const Icon = stat.icon
        return (
          <div
            key={stat.label}
            className="border border-[#2a2a3a] bg-[#12121a] px-4 py-3 transition-all duration-200 hover:border-[#00ff88]/40 hover:shadow-[0_0_12px_rgba(0,255,136,0.06)] corner-deco"
          >
            <div className="flex items-center gap-2">
              {Icon && (
                <Icon
                  size={13}
                  className={cn('shrink-0', stat.color ?? 'text-[#00ff88]')}
                  strokeWidth={1.5}
                />
              )}
              <span
                className={cn(
                  'text-xl font-bold tabular-nums font-mono',
                  stat.color ?? 'text-[#e0e0e0]',
                )}
              >
                {typeof stat.value === 'number'
                  ? stat.value.toLocaleString()
                  : stat.value}
              </span>
            </div>
            <p className="mt-1 font-mono text-[10px] uppercase tracking-[0.12em] text-[#6b7280]">
              {stat.label}
            </p>
          </div>
        )
      })}
    </div>
  )
}
