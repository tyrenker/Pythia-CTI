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
          <div key={i} className="h-[4.5rem] animate-pulse rounded-xl bg-bg-surface" />
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
            className="rounded-xl border border-[#2a2a3e] bg-bg-surface px-4 py-3"
          >
            <div className="flex items-center gap-2">
              {Icon && (
                <Icon size={14} className={cn('shrink-0', stat.color ?? 'text-text-muted')} />
              )}
              <span
                className={cn(
                  'text-xl font-bold tabular-nums',
                  stat.color ?? 'text-text-primary',
                )}
              >
                {typeof stat.value === 'number'
                  ? stat.value.toLocaleString()
                  : stat.value}
              </span>
            </div>
            <p className="mt-0.5 text-xs text-text-muted">{stat.label}</p>
          </div>
        )
      })}
    </div>
  )
}
