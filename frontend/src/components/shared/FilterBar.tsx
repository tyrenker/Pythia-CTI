import type { ReactNode } from 'react'

interface FilterBarProps {
  children: ReactNode
  actions?: ReactNode
  activeCount?: number
  onClearFilters?: () => void
}

export function FilterBar({
  children,
  actions,
  activeCount,
  onClearFilters,
}: FilterBarProps) {
  const hasActive = activeCount != null && activeCount > 0

  return (
    <div className="mb-6 border border-[#2a2a3a] bg-[#0a0a0f] px-4 py-3 transition-colors">
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex flex-1 flex-wrap items-center gap-3">{children}</div>
        <div className="flex items-center gap-3">
          {actions}
          {hasActive && onClearFilters && (
            <button
              onClick={onClearFilters}
              className="font-mono text-[10px] uppercase tracking-wider text-[#6b7280] transition-colors hover:text-[#ff3366]"
            >
              [clear]
            </button>
          )}
        </div>
      </div>
      {hasActive && (
        <div className="mt-2 flex items-center gap-2">
          <span className="font-mono text-[10px] text-[#6b7280]">active filters:</span>
          <span className="inline-flex h-4 min-w-[1rem] items-center justify-center bg-[#00ff88] px-1 font-mono text-[9px] font-bold text-[#0a0a0f]">
            {activeCount}
          </span>
        </div>
      )}
    </div>
  )
}
