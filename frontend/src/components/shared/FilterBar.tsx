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
    <div className="mb-6 rounded-xl border border-[#2a2a3e] bg-bg-elevated px-4 py-3">
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex flex-1 flex-wrap items-center gap-3">{children}</div>
        <div className="flex items-center gap-3">
          {actions}
          {hasActive && onClearFilters && (
            <button
              onClick={onClearFilters}
              className="text-xs text-text-muted transition-colors hover:text-accent-bright"
            >
              Clear filters
            </button>
          )}
        </div>
      </div>
      {hasActive && (
        <div className="mt-2 flex items-center gap-1.5">
          <span className="text-xs text-text-muted">Active filters:</span>
          <span className="inline-flex h-4 min-w-[1rem] items-center justify-center rounded-full bg-accent px-1 text-[10px] font-bold text-white">
            {activeCount}
          </span>
        </div>
      )}
    </div>
  )
}
