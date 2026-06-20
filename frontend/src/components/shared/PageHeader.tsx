import type { ReactNode } from 'react'

interface PageHeaderProps {
  title: string
  description?: string
  actions?: ReactNode
}

export function PageHeader({ title, description, actions }: PageHeaderProps) {
  return (
    <div className="mb-6 flex items-start justify-between gap-4">
      <div>
        <div className="flex items-center gap-2 mb-0.5">
          <span className="font-mono text-xs text-[#00ff88] select-none">{'// '}</span>
          <h1 className="font-display text-xl font-bold uppercase tracking-widest text-[#e0e0e0]">
            {title}
          </h1>
        </div>
        {description && (
          <p className="mt-1 font-mono text-xs text-[#6b7280] tracking-wide">{description}</p>
        )}
      </div>
      {actions && (
        <div className="flex shrink-0 items-center gap-2">{actions}</div>
      )}
    </div>
  )
}
