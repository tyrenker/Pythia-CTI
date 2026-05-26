import { cn } from '@/lib/utils'

interface Props {
  title: string
  description?: string
  className?: string
}

export function EmptyState({ title, description, className }: Props) {
  return (
    <div className={cn('flex flex-col items-center justify-center py-16 text-center', className)}>
      <div className="mb-3 text-4xl opacity-30">◎</div>
      <p className="text-sm font-medium text-text-primary">{title}</p>
      {description && <p className="mt-1 text-xs text-text-muted max-w-xs">{description}</p>}
    </div>
  )
}
