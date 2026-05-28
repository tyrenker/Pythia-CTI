import { ChevronLeft, ChevronRight } from 'lucide-react'

interface ResultCountProps {
  page: number
  pageSize: number
  total?: number
  pageItemCount: number
  onPrev: () => void
  onNext: () => void
  noun?: string
}

export function ResultCount({
  page,
  pageSize,
  total,
  pageItemCount,
  onPrev,
  onNext,
  noun = 'results',
}: ResultCountProps) {
  const start = pageItemCount === 0 ? 0 : page * pageSize + 1
  const end = page * pageSize + pageItemCount

  let label: string
  if (pageItemCount === 0) {
    label = `No ${noun}`
  } else if (total != null) {
    label = `Showing ${start.toLocaleString()}–${end.toLocaleString()} of ${total.toLocaleString()} ${noun} · Page ${page + 1}`
  } else {
    label = `Page ${page + 1}`
  }

  return (
    <div className="mt-4 flex items-center justify-between text-xs text-text-muted">
      <span>{label}</span>
      <div className="flex items-center gap-3">
        <button
          onClick={onPrev}
          disabled={page === 0}
          className="flex items-center gap-1 transition-colors hover:text-text-primary disabled:opacity-40"
        >
          <ChevronLeft size={14} /> Prev
        </button>
        <button
          onClick={onNext}
          disabled={pageItemCount < pageSize}
          className="flex items-center gap-1 transition-colors hover:text-text-primary disabled:opacity-40"
        >
          Next <ChevronRight size={14} />
        </button>
      </div>
    </div>
  )
}
