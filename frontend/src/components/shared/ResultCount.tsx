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
    label = `${start.toLocaleString()}–${end.toLocaleString()} of ${total.toLocaleString()} ${noun} · page ${page + 1}`
  } else {
    label = `page ${page + 1}`
  }

  return (
    <div className="mt-4 flex items-center justify-between font-mono text-[10px] uppercase tracking-[0.1em] text-[#6b7280]">
      <span>{label}</span>
      <div className="flex items-center gap-3">
        <button
          onClick={onPrev}
          disabled={page === 0}
          className="flex items-center gap-1 transition-colors hover:text-[#00ff88] disabled:opacity-30"
        >
          <ChevronLeft size={12} strokeWidth={1.5} /> PREV
        </button>
        <button
          onClick={onNext}
          disabled={pageItemCount < pageSize}
          className="flex items-center gap-1 transition-colors hover:text-[#00ff88] disabled:opacity-30"
        >
          NEXT <ChevronRight size={12} strokeWidth={1.5} />
        </button>
      </div>
    </div>
  )
}
