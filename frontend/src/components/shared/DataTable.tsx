import { useState } from 'react'
import { ChevronUp, ChevronDown } from 'lucide-react'
import { cn } from '@/lib/utils'
import { EmptyState } from './EmptyState'

export interface Column<T> {
  key: string
  header: string
  sortable?: boolean
  className?: string
  render: (row: T) => React.ReactNode
}

interface Props<T> {
  columns: Column<T>[]
  data: T[]
  loading?: boolean
  emptyTitle?: string
  emptyDescription?: string
  onRowClick?: (row: T) => void
  keyFn: (row: T) => string
}

export function DataTable<T>({
  columns,
  data,
  loading,
  emptyTitle = 'No results',
  emptyDescription,
  onRowClick,
  keyFn,
}: Props<T>) {
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc')

  function toggleSort(key: string) {
    if (sortKey === key) {
      setSortDir(d => (d === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortKey(key)
      setSortDir('asc')
    }
  }

  const sorted = [...data].sort((a, b) => {
    if (!sortKey) return 0
    const av = String((a as Record<string, unknown>)[sortKey] ?? '')
    const bv = String((b as Record<string, unknown>)[sortKey] ?? '')
    return sortDir === 'asc' ? av.localeCompare(bv, undefined, { numeric: true }) : bv.localeCompare(av, undefined, { numeric: true })
  })

  if (loading) {
    return (
      <div className="space-y-2 p-4">
        {Array.from({ length: 6 }).map((_, i) => (
          <div key={i} className="h-10 animate-pulse rounded bg-bg-elevated" />
        ))}
      </div>
    )
  }

  if (data.length === 0) {
    return <EmptyState title={emptyTitle} description={emptyDescription} />
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-[#2a2a3e]">
            {columns.map(col => (
              <th
                key={col.key}
                className={cn(
                  'h-10 px-3 text-left text-xs font-medium text-text-muted',
                  col.sortable && 'cursor-pointer select-none hover:text-text-primary',
                  col.className,
                )}
                onClick={() => col.sortable && toggleSort(col.key)}
              >
                <span className="inline-flex items-center gap-1">
                  {col.header}
                  {col.sortable && sortKey === col.key && (
                    sortDir === 'asc' ? <ChevronUp size={12} /> : <ChevronDown size={12} />
                  )}
                </span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map(row => (
            <tr
              key={keyFn(row)}
              className={cn(
                'border-b border-[#2a2a3e] transition-colors',
                onRowClick && 'cursor-pointer hover:bg-bg-elevated',
              )}
              onClick={() => onRowClick?.(row)}
            >
              {columns.map(col => (
                <td key={col.key} className={cn('h-10 px-3 text-xs', col.className)}>
                  {col.render(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
