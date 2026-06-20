import { cn } from '@/lib/utils'

interface Props {
  value: string
  onChange: (value: string) => void
  placeholder?: string
  className?: string
}

export function SearchInput({ value, onChange, placeholder = 'Search...', className }: Props) {
  return (
    <div className={cn('relative', className)}>
      <span className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 font-mono text-[10px] text-[#00ff88]/50 select-none">
        {'>'}
      </span>
      <input
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full border border-[#2a2a3a] bg-[#12121a] pl-6 pr-3 py-1.5 font-mono text-[10px] text-[#e0e0e0] placeholder-[#6b7280]/60 focus:outline-none focus:border-[#00ff88] transition-colors"
      />
    </div>
  )
}
