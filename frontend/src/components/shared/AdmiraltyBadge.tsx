import { ADMIRALTY_SOURCE, ADMIRALTY_ACCURACY } from '@/lib/constants'

interface Props {
  code: string | null | undefined
}

export function AdmiraltyBadge({ code }: Props) {
  if (!code) return <span className="font-mono text-[#6b7280]">—</span>

  const source = code[0]?.toUpperCase() ?? ''
  const accuracy = code[1] ?? ''
  const tooltip = [
    ADMIRALTY_SOURCE[source] ? `Source: ${ADMIRALTY_SOURCE[source]}` : '',
    ADMIRALTY_ACCURACY[accuracy] ? `Info: ${ADMIRALTY_ACCURACY[accuracy]}` : '',
  ].filter(Boolean).join(' · ')

  return (
    <span
      title={tooltip}
      className="inline-flex items-center px-1.5 py-0.5 text-[10px] font-mono font-medium uppercase tracking-wider rounded-none border border-[#6b7280] text-[#9ca3af] bg-[#6b7280]/10 cursor-help"
    >
      {code.toUpperCase()}
    </span>
  )
}
