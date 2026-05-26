import { ADMIRALTY_SOURCE, ADMIRALTY_ACCURACY } from '@/lib/constants'

interface Props {
  code: string | null | undefined
}

export function AdmiraltyBadge({ code }: Props) {
  if (!code) return <span className="text-text-muted">—</span>

  const source = code[0]?.toUpperCase() ?? ''
  const accuracy = code[1] ?? ''
  const tooltip = [
    ADMIRALTY_SOURCE[source] ? `Source: ${ADMIRALTY_SOURCE[source]}` : '',
    ADMIRALTY_ACCURACY[accuracy] ? `Info: ${ADMIRALTY_ACCURACY[accuracy]}` : '',
  ].filter(Boolean).join(' · ')

  return (
    <span
      title={tooltip}
      className="inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium font-mono bg-zinc-800 text-zinc-300 cursor-help"
    >
      {code.toUpperCase()}
    </span>
  )
}
