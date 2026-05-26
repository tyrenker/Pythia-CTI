import { useNavigate } from 'react-router-dom'
import { cn } from '@/lib/utils'

interface Props {
  id: string
  className?: string
}

export function TechniqueTag({ id, className }: Props) {
  const navigate = useNavigate()
  const isAtlas = id.startsWith('AML.')
  return (
    <button
      onClick={() => navigate(`/ttps/${id}`)}
      className={cn(
        'inline-flex items-center rounded px-1.5 py-0.5 text-xs font-mono font-medium transition-opacity hover:opacity-80',
        isAtlas
          ? 'bg-cyan-900 text-cyan-300'
          : 'bg-purple-900 text-purple-300',
        className,
      )}
    >
      {id}
    </button>
  )
}
