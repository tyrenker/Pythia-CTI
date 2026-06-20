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
        'inline-flex items-center px-1.5 py-0.5 text-[10px] font-mono font-medium transition-all duration-150 rounded-none',
        isAtlas
          ? 'border border-[#00ff88] text-[#00ff88] bg-[#00ff88]/10 hover:bg-[#00ff88]/20 hover:shadow-[0_0_8px_rgba(0,212,255,0.3)]'
          : 'border border-[#ff00ff] text-[#ff00ff] bg-[#ff00ff]/10 hover:bg-[#ff00ff]/20 hover:shadow-[0_0_8px_rgba(255,0,255,0.3)]',
        className,
      )}
    >
      {id}
    </button>
  )
}
