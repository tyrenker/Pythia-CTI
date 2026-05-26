import { Link } from 'react-router-dom'
import { ChevronRight } from 'lucide-react'

interface Crumb {
  label: string
  to?: string
}

interface Props {
  crumbs: Crumb[]
}

export function Breadcrumb({ crumbs }: Props) {
  return (
    <nav className="flex items-center gap-1 text-xs text-text-muted mb-4">
      {crumbs.map((crumb, i) => (
        <span key={i} className="flex items-center gap-1">
          {i > 0 && <ChevronRight size={12} />}
          {crumb.to ? (
            <Link to={crumb.to} className="hover:text-text-primary transition-colors">
              {crumb.label}
            </Link>
          ) : (
            <span className="text-text-primary">{crumb.label}</span>
          )}
        </span>
      ))}
    </nav>
  )
}
