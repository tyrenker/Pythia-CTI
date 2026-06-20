import { Link } from 'react-router-dom'

interface Crumb {
  label: string
  to?: string
}

interface Props {
  crumbs: Crumb[]
}

export function Breadcrumb({ crumbs }: Props) {
  return (
    <nav className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.1em] text-[#6b7280] mb-5">
      {crumbs.map((crumb, i) => (
        <span key={i} className="flex items-center gap-1.5">
          {i > 0 && <span className="text-[#00ff88]/30">/</span>}
          {crumb.to ? (
            <Link to={crumb.to} className="transition-colors hover:text-[#00ff88]">
              {crumb.label}
            </Link>
          ) : (
            <span className="text-[#e0e0e0]">{crumb.label}</span>
          )}
        </span>
      ))}
    </nav>
  )
}
