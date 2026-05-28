import { useState } from 'react'
import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard,
  Rss,
  Users,
  Crosshair,
  AlertCircle,
  Newspaper,
  Code2,
  Bug,
  Bot,
  BarChart3,
  Bookmark,
  BookOpen,
  Zap,
  Settings,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { IngestBar } from '../shared/IngestBar'
import { ApiKeyModal } from '../settings/ApiKeyModal'

const INTELLIGENCE_ITEMS = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, exact: true },
  { to: '/intel', label: 'Intel Feed', icon: Rss },
  { to: '/actors', label: 'Actors', icon: Users },
  { to: '/ttps', label: 'TTPs', icon: Crosshair },
  { to: '/iocs', label: 'IoCs', icon: AlertCircle },
  { to: '/articles', label: 'Articles', icon: Newspaper },
]

const DEFENSE_ITEMS = [
  { to: '/rules', label: 'Rules', icon: Code2 },
  { to: '/malware', label: 'Malware', icon: Bug },
  { to: '/ai-threats', label: 'AI Threats', icon: Bot },
  { to: '/analytics', label: 'Analytics', icon: BarChart3 },
  { to: '/watchlist', label: 'Watchlist', icon: Bookmark },
]

const REFERENCE_ITEMS = [
  { to: '/docs', label: 'Docs', icon: BookOpen },
]

interface NavItemProps {
  to: string
  label: string
  icon: React.ElementType
  exact?: boolean
  collapsed: boolean
}

function NavItem({ to, label, icon: Icon, exact, collapsed }: NavItemProps) {
  return (
    <NavLink
      to={to}
      end={exact}
      title={collapsed ? label : undefined}
      className={({ isActive }) =>
        cn(
          'flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-all duration-150',
          'text-white/70 hover:text-white hover:bg-bg-elevated',
          isActive && 'border-l-2 border-accent-bright bg-bg-elevated text-white rounded-l-none pl-[10px]',
          collapsed && 'justify-center px-2',
        )
      }
    >
      <Icon size={16} className="shrink-0" />
      {!collapsed && <span>{label}</span>}
    </NavLink>
  )
}

interface SectionProps {
  label: string
  collapsed: boolean
  children: React.ReactNode
}

function Section({ label, collapsed, children }: SectionProps) {
  return (
    <div className="flex flex-col gap-0.5">
      {!collapsed && (
        <span className="px-3 pb-1 pt-3 text-[10px] uppercase tracking-widest text-text-muted">
          {label}
        </span>
      )}
      {collapsed && <div className="my-1 border-t border-[#2a2a3e]" />}
      {children}
    </div>
  )
}

interface SidebarProps {
  collapsed: boolean
  onToggle: () => void
}

export function Sidebar({ collapsed, onToggle }: SidebarProps) {
  const [ingestOpen, setIngestOpen] = useState(false)
  const [settingsOpen, setSettingsOpen] = useState(false)

  return (
    <>
      <aside
        className={cn(
          'fixed top-0 left-0 bottom-0 z-30 flex flex-col border-r border-[#2a2a3e] bg-bg-surface transition-all duration-200',
          collapsed ? 'w-[60px]' : 'w-[220px]',
        )}
      >
        {/* Logo + collapse toggle */}
        <div className="flex h-14 shrink-0 items-center justify-between px-3 border-b border-[#2a2a3e]">
          {!collapsed && (
            <NavLink to="/" className="font-mono text-sm font-semibold text-accent-bright">
              ⬡ Pythia
            </NavLink>
          )}
          <button
            onClick={onToggle}
            className={cn(
              'rounded-md p-1.5 text-white/70 hover:text-white hover:bg-bg-elevated transition-colors',
              collapsed && 'mx-auto',
            )}
            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
          </button>
        </div>

        {/* Nav sections */}
        <nav className="flex-1 overflow-y-auto overflow-x-hidden px-2 py-2">
          <Section label="Intelligence" collapsed={collapsed}>
            {INTELLIGENCE_ITEMS.map((item) => (
              <NavItem key={item.to} {...item} collapsed={collapsed} />
            ))}
          </Section>
          <Section label="Defense" collapsed={collapsed}>
            {DEFENSE_ITEMS.map((item) => (
              <NavItem key={item.to} {...item} collapsed={collapsed} />
            ))}
          </Section>
          <Section label="Reference" collapsed={collapsed}>
            {REFERENCE_ITEMS.map((item) => (
              <NavItem key={item.to} {...item} collapsed={collapsed} />
            ))}
          </Section>
        </nav>

        {/* Bottom actions */}
        <div className="shrink-0 border-t border-[#2a2a3e] px-2 py-3 flex flex-col gap-1">
          <button
            onClick={() => setIngestOpen(true)}
            title={collapsed ? 'Analyze Intel' : undefined}
            className={cn(
              'flex items-center gap-2 rounded-lg bg-accent px-3 py-2 text-xs font-semibold text-white hover:opacity-90 transition-opacity',
              collapsed ? 'justify-center px-2' : 'w-full',
            )}
          >
            <Zap size={14} className="shrink-0" />
            {!collapsed && <span>Analyze Intel</span>}
          </button>
          <button
            onClick={() => setSettingsOpen(true)}
            title={collapsed ? 'Settings' : undefined}
            className={cn(
              'flex items-center gap-2 rounded-md px-3 py-2 text-xs font-medium text-white/70 hover:text-white hover:bg-bg-elevated transition-colors',
              collapsed ? 'justify-center px-2' : 'w-full',
            )}
          >
            <Settings size={14} className="shrink-0" />
            {!collapsed && <span>Settings</span>}
          </button>
        </div>
      </aside>

      <IngestBar open={ingestOpen} onClose={() => setIngestOpen(false)} />
      <ApiKeyModal open={settingsOpen} onClose={() => setSettingsOpen(false)} />
    </>
  )
}

// Keep TopNav export so any other importer doesn't break during transition
export { Sidebar as TopNav }
