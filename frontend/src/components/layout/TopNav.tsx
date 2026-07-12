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
  Target,
  Globe,
  Network,
  Grid3x3,
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
  { to: '/hunt', label: 'Hunt', icon: Target },
  { to: '/rules', label: 'Rules', icon: Code2 },
  { to: '/malware', label: 'Malware', icon: Bug },
  { to: '/ai-threats', label: 'AI Threats', icon: Bot },
  { to: '/analytics', label: 'Analytics', icon: BarChart3 },
  { to: '/graph', label: 'Threat Graph', icon: Network },
  { to: '/heatmap', label: 'MITRE Heatmap', icon: Grid3x3 },
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
          'flex items-center gap-2.5 px-3 py-2 font-mono text-xs font-medium tracking-wide transition-all duration-150',
          'text-[#b0b0c8] hover:text-[#e0e0e0] hover:bg-[#00ff88]/[0.04]',
          isActive && [
            'border-l-2 border-[#00ff88] text-[#00ff88] bg-[#00ff88]/[0.06] pl-[10px]',
            '[text-shadow:0_0_8px_rgba(0,255,136,0.4)]',
          ],
          collapsed && 'justify-center px-2',
        )
      }
    >
      <Icon size={14} className="shrink-0" strokeWidth={1.5} />
      {!collapsed && <span className="uppercase tracking-[0.08em] text-[10px]">{label}</span>}
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
        <span className="px-3 pb-1 pt-3 font-mono text-[9px] uppercase tracking-[0.2em] text-[#6b7280]/90 select-none">
          {'// '}{label}
        </span>
      )}
      {collapsed && <div className="my-1 border-t border-[#2a2a3a]" />}
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
          'fixed top-0 left-0 bottom-0 z-30 flex flex-col transition-all duration-200',
          'bg-[#0a0a0f] border-r border-[#2a2a3a]',
          'shadow-[1px_0_0_0_rgba(0,255,136,0.06),2px_0_8px_rgba(0,255,136,0.03)]',
          collapsed ? 'w-[60px]' : 'w-[220px]',
        )}
      >
        {/* Logo + collapse toggle */}
        <div className="flex h-14 shrink-0 items-center justify-between px-3 border-b border-[#2a2a3a]">
          {!collapsed && (
            <NavLink
              to="/"
              className="flex items-center gap-1.5 select-none group"
            >
              <span className="font-mono text-[#00ff88] text-xs opacity-60 group-hover:opacity-100 transition-opacity">{'>'}</span>
              <span className="font-display text-sm font-bold uppercase tracking-[0.2em] text-[#00ff88] [text-shadow:0_0_10px_rgba(0,255,136,0.4)] glitch-text">
                PYTHIA
              </span>
              <span className="font-mono text-[10px] text-[#00ff88]/40 animate-blink ml-0.5">_</span>
            </NavLink>
          )}
          {collapsed && (
            <NavLink to="/" className="mx-auto select-none">
              <span className="font-display text-sm font-bold text-[#00ff88] [text-shadow:0_0_10px_rgba(0,255,136,0.5)]">P</span>
            </NavLink>
          )}
          <button
            onClick={onToggle}
            className={cn(
              'rounded-none p-1.5 font-mono text-[#9ca3af] hover:text-[#00ff88] transition-colors border border-transparent hover:border-[#00ff88]/30',
              collapsed ? 'mx-auto' : '',
            )}
            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {collapsed
              ? <ChevronRight size={14} strokeWidth={1.5} />
              : <ChevronLeft size={14} strokeWidth={1.5} />
            }
          </button>
        </div>

        {/* Nav sections */}
        <nav className="flex-1 overflow-y-auto overflow-x-hidden py-2">
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
        <div className="shrink-0 border-t border-[#2a2a3a] px-2 py-3 flex flex-col gap-1.5">
          <button
            onClick={() => setIngestOpen(true)}
            title={collapsed ? 'Analyze Intel' : undefined}
            className={cn(
              'flex items-center gap-2 bg-[#00ff88] px-3 py-2 font-mono text-[10px] font-bold uppercase tracking-wider text-[#0a0a0f]',
              'transition-all duration-150 hover:shadow-[0_0_15px_rgba(0,255,136,0.5)] active:scale-[0.98]',
              'cyber-chamfer-sm',
              collapsed ? 'justify-center px-2' : 'w-full',
            )}
          >
            <Zap size={12} className="shrink-0" strokeWidth={2} />
            {!collapsed && <span>Analyze Intel</span>}
          </button>
          <button
            onClick={() => setSettingsOpen(true)}
            title={collapsed ? 'Settings' : undefined}
            className={cn(
              'flex items-center gap-2 px-3 py-2 font-mono text-[10px] font-medium uppercase tracking-wider text-[#9ca3af]',
              'border border-transparent hover:border-[#2a2a3a] hover:text-[#e0e0e0] transition-all duration-150',
              collapsed ? 'justify-center px-2' : 'w-full',
            )}
          >
            <Settings size={12} className="shrink-0" strokeWidth={1.5} />
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
