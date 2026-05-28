import { useState } from 'react'
import { NavLink } from 'react-router-dom'
import { Settings, Zap } from 'lucide-react'
import { cn } from '@/lib/utils'
import { IngestBar } from '../shared/IngestBar'
import { ApiKeyModal } from '../settings/ApiKeyModal'

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', exact: true },
  { to: '/intel', label: 'Intel' },
  { to: '/actors', label: 'Actors' },
  { to: '/ttps', label: 'TTPs' },
  { to: '/iocs', label: 'IoCs' },
  { to: '/rules', label: 'Rules' },
  { to: '/malware', label: 'Malware' },
  { to: '/ai-threats', label: 'AI Threats' },
  { to: '/analytics', label: 'Analytics' },
  { to: '/watchlist', label: 'Watchlist' },
  { to: '/articles', label: 'Articles' },
  { to: '/docs', label: 'Docs' },
]

export function TopNav() {
  const [ingestOpen, setIngestOpen] = useState(false)
  const [settingsOpen, setSettingsOpen] = useState(false)

  return (
    <>
      <header className="fixed top-0 left-0 right-0 z-30 h-14 border-b border-[#2a2a3e] bg-bg-surface/95 backdrop-blur">
        <div className="flex h-full items-center gap-6 px-4">
          <NavLink to="/" className="shrink-0 font-mono text-sm font-semibold text-accent-bright">
            ⬡ Pythia
          </NavLink>

          <nav className="hidden md:flex items-center gap-1 overflow-x-auto">
            {NAV_ITEMS.map(({ to, label, exact }) => (
              <NavLink
                key={to}
                to={to}
                end={exact}
                className={({ isActive }) =>
                  cn(
                    'shrink-0 rounded px-2.5 py-1.5 text-xs font-medium transition-colors',
                    isActive
                      ? 'border-b-2 border-accent-bright text-text-primary rounded-b-none pb-[5px]'
                      : 'text-text-muted hover:text-text-primary',
                  )
                }
              >
                {label}
              </NavLink>
            ))}
          </nav>

          <div className="ml-auto flex items-center gap-2">
            <button
              onClick={() => setIngestOpen(true)}
              className="flex items-center gap-2 rounded-lg bg-accent px-3 py-1.5 text-xs font-semibold text-white hover:opacity-90 transition-opacity"
            >
              <Zap size={12} />
              <span className="hidden sm:inline">Analyze Intel</span>
            </button>
            <button
              onClick={() => setSettingsOpen(true)}
              className="rounded-lg p-1.5 text-text-muted hover:text-text-primary transition-colors"
              title="Settings"
            >
              <Settings size={16} />
            </button>
          </div>
        </div>
      </header>

      <IngestBar open={ingestOpen} onClose={() => setIngestOpen(false)} />
      <ApiKeyModal open={settingsOpen} onClose={() => setSettingsOpen(false)} />
    </>
  )
}
