import { useState } from 'react'
import { Sidebar } from './TopNav'

interface Props {
  children: React.ReactNode
}

export function Shell({ children }: Props) {
  const [collapsed, setCollapsed] = useState(
    () => localStorage.getItem('sidebar-collapsed') === 'true',
  )

  function handleToggle() {
    setCollapsed((prev) => {
      const next = !prev
      localStorage.setItem('sidebar-collapsed', String(next))
      return next
    })
  }

  return (
    <div className="flex min-h-screen bg-bg-base">
      <Sidebar collapsed={collapsed} onToggle={handleToggle} />
      <main
        className="flex-1 transition-all duration-200"
        style={{ marginLeft: collapsed ? 60 : 220 }}
      >
        <div className="mx-auto max-w-screen-xl px-4 py-6">
          {children}
        </div>
      </main>
    </div>
  )
}
