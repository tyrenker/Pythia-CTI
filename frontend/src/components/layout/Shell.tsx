import { TopNav } from './TopNav'

interface Props {
  children: React.ReactNode
}

export function Shell({ children }: Props) {
  return (
    <div className="min-h-screen bg-bg-base">
      <TopNav />
      <main className="pt-14">
        <div className="mx-auto max-w-screen-xl px-4 py-6">
          {children}
        </div>
      </main>
    </div>
  )
}
