import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'
import type { SyncStatusItem } from '@/types/api'

interface SyncStatusResponse {
  sources: Record<string, { last_run: string | null; status: string }>
  scheduler_enabled: boolean
}

export function useSyncStatus() {
  return useQuery({
    queryKey: ['sync-status'],
    queryFn: async () => {
      const resp = await apiFetch<SyncStatusResponse>('/sync/status')
      const items: SyncStatusItem[] = Object.entries(resp.sources).map(([source, v]) => ({
        source,
        last_run: v.last_run,
        status: v.status,
      }))
      return items
    },
  })
}
