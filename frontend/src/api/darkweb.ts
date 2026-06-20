import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiPost } from './client'

export interface DarkWebSource {
  id: string
  name: string
  category: string
  active: boolean
  auto_ingest: boolean
  poll_interval_h: number
  last_polled_at: string | null
  last_error: string | null
  post_count: number
  description: string | null
  onion_url: string
  created_at: string
}

export interface DarkWebPost {
  id: string
  source_id: string
  source_name: string | null
  category: string | null
  title: string | null
  published_at: string | null
  status: string
  victim_org: string | null
  victim_sector: string | null
  victim_country: string | null
  threat_actor: string | null
  tlp: string
  admiralty_code: string
  report_id: string | null
  created_at: string
  error: string | null
}

export interface DarkWebVictim {
  victim_org: string
  victim_sector: string | null
  victim_country: string | null
  threat_actor: string | null
  first_seen: string
  post_id: string
}

export interface DarkWebStats {
  active_sources: number
  total_sources: number
  posts_today: number
  victims_30d: number
  pending_ingest: number
  top_actor: string | null
  top_actor_count: number
  by_status: Record<string, number>
  by_category: Record<string, number>
}

function qs(params: Record<string, string | number | boolean | undefined>): string {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== '' && v !== null) p.set(k, String(v))
  }
  const s = p.toString()
  return s ? `?${s}` : ''
}

export function useDarkWebSources(category?: string, activeOnly = false) {
  return useQuery({
    queryKey: ['dw-sources', category, activeOnly],
    queryFn: () =>
      apiFetch<DarkWebSource[]>(`/dark-web/sources${qs({ category, active_only: activeOnly || undefined })}`),
    staleTime: 60_000,
  })
}

export function useDarkWebPosts(params: {
  source_id?: string
  status?: string
  category?: string
  victim_sector?: string
  threat_actor?: string
  limit?: number
  offset?: number
} = {}) {
  const q = qs({ ...params, limit: params.limit ?? 50 })
  return useQuery({
    queryKey: ['dw-posts', q],
    queryFn: () => apiFetch<DarkWebPost[]>(`/dark-web/posts${q}`),
    refetchInterval: 60_000,
  })
}

export function useDarkWebPost(id: string) {
  return useQuery({
    queryKey: ['dw-post', id],
    queryFn: () => apiFetch<DarkWebPost>(`/dark-web/posts/${id}`),
    enabled: !!id,
  })
}

export function useDarkWebVictims(params: {
  sector?: string
  country?: string
  actor?: string
  limit?: number
} = {}) {
  const q = qs({ ...params, limit: params.limit ?? 100 })
  return useQuery({
    queryKey: ['dw-victims', q],
    queryFn: () => apiFetch<DarkWebVictim[]>(`/dark-web/victims${q}`),
    staleTime: 120_000,
  })
}

export function useDarkWebStats() {
  return useQuery({
    queryKey: ['dw-stats'],
    queryFn: () => apiFetch<DarkWebStats>('/dark-web/stats'),
    refetchInterval: 60_000,
  })
}

export function usePullDarkWeb() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (sourceId?: string) => {
      const q = sourceId ? `?source_id=${sourceId}` : ''
      return apiPost<{ status: string; new_posts: number }>(`/dark-web/pull${q}`, {})
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['dw-posts'] })
      qc.invalidateQueries({ queryKey: ['dw-sources'] })
      qc.invalidateQueries({ queryKey: ['dw-stats'] })
    },
  })
}

export function useFetchDarkWebPost() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (postId: string) =>
      apiPost<{ status: string; post_id: string }>(`/dark-web/posts/${postId}/fetch`, {}),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['dw-posts'] }),
  })
}

export function useIngestDarkWebPost() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (postId: string) =>
      apiPost<{ status: string; report_id: string }>(`/dark-web/posts/${postId}/ingest`, {}),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['dw-posts'] })
      qc.invalidateQueries({ queryKey: ['dw-victims'] })
      qc.invalidateQueries({ queryKey: ['dw-stats'] })
      qc.invalidateQueries({ queryKey: ['threats'] })
    },
  })
}

export function useToggleDarkWebSource() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, active, auto_ingest }: { id: string; active?: boolean; auto_ingest?: boolean }) =>
      apiFetch<DarkWebSource>(`/dark-web/sources/${id}`, {
        method: 'PATCH',
        body: JSON.stringify({ active, auto_ingest }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['dw-sources'] }),
  })
}
