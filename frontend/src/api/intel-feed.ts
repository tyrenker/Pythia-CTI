import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiPost } from './client'
import type { FeedSource, FeedArticle } from '@/types/api'

interface ListArticlesParams {
  source_id?: string
  status?: string
  limit?: number
  offset?: number
}

function buildQs(params: Record<string, string | number | undefined>): string {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== '') p.set(k, String(v))
  }
  const s = p.toString()
  return s ? `?${s}` : ''
}

export function useFeedSources(activeOnly = false) {
  return useQuery({
    queryKey: ['feed-sources', activeOnly],
    queryFn: () =>
      apiFetch<FeedSource[]>(`/intel-feed/sources${activeOnly ? '?active_only=true' : ''}`),
    staleTime: 60_000,
  })
}

export function useFeedArticles(params: ListArticlesParams = {}) {
  const qs = buildQs({ ...params, limit: params.limit ?? 50 })
  return useQuery({
    queryKey: ['feed-articles', qs],
    queryFn: () => apiFetch<FeedArticle[]>(`/intel-feed/articles${qs}`),
    refetchInterval: (query) => {
      const data = query.state.data
      if (data?.some((a: FeedArticle) => a.status === 'ingesting')) return 5_000
      return 30_000
    },
  })
}

export function useFeedArticle(id: string) {
  return useQuery({
    queryKey: ['feed-article', id],
    queryFn: () => apiFetch<FeedArticle>(`/intel-feed/articles/${id}`),
    enabled: !!id,
  })
}

export function useTriggerFetch() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (sourceId?: string) => {
      const qs = sourceId ? `?source_id=${sourceId}` : ''
      return apiPost<{ status: string; new_articles: number }>(
        `/intel-feed/fetch${qs}`,
        {},
      )
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['feed-articles'] })
      qc.invalidateQueries({ queryKey: ['feed-sources'] })
    },
  })
}

export function useIngestArticle() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (articleId: string) =>
      apiPost<{ status: string; report_id: string }>(
        `/intel-feed/articles/${articleId}/ingest`,
        {},
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['feed-articles'] })
      qc.invalidateQueries({ queryKey: ['threats'] })
    },
  })
}

export function useToggleSource() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, active }: { id: string; active: boolean }) =>
      apiFetch<FeedSource>(`/intel-feed/sources/${id}`, {
        method: 'PATCH',
        body: JSON.stringify({ active }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['feed-sources'] }),
  })
}
