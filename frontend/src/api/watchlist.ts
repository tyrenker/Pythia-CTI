import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiPost, apiDelete } from './client'
import type { WatchlistSubscription } from '@/types/api'

export function useWatchlist() {
  return useQuery({
    queryKey: ['watchlist'],
    queryFn: () => apiFetch<WatchlistSubscription[]>('/watchlist'),
  })
}

interface CreateSubParams {
  name: string
  webhook_url: string
  webhook_type: string
  filter_actor?: string
  filter_ttp?: string
  filter_sector?: string
}

export function useCreateSubscription() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (params: CreateSubParams) => apiPost<WatchlistSubscription>('/watchlist', params),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['watchlist'] }),
  })
}

export function useDeleteSubscription() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => apiDelete(`/watchlist/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['watchlist'] }),
  })
}

export function useTestSubscription() {
  return useMutation({
    mutationFn: (id: string) => apiPost<{ status: string }>('/watchlist/test', { id }),
  })
}
