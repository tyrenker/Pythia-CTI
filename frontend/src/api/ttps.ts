import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'
import type { ActorRef, AttckTechnique, HuntQueriesResponse } from '@/types/api'

interface ListTTPsParams {
  tactic?: string
  domain?: string
  search?: string
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

export function useTTPs(params: ListTTPsParams = {}) {
  const qs = buildQs({ ...params, limit: params.limit ?? 50 })
  return useQuery({
    queryKey: ['ttps', qs],
    queryFn: () => apiFetch<AttckTechnique[]>(`/ttps${qs}`),
  })
}

export function useTTP(id: string) {
  return useQuery({
    queryKey: ['ttp', id],
    queryFn: () => apiFetch<AttckTechnique>(`/ttps/${id}`),
    enabled: !!id,
  })
}

export function useHuntQueries(id: string) {
  return useQuery({
    queryKey: ['hunt-queries', id],
    queryFn: () => apiFetch<HuntQueriesResponse>(`/ttps/${id}/hunt-queries`),
    enabled: !!id,
  })
}

export function useActorsByTTP(id: string) {
  return useQuery({
    queryKey: ['ttp-actors', id],
    queryFn: () => apiFetch<ActorRef[]>(`/ttps/${id}/actors`),
    enabled: !!id,
  })
}
