import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'
import type { ThreatSummary, ThreatDetail } from '@/types/api'

interface ListThreatsParams {
  tlp?: string
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

export function useThreats(params: ListThreatsParams = {}) {
  const qs = buildQs({ ...params, limit: params.limit ?? 50 })
  return useQuery({
    queryKey: ['threats', qs],
    queryFn: () => apiFetch<ThreatSummary[]>(`/threats${qs}`),
  })
}

export function useThreat(id: string) {
  return useQuery({
    queryKey: ['threat', id],
    queryFn: () => apiFetch<ThreatDetail>(`/threats/${id}`),
    enabled: !!id,
  })
}
