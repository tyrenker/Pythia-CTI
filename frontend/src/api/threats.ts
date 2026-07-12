import { useQuery, useMutation } from '@tanstack/react-query'
import { apiFetch, apiPost } from './client'
import type { ThreatSummary, ThreatDetail, SuggestedRulesResponse } from '@/types/api'

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

export function useSuggestRules() {
  return useMutation({
    mutationFn: (threatId: string) =>
      apiPost<SuggestedRulesResponse>(`/threats/${threatId}/suggest-rules`, {}),
  })
}

export function useSaveRule() {
  return useMutation({
    mutationFn: (body: {
      rule_type: string
      title: string
      content: string
      severity?: string
      technique_ids?: string[]
      source_url?: string
    }) => apiPost<{ id: string }>('/rules', body),
  })
}

