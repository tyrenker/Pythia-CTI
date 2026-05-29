import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiPost, apiDelete } from './client'
import type { DetectionRule } from '@/types/api'

interface ListRulesParams {
  rule_type?: string
  severity?: string
  technique_id?: string
  source?: string
  limit?: number
  offset?: number
}

export interface CreateRuleParams {
  rule_type: string
  title: string
  content: string
  severity?: string
  technique_ids?: string[]
  actor_ids?: string[]
  status?: string
  source_url?: string
}

function buildQs(params: Record<string, string | number | undefined>): string {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== '') p.set(k, String(v))
  }
  const s = p.toString()
  return s ? `?${s}` : ''
}

export function useRules(params: ListRulesParams = {}) {
  const qs = buildQs({ ...params, limit: params.limit ?? 50 })
  return useQuery({
    queryKey: ['rules', qs],
    queryFn: () => apiFetch<DetectionRule[]>(`/rules${qs}`),
  })
}

export function useRulesCount(params: Omit<ListRulesParams, 'limit' | 'offset'> = {}) {
  const qs = buildQs(params)
  return useQuery({
    queryKey: ['rules', 'count', qs],
    queryFn: () => apiFetch<{ total: number }>(`/rules/count${qs}`),
  })
}

export function useRule(type: string, id: string) {
  return useQuery({
    queryKey: ['rule', type, id],
    queryFn: () => apiFetch<DetectionRule>(`/rules/${type}/${id}`),
    enabled: !!id && !!type,
  })
}

export function useCreateRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (params: CreateRuleParams) => apiPost<DetectionRule>('/rules', params),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
  })
}

export interface UpdateRuleParams {
  title?: string
  content?: string
  severity?: string
  technique_ids?: string[]
  actor_ids?: string[]
  status?: string
  source_url?: string
}

export function useUpdateRule(id: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (params: UpdateRuleParams) =>
      apiFetch<DetectionRule>(`/rules/${id}`, {
        method: 'PATCH',
        body: JSON.stringify(params),
      }),
    onSuccess: (updated) => {
      qc.setQueryData(['rule', updated.rule_type, id], updated)
      qc.invalidateQueries({ queryKey: ['rules'] })
    },
  })
}

export function useDeleteRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => apiDelete(`/rules/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
  })
}
