import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'
import type { IocSummary, IocDetail } from '@/types/api'

interface ListIocsParams {
  type?: string       // filter by IoC type — backend param name is "type"
  pyramid_tier?: string
  tlp?: string
  actor_id?: string
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

export function useIocs(params: ListIocsParams = {}) {
  const qs = buildQs({ ...params, limit: params.limit ?? 100 })
  return useQuery({
    queryKey: ['iocs', qs],
    queryFn: () => apiFetch<IocSummary[]>(`/iocs${qs}`),
  })
}

export function useIoc(id: string) {
  return useQuery({
    queryKey: ['ioc', id],
    queryFn: () => apiFetch<IocDetail>(`/iocs/${id}`),
    enabled: !!id,
  })
}
