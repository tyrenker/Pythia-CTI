import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'
import type { ActorSummary, ActorDetail, KillChainView, DiamondModel } from '@/types/api'

interface ListActorsParams {
  name?: string
  country?: string
  sponsor_type?: string
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

export function useActors(params: ListActorsParams = {}) {
  const qs = buildQs({ ...params, limit: params.limit ?? 50 })
  return useQuery({
    queryKey: ['actors', qs],
    queryFn: () => apiFetch<ActorSummary[]>(`/actors${qs}`),
  })
}

export function useActor(id: string) {
  return useQuery({
    queryKey: ['actor', id],
    queryFn: () => apiFetch<ActorDetail>(`/actors/${id}`),
    enabled: !!id,
  })
}

export function useActorKillChain(id: string) {
  return useQuery({
    queryKey: ['actor-killchain', id],
    queryFn: () => apiFetch<KillChainView>(`/actors/${id}/killchain`),
    enabled: !!id,
  })
}

export function useActorDiamond(id: string) {
  return useQuery({
    queryKey: ['actor-diamond', id],
    queryFn: () => apiFetch<DiamondModel>(`/actors/${id}/diamond`),
    enabled: !!id,
  })
}

export function useActorStix(id: string, enabled: boolean) {
  return useQuery({
    queryKey: ['actor-stix', id],
    queryFn: () => apiFetch<Record<string, unknown>>(`/actors/${id}/stix`),
    enabled: !!id && enabled,
  })
}
