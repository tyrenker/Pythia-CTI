import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'
import type { OWASPItem, AIIncident, AtlasEntry, AIThreatsOverview } from '@/types/api'

export function useAIThreatsOverview() {
  return useQuery({
    queryKey: ['ai-threats-overview'],
    queryFn: () => apiFetch<AIThreatsOverview>('/ai-threats'),
  })
}

export function useOWASPItems() {
  return useQuery({
    queryKey: ['owasp-llm'],
    queryFn: () => apiFetch<OWASPItem[]>('/ai-threats/owasp-llm'),
  })
}

export function useAIIncidents() {
  return useQuery({
    queryKey: ['ai-incidents'],
    queryFn: () => apiFetch<AIIncident[]>('/ai-threats/incidents'),
  })
}

export function useAtlasTechniques() {
  return useQuery({
    queryKey: ['atlas'],
    queryFn: () => apiFetch<AtlasEntry[]>('/ai-threats/atlas'),
  })
}
