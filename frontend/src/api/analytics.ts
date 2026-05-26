import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'
import type { CoverageReport, SectorReport } from '@/types/api'

export function useCoverage(limit = 20) {
  return useQuery({
    queryKey: ['coverage', limit],
    queryFn: () => apiFetch<CoverageReport>(`/analytics/coverage?limit=${limit}`),
  })
}

export function useSectors(sponsorType?: string, country?: string) {
  const p = new URLSearchParams()
  if (sponsorType) p.set('sponsor_type', sponsorType)
  if (country) p.set('country', country)
  const qs = p.toString() ? `?${p}` : ''
  return useQuery({
    queryKey: ['sectors', sponsorType, country],
    queryFn: () => apiFetch<SectorReport>(`/analytics/sectors${qs}`),
  })
}
