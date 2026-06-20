import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiPost } from './client'

export interface SiemAlert {
  id: string
  siem_source: string
  external_alert_id: string | null
  rule_id: string | null
  campaign_id: string | null
  severity: string
  title: string
  attacker_ip: string | null
  mitre_techniques: string[]
  triage_status: string
  analyst_notes: string | null
  triaged_by: string | null
  triaged_at: string | null
  received_at: string
}

export interface SiemStatus {
  configured: boolean
  siem_type: string
  connected?: boolean
}

export interface AlertStats {
  by_severity: Record<string, number>
  by_triage: Record<string, number>
  total: number
}

export interface RuleDeployResult {
  rule_id: string
  siem_rule_id: string
  deployed_at: string
}

function qs(params: Record<string, string | number | boolean | undefined>): string {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== '' && v !== null) p.set(k, String(v))
  }
  const s = p.toString()
  return s ? `?${s}` : ''
}

export function useSiemStatus() {
  return useQuery({
    queryKey: ['siem-status'],
    queryFn: () => apiFetch<SiemStatus>('/siem/status'),
  })
}

export function useSiemAlerts(params: Record<string, string | number | undefined> = {}) {
  const q = qs(params)
  return useQuery({
    queryKey: ['siem-alerts', q],
    queryFn: () => apiFetch<SiemAlert[]>(`/siem/alerts${q}`),
  })
}

export function useSiemAlert(id: string) {
  return useQuery({
    queryKey: ['siem-alert', id],
    queryFn: () => apiFetch<SiemAlert>(`/siem/alerts/${id}`),
    enabled: !!id,
  })
}

export function useAlertStats() {
  return useQuery({
    queryKey: ['siem-alert-stats'],
    queryFn: () => apiFetch<AlertStats>('/siem/alerts/stats'),
    refetchInterval: 30_000,
  })
}

export function useDeployRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (ruleId: string) => apiPost<RuleDeployResult>(`/siem/rules/deploy/${ruleId}`, {}),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
  })
}

export function useDeployAllRules() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => apiPost<RuleDeployResult[]>('/siem/rules/deploy-all', {}),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
  })
}

export function useTriageAlert() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, triage_status, analyst_notes }: { id: string; triage_status: string; analyst_notes?: string }) =>
      apiFetch<SiemAlert>(`/siem/alerts/${id}/triage`, {
        method: 'PATCH',
        body: JSON.stringify({ triage_status, analyst_notes }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['siem-alerts'] }),
  })
}
