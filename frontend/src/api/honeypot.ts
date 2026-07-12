import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'

export interface HoneypotEvent {
  id: string
  honeypot_type: string
  attacker_ip: string
  attacker_asn: string | null
  attacker_country_code: string | null
  attacker_org: string | null
  target_port: number | null
  protocol: string | null
  event_timestamp: string
  received_at: string
  tpot_session_id: string | null
  username_attempted: string | null
  password_attempted: string | null
  commands_run: string[]
  files_downloaded: string[]
  payload_hash: string | null
  ttp_ids: string[]
  campaign_id: string | null
  enriched_at: string | null
  abuseipdb_score: number | null
  greynoise_classification: string | null
  vt_detections: number | null
}

export interface HoneypotCampaign {
  id: string
  name: string
  status: string
  first_seen: string
  last_seen: string
  attacker_ips: string[]
  asns: string[]
  ttp_ids: string[]
  payload_hashes: string[]
  credential_patterns: { usernames: string[]; passwords: string[] }
  target_ports: number[]
  event_count: number
  sigma_rule_id: string | null
  report_id: string | null
  notes: string | null
  created_at: string
  updated_at: string
}

export interface HoneypotDailyStats {
  event_count: number
  top_ips: [string, number][]
  top_ports: [number, number][]
  by_honeypot_type: Record<string, number>
  top_credentials: [string, number][]
  top_countries: [string, number][]
}

export interface HoneypotRealtimeStats {
  window_minutes: number
  event_count: number
  by_honeypot_type: Record<string, number>
}

function qs(params: Record<string, string | number | boolean | undefined>): string {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== '' && v !== null) p.set(k, String(v))
  }
  const s = p.toString()
  return s ? `?${s}` : ''
}

export function useHoneypotEvents(params: Record<string, string | number | undefined> = {}) {
  const q = qs(params)
  return useQuery({
    queryKey: ['honeypot-events', q],
    queryFn: () => apiFetch<HoneypotEvent[]>(`/honeypot/events${q}`),
    refetchInterval: 10_000,
  })
}

export function useHoneypotEvent(id: string) {
  return useQuery({
    queryKey: ['honeypot-event', id],
    queryFn: () => apiFetch<HoneypotEvent>(`/honeypot/events/${id}`),
    enabled: !!id,
  })
}

export function useHoneypotCampaigns(params: Record<string, string | number | undefined> = {}) {
  const q = qs(params)
  return useQuery({
    queryKey: ['honeypot-campaigns', q],
    queryFn: () => apiFetch<HoneypotCampaign[]>(`/honeypot/campaigns${q}`),
    staleTime: 30_000,
  })
}

export function useHoneypotCampaign(id: string) {
  return useQuery({
    queryKey: ['honeypot-campaign', id],
    queryFn: () => apiFetch<HoneypotCampaign>(`/honeypot/campaigns/${id}`),
    enabled: !!id,
  })
}

export function useHoneypotDailyStats() {
  return useQuery({
    queryKey: ['honeypot-daily-stats'],
    queryFn: () => apiFetch<HoneypotDailyStats>('/honeypot/stats/daily'),
    refetchInterval: 60_000,
  })
}

export function useHoneypotRealtimeStats() {
  return useQuery({
    queryKey: ['honeypot-realtime-stats'],
    queryFn: () => apiFetch<HoneypotRealtimeStats>('/honeypot/stats/realtime'),
    refetchInterval: 5_000,
  })
}
