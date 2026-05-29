import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiPost, apiDelete } from './client'

const API_BASE = '/v1'
function getApiKey(): string {
  return localStorage.getItem('pythia_api_key') ?? ''
}
import type {
  HuntSessionSummary,
  HuntSessionDetail,
  HuntNote,
  HuntDraftDetection,
  HuntObservation,
  ActorSuggestionsResponse,
  HypothesisRefinement,
} from '@/types/api'

// ── Sessions ──────────────────────────────────────────────────────────────────

export function useHunts(statusFilter?: string) {
  const qs = statusFilter ? `?status=${statusFilter}` : ''
  return useQuery({
    queryKey: ['hunts', statusFilter],
    queryFn: () => apiFetch<HuntSessionSummary[]>(`/hunts${qs}`),
  })
}

export function useHunt(id: string) {
  return useQuery({
    queryKey: ['hunt', id],
    queryFn: () => apiFetch<HuntSessionDetail>(`/hunts/${id}`),
    enabled: !!id,
    refetchInterval: false,
  })
}

export function useCreateHunt() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: {
      name: string
      hypothesis?: string
      analyst?: string
      sector_focus?: string[]
      motivation_focus?: string[]
    }) => apiPost<HuntSessionDetail>('/hunts', body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['hunts'] }),
  })
}

export function useUpdateHunt(id: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: Partial<{
      name: string
      hypothesis: string
      status: string
      analyst: string
      sector_focus: string[]
      motivation_focus: string[]
    }>) => apiFetch<HuntSessionDetail>(`/hunts/${id}`, {
      method: 'PUT',
      body: JSON.stringify(body),
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['hunt', id] })
      qc.invalidateQueries({ queryKey: ['hunts'] })
    },
  })
}

export function useDeleteHunt() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => apiDelete(`/hunts/${id}`),
    onSettled: () => qc.invalidateQueries({ queryKey: ['hunts'] }),
  })
}

// ── Observations ──────────────────────────────────────────────────────────────

export function useAddObservation(sessionId: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: {
      obs_type: string
      value: string
      confidence_source?: string
      confidence_info?: string
      notes?: string
    }) => apiPost<HuntObservation>(`/hunts/${sessionId}/observations`, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['hunt', sessionId] }),
  })
}

export function useRemoveObservation(sessionId: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (obsId: string) => apiDelete(`/hunts/${sessionId}/observations/${obsId}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['hunt', sessionId] }),
  })
}

// ── Notes ─────────────────────────────────────────────────────────────────────

export function useHuntNotes(sessionId: string) {
  return useQuery({
    queryKey: ['hunt-notes', sessionId],
    queryFn: () => apiFetch<HuntNote>(`/hunts/${sessionId}/notes`),
    enabled: !!sessionId,
  })
}

export function useUpsertNotes(sessionId: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (content: string) =>
      apiFetch<HuntNote>(`/hunts/${sessionId}/notes`, {
        method: 'PUT',
        body: JSON.stringify({ content }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['hunt-notes', sessionId] }),
  })
}

// ── Draft Detections ──────────────────────────────────────────────────────────

export function useHuntDetections(sessionId: string) {
  return useQuery({
    queryKey: ['hunt-detections', sessionId],
    queryFn: () => apiFetch<HuntDraftDetection[]>(`/hunts/${sessionId}/detections`),
    enabled: !!sessionId,
  })
}

export function useDraftDetection(sessionId: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { obs_ids: string[]; rule_type: string }) =>
      apiPost<HuntDraftDetection>(`/hunts/${sessionId}/draft-detection`, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['hunt-detections', sessionId] }),
  })
}

export function useUpdateDetection(sessionId: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...body }: { id: string; status?: string; content?: string; title?: string }) =>
      apiFetch<HuntDraftDetection>(`/hunts/${sessionId}/detections/${id}`, {
        method: 'PUT',
        body: JSON.stringify(body),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['hunt-detections', sessionId] }),
  })
}

export function usePromoteDetection(sessionId: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (detectionId: string) =>
      apiPost<{ rule_id: string; message: string }>(
        `/hunts/${sessionId}/detections/${detectionId}/promote`,
        {},
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['hunt-detections', sessionId] }),
  })
}

// ── Claude endpoints ──────────────────────────────────────────────────────────

export function useSuggestActors(sessionId: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => apiPost<ActorSuggestionsResponse>(`/hunts/${sessionId}/suggest-actors`, {}),
    onSuccess: (data) => qc.setQueryData(['hunt-actor-suggestions', sessionId], data),
  })
}

export function useCachedActorSuggestions(sessionId: string) {
  return useQuery<ActorSuggestionsResponse | null>({
    queryKey: ['hunt-actor-suggestions', sessionId],
    queryFn: () => null,
    enabled: false,
    staleTime: Infinity,
  })
}

export function useRefineHypothesis(sessionId: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => apiPost<HypothesisRefinement>(`/hunts/${sessionId}/refine-hypothesis`, {}),
    onSuccess: (data) => qc.setQueryData(['hunt-hypothesis-refinement', sessionId], data),
  })
}

export function useCachedHypothesisRefinement(sessionId: string) {
  return useQuery<HypothesisRefinement | null>({
    queryKey: ['hunt-hypothesis-refinement', sessionId],
    queryFn: () => null,
    enabled: false,
    staleTime: Infinity,
  })
}

// ── Exports ───────────────────────────────────────────────────────────────────

export async function exportHunt(
  sessionId: string,
  format: 'markdown' | 'stix' | 'pdf',
  template?: 'executive' | 'technical',
): Promise<void> {
  const key = getApiKey()
  const headers: HeadersInit = key ? { 'X-API-Key': key } : {}

  let path = `${API_BASE}/hunts/${sessionId}/export/${format}`
  if (format === 'pdf' && template) path += `?template=${template}`

  const res = await fetch(path, { headers })
  if (!res.ok) throw new Error(`Export failed: ${res.statusText}`)

  const blob = await res.blob()
  const objectUrl = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = objectUrl

  const cd = res.headers.get('Content-Disposition') ?? ''
  const match = cd.match(/filename="([^"]+)"/)
  const ext = format === 'markdown' ? 'md' : format === 'stix' ? 'json' : 'pdf'
  a.download = match ? match[1] : `hunt-${sessionId.slice(0, 8)}.${ext}`

  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(objectUrl)
}
