import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiPost, apiDelete } from './client'
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

export function useArchiveHunt(id: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => apiDelete(`/hunts/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['hunts'] }),
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
  return useMutation({
    mutationFn: () => apiPost<ActorSuggestionsResponse>(`/hunts/${sessionId}/suggest-actors`, {}),
  })
}

export function useRefineHypothesis(sessionId: string) {
  return useMutation({
    mutationFn: () => apiPost<HypothesisRefinement>(`/hunts/${sessionId}/refine-hypothesis`, {}),
  })
}
