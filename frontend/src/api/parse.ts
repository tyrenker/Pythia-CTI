import { useMutation } from '@tanstack/react-query'
import { apiPost } from './client'
import type { ParseResponse } from '@/types/api'

interface ParseParams {
  url?: string
  raw_text?: string
  tlp?: string
}

export function useParse() {
  return useMutation({
    mutationFn: (params: ParseParams) => apiPost<ParseResponse>('/parse', params),
  })
}
