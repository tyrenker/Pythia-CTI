const API_BASE = '/v1'

function getApiKey(): string {
  return localStorage.getItem('pythia_api_key') ?? ''
}

export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const key = getApiKey()
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    ...(key ? { 'X-API-Key': key } : {}),
    ...(init?.headers ?? {}),
  }

  const res = await fetch(`${API_BASE}${path}`, { ...init, headers })
  if (!res.ok) {
    const body = await res.text()
    let detail = body
    try {
      detail = JSON.parse(body)?.detail ?? body
    } catch { /* raw text */ }
    throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail))
  }
  return res.json() as Promise<T>
}

export async function apiPost<T>(path: string, body: unknown): Promise<T> {
  return apiFetch<T>(path, {
    method: 'POST',
    body: JSON.stringify(body),
  })
}

export async function apiDelete(path: string): Promise<void> {
  const key = getApiKey()
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    ...(key ? { 'X-API-Key': key } : {}),
  }
  const res = await fetch(`${API_BASE}${path}`, { method: 'DELETE', headers })
  if (!res.ok) {
    const body = await res.text()
    let detail: unknown = body
    try { detail = JSON.parse(body)?.detail ?? body } catch { /* raw text */ }
    throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail))
  }
  // 204 No Content — nothing to parse
}
