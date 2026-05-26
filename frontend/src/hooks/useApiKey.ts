import { useState, useCallback, useEffect } from 'react'

const STORAGE_KEY = 'pythia_api_key'

// Module-level store so all hook instances share the same state.
const listeners = new Set<(key: string) => void>()
let currentKey = localStorage.getItem(STORAGE_KEY) ?? ''

function setGlobalKey(key: string) {
  currentKey = key
  if (key) {
    localStorage.setItem(STORAGE_KEY, key)
  } else {
    localStorage.removeItem(STORAGE_KEY)
  }
  listeners.forEach(fn => fn(key))
}

export function useApiKey() {
  const [apiKey, setApiKeyState] = useState(currentKey)

  useEffect(() => {
    listeners.add(setApiKeyState)
    return () => { listeners.delete(setApiKeyState) }
  }, [])

  const setApiKey = useCallback((key: string) => {
    setGlobalKey(key)
  }, [])

  return { apiKey, setApiKey }
}
