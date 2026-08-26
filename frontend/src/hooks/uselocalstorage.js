import { useState, useEffect } from 'react'

/**
 * Drop-in replacement for useState(defaultValue) that also persists
 * the value to localStorage under `key`.
 *
 * - On first render, it tries to read `key` from localStorage. If
 *   found, that becomes the initial value instead of `defaultValue`.
 * - On every change to `value`, it re-writes localStorage.
 *
 * Usage is identical to useState:
 *   const [history, setHistory] = useLocalStorageState('history', [])
 */
export function useLocalStorageState(key, defaultValue) {
  // The function passed to useState only runs ONCE, on mount.
  // Without this, we'd re-read localStorage on every re-render for no reason.
  const [value, setValue] = useState(() => {
    try {
      const stored = window.localStorage.getItem(key)
      return stored !== null ? JSON.parse(stored) : defaultValue
    } catch (err) {
      // Corrupt JSON, storage disabled in this browser, etc. -- fail safe.
      console.warn(`useLocalStorageState: could not read "${key}"`, err)
      return defaultValue
    }
  })

  // Runs after every render where `value` changed, writing it back out.
  useEffect(() => {
    try {
      window.localStorage.setItem(key, JSON.stringify(value))
    } catch (err) {
      console.warn(`useLocalStorageState: could not write "${key}"`, err)
    }
  }, [key, value])

  return [value, setValue]
}