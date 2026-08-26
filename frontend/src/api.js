const API_BASE = 'http://localhost:8000'

export async function askQuestion(payload) {
  const res = await fetch(`${API_BASE}/ask`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) {
    const detail = await res.text()
    throw new Error(`API error ${res.status}: ${detail}`)
  }
  return res.json()
}

export async function getTraceSummary() {
  const res = await fetch(`${API_BASE}/dashboard/trace-summary`)
  if (!res.ok) throw new Error(`API error ${res.status}`)
  return res.json()
}

export async function getRedTeamSummary() {
  const res = await fetch(`${API_BASE}/dashboard/red-team-summary`)
  if (!res.ok) throw new Error(`API error ${res.status}`)
  return res.json()
}