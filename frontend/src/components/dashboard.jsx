import { useEffect, useState } from 'react'
import { getTraceSummary, getRedTeamSummary } from '../api.js'

const STAGE_LABELS = {
  question_sanitizer: 'Regex Question Sanitizer',
  question_sanitizer_regex: 'Regex Question Sanitizer',
  question_guard_semantic: 'Semantic Question Guard',
  firewall: 'Document Firewall',
  semantic_validation: 'Semantic Output Validation',
  output_validation: 'Signature Output Validation',
  regex_layer: 'Regex Sanitizer Layer',
  semantic_question_layer: 'Semantic Question Guard',
  firewall_layer: 'Document Firewall Layer',
  output_validation_layer: 'Output Validation Layer',
  full_pipeline: 'Full End-to-End Defense',
}

function formatDate(isoString) {
  if (!isoString) return 'Never'
  const d = new Date(isoString)
  if (isNaN(d.getTime())) return isoString
  return d.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export default function Dashboard() {
  const [trace, setTrace] = useState(null)
  const [redTeam, setRedTeam] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    Promise.all([getTraceSummary(), getRedTeamSummary()])
      .then(([t, r]) => {
        setTrace(t)
        setRedTeam(r)
      })
      .catch((err) => setError(err.message))
  }, [])

  if (error) {
    return <div style={{ color: '#991b1b', fontWeight: 600 }}>Error loading dashboard: {error}</div>
  }

  return (
    <div style={{
      width: '100%',
      height: '100%',
      display: 'flex',
      flexDirection: 'column',
      gap: '12px',
      boxSizing: 'border-box'
    }}>
      <h1 className="page-title" style={{ margin: '0 0 4px 0', fontSize: '1.75rem' }}>Dashboard</h1>

      {/* Section 1: Query Trace Log */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-dark)' }}>
            Query Trace Log
          </h3>
          {trace && trace.total > 0 && (
            <span style={{
              background: '#1b374d',
              color: '#E8EEF5',
              padding: '2px 10px',
              borderRadius: '12px',
              fontSize: '0.75rem',
              fontWeight: 600
            }}>
              {trace.total} Total Queries
            </span>
          )}
        </div>

        {!trace ? (
          <p className="empty-hint">Loading...</p>
        ) : trace.total === 0 ? (
          <p className="empty-hint">No trace log yet — ask questions on the Security console first.</p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              paddingBottom: '4px',
              borderBottom: '1px solid rgba(28, 40, 57, 0.2)'
            }}>
              <span style={{ fontSize: '0.9rem', color: 'var(--text-dark)' }}>Total questions logged</span>
              <strong style={{ fontSize: '1.05rem', color: 'var(--text-dark)' }}>{trace.total}</strong>
            </div>

            {Object.entries(trace.blocked_by_stage || {}).map(([stage, count]) => (
              <div key={stage} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '2px 0' }}>
                <span style={{ fontSize: '0.88rem', color: 'var(--text-dark)' }}>{STAGE_LABELS[stage] || stage}</span>
                <span style={{
                  color: count > 0 ? '#991b1b' : '#475569',
                  fontWeight: 600,
                  fontSize: '0.85rem'
                }}>
                  {count} blocked
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Visual Section Divider */}
      <hr style={{ border: 'none', borderTop: '1px solid rgba(28, 40, 57, 0.2)', margin: '4px 0' }} />

      {/* Section 2: Red Team Report History */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-dark)' }}>
            Red Team Report History
          </h3>
          {redTeam && redTeam.runs > 0 && (
            <span style={{
              background: '#1b374d',
              color: '#cfe8d5',
              padding: '2px 10px',
              borderRadius: '12px',
              fontSize: '0.75rem',
              fontWeight: 600
            }}>
              {redTeam.runs} {redTeam.runs === 1 ? 'Run' : 'Runs'} Recorded
            </span>
          )}
        </div>

        {!redTeam ? (
          <p className="empty-hint">Loading...</p>
        ) : redTeam.runs === 0 ? (
          <p className="empty-hint">No red team suite runs recorded yet — run src/red_team_suite.py first.</p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              fontSize: '0.82rem',
              color: '#334155',
              paddingBottom: '4px',
              borderBottom: '1px solid rgba(28, 40, 57, 0.15)'
            }}>
              <span>Most Recent Run:</span>
              <strong style={{ color: 'var(--text-dark)' }}>{formatDate(redTeam.latest_timestamp)}</strong>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {Object.entries(redTeam.layer_summaries || {}).map(([layer, s]) => {
                const percent = s.total > 0 ? Math.round((s.blocked / s.total) * 100) : 0
                const isHigh = percent >= 80

                return (
                  <div key={layer} style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.84rem' }}>
                      <span style={{ color: 'var(--text-dark)', fontWeight: 600 }}>{STAGE_LABELS[layer] || layer}</span>
                      <span style={{ color: '#475569', fontSize: '0.8rem' }}>
                        <strong style={{ color: 'var(--text-dark)' }}>{s.blocked}/{s.total}</strong> blocked ({percent}%)
                      </span>
                    </div>

                    <div style={{
                      width: '100%',
                      height: '6px',
                      background: 'rgba(28, 40, 57, 0.15)',
                      borderRadius: '4px',
                      overflow: 'hidden'
                    }}>
                      <div
                        style={{
                          width: `${percent}%`,
                          height: '100%',
                          borderRadius: '4px',
                          background: isHigh ? '#20364c' : percent > 0 ? '#b45309' : '#64748b',
                          transition: 'width 0.4s ease'
                        }}
                      />
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}