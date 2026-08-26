import { useState, useRef, useEffect } from 'react'
import DefensesPanel from './defensespanel.jsx'
import { askQuestion } from '../api.js'

const TAG_CLASS = { pass: 'tag-pass', block: 'tag-block', info: 'tag-info', skip: 'tag-skip' }

export default function SecurityConsole({ settings, history, setHistory }) {
  const [defenses, setDefenses] = useState({
    question_sanitize: true,
    question_semantic_check: true,
    firewall: true,
    validate: true,
    validate_semantic: true,
  })
  // history / setHistory now come from App.jsx as props (see App.jsx) --
  // this is the only structural change in this file. Everything below
  // that calls setHistory(...) is untouched: it's still the same setter
  // function, just owned one level up.
  const [question, setQuestion] = useState('')
  const [loading, setLoading] = useState(false)
  const [expandedTrace, setExpandedTrace] = useState({}) 
  const listRef = useRef(null)

  useEffect(() => {
    if (listRef.current) {
      listRef.current.scrollTop = listRef.current.scrollHeight
    }
  }, [history])

  async function handleSend() {
    const q = question.trim()
    if (!q || loading) return

    // 1. Add immediately to history with matching key "question" and result = null
    const userEntry = {
      question: q,
      result: null,
      timestamp: new Date().toLocaleTimeString(),
    }

    setHistory((prev) => [...prev, userEntry])
    setQuestion('')
    setLoading(true)

    try {
      const result = await askQuestion({
        question: q,
        backend: settings.backend,
        model: settings.model || null,
        k: settings.k,
        ...defenses,
      })

      // 2. Replace the null result with the actual API result
      setHistory((prev) =>
        prev.map((item, idx) =>
          idx === prev.length - 1 ? { ...item, result: result } : item
        )
      )
    } catch (err) {
      // 3. Gracefully attach the error state to the last message
      setHistory((prev) =>
        prev.map((item, idx) =>
          idx === prev.length - 1
            ? {
                ...item,
                result: {
                  blocked_at: 'error',
                  trace: [],
                  retrieved_chunks: [],
                  answer: `Error: ${err.message || 'Failed to fetch response'}`,
                },
              }
            : item
        )
      )
    } finally {
      setLoading(false)
    }
  }

  function handleKeyDown(e) {
    if (e.key === 'Enter') handleSend()
  }
  function toggleTrace(i) {
  setExpandedTrace(prev => ({ ...prev, [i]: !prev[i] }))
  }

  return (
    <>
      <h1 className="page-title">RAG Security Console</h1>
      <div className="console-layout">
        <div className="console-card">
          <div className="message-list" ref={listRef}>
            {history.length === 0 && (
              <div className="empty-hint">
                Ask a question below to see the defense trace and answer here.
              </div>
            )}

            {history.map((entry, i) => {
              const r = entry.result
              const blocked = r ? (r.blocked_at !== null || r.canary_leaked) : false

              return (
                <div className="message-block" key={i}>
                  {/* 1. User question shows immediately */}
                  <div className="user-bubble">{entry.question}</div>

                  {/* 2. IF RESULT EXISTS: Show trace, chunks, and answer */}
                  {r ? (
                    <>
                       <button
                          className="toggle-details-btn"
                          onClick={() => toggleTrace(i)}
                        >
                          {expandedTrace[i] ? '▲ Hide layer details' : '▼ Show layer details'}
                       </button>
                        {expandedTrace[i] && r.trace && r.trace.map((step, j) => (
                        <div className="trace-line" key={j}>
                          <span className={`tag ${TAG_CLASS[step.result] || 'tag-info'}`}>
                            [{step.result.toUpperCase()}]
                          </span>
                          <strong>{step.stage}</strong> -- {step.detail}
                        </div>
                      ))}
                      {r.blocked_at === null && r.retrieved_chunks && r.retrieved_chunks.length > 0 && (
                        <div className="retrieved-chunks">
                          Retrieved: {r.retrieved_chunks.map((c) => c.source).join(', ')}
                        </div>
                      )}
                      <div className={`answer-box ${blocked ? 'blocked' : 'ok'}`}>
                        {r.answer}
                      </div>
                    </>
                  ) : (
                    /* 3. IF RESULT IS NULL: Show the Thinking Box */
                    <div className="thinking-box">
                      <span className="spinner">⚡</span>
                      <span>Evaluating Guardrails & Generating Response...</span>
                    </div>
                  )}
                </div>
              )
            })}
          </div>

          <div className="input-row">
            <input
              type="text"
              placeholder="Ask your Question"
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              onKeyDown={handleKeyDown}
            />
            <button className="send-button" onClick={handleSend} disabled={loading}>
              {loading ? '...' : '\u25B6'}
            </button>
          </div>
        </div>

        <DefensesPanel defenses={defenses} setDefenses={setDefenses} />
      </div>
    </>
  )
}