import { useState } from 'react'
import Sidebar from './components/Sidebar.jsx'
import SecurityConsole from './components/SecurityConsole.jsx'
import Dashboard from './components/Dashboard.jsx'
import { useLocalStorageState } from './hooks/useLocalStorage.js'

export default function App() {
  const [page, setPage] = useState('security_console')
  const [settings, setSettings] = useState({ backend: 'ollama', model: '', k: 5 })

  // Lives here instead of inside SecurityConsole so it survives that
  // component unmounting when you switch pages, and survives a full
  // page reload because useLocalStorageState mirrors it to localStorage.
  const [history, setHistory] = useLocalStorageState(
    'rag_security_console_history',
    []
  )

  return (
    <div className="app-shell">
      <Sidebar page={page} setPage={setPage} settings={settings} setSettings={setSettings} />
      <div className="main-area">
        {page === 'security_console' && (
          <SecurityConsole
            settings={settings}
            history={history}
            setHistory={setHistory}
          />
        )}
        {page === 'dashboard' && <Dashboard />}
      </div>
    </div>
  )
}