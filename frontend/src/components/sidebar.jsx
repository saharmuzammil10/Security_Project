import { useState } from 'react'

export default function Sidebar({ page, setPage, settings, setSettings }) {
  const [settingsOpen, setSettingsOpen] = useState(false)

  const navItems = [
    { key: 'dashboard', label: 'Dashboard' },
    { key: 'security_console', label: 'Security console' },
  ]

  return (
    <div className="sidebar">
      <div className="sidebar-title">RAG Console</div>

      {navItems.map((item) => (
        <button
          key={item.key}
          className={`nav-item ${page === item.key ? 'selected' : ''}`}
          onClick={() => setPage(item.key)}
        >
          {item.label}
        </button>
      ))}

      <div className="settings-section">
        <button
          className={`settings-toggle ${settingsOpen ? 'open' : ''}`}
          onClick={() => setSettingsOpen((v) => !v)}
        >
          Settings <span>{settingsOpen ? '\u25B2' : '\u25BC'}</span>
        </button>

        {settingsOpen && (
          <div className="settings-body">
            <div>
              <label>Backend</label>
              <select
                value={settings.backend}
                onChange={(e) => setSettings({ ...settings, backend: e.target.value })}
              >
                <option value="ollama">ollama</option>
                <option value="claude">claude</option>
              </select>
            </div>

            <div>
              <label>Model override (optional)</label>
              <input
                type="text"
                value={settings.model}
                onChange={(e) => setSettings({ ...settings, model: e.target.value })}
                placeholder=""
              />
            </div>

            <div>
              <label>Chunks to retrieve (k): {settings.k}</label>
              <input
                type="range"
                min="1"
                max="10"
                value={settings.k}
                onChange={(e) => setSettings({ ...settings, k: Number(e.target.value) })}
              />
            </div>
          </div>
        )}
      </div>
    </div>
  )
}