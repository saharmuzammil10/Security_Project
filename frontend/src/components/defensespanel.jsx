export default function DefensesPanel({ defenses, setDefenses }) {
  const items = [
    { key: 'question_sanitize', label: 'Regex question sanitizer' },
    { key: 'question_semantic_check', label: 'Semantic question guard' },
    { key: 'firewall', label: 'Document firewall' },
    { key: 'validate', label: 'Output validation' },
    { key: 'validate_semantic', label: 'Semantic output validation' },
  ]

  return (
    <div className="defenses-panel">
      <h3>Defenses</h3>
      {items.map((item) => (
        <label className="defense-checkbox" key={item.key}>
          <input
            type="checkbox"
            checked={defenses[item.key]}
            onChange={(e) => setDefenses({ ...defenses, [item.key]: e.target.checked })}
          />
          {item.label}
        </label>
      ))}
    </div>
  )
}