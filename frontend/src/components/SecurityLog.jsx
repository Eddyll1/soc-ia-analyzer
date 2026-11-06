export default function SecurityLog({ data }) {
  const log = data?.security_log || []
  const label = { injection_detected: 'Inyección en log detectada', invalid_citation_blocked: 'Cita Log_ID inexistente bloqueada',
    severity_floor_applied: 'Severidad elevada por piso de reglas', bad_json: 'Salida IA no-JSON rechazada' }
  const color = { injection_detected: '#ea580c', invalid_citation_blocked: '#dc2626', severity_floor_applied: '#ca8a04', bad_json: '#64748b' }
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
      <div className="text-sm text-slate-300 mb-1">Registro de seguridad de la capa IA</div>
      <p className="text-xs text-slate-500 mb-3">Modo IA: <b>{data?.ai_mode}</b>. Defensas anti prompt-injection aplicadas sobre la salida del modelo.</p>
      {log.length === 0
        ? <p className="text-sm text-emerald-400">Sin incidencias de seguridad en esta ejecución.</p>
        : <div className="space-y-1">
            {log.map((s, i) => (
              <div key={i} className="text-xs flex gap-2">
                <span className="font-medium" style={{ color: color[s.type] || '#94a3b8' }}>{label[s.type] || s.type}</span>
                <span className="text-slate-400">{s.log_id || s.incident_id || ''} {s.invalid ? `→ ${s.invalid.join(', ')}` : ''} {s.note || ''} {s.matches ? `→ ${s.matches.join(' | ')}` : ''}</span>
              </div>
            ))}
          </div>}
    </div>
  )
}
