import { useState } from 'react'
import { sevBadge } from '../lib/format'

function Incident({ inc }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg">
      <button onClick={() => setOpen(!open)} className="w-full flex items-center justify-between p-4 text-left">
        <div className="flex items-center gap-3">
          <span className="font-mono text-sky-400">{inc.code}</span>
          <span className="px-2 py-0.5 rounded text-xs font-medium" style={sevBadge(inc.severity)}>{inc.severity}</span>
          <span className="text-sm text-slate-300">{inc.narrative?.slice(0, 80) || 'Incidente correlacionado'}</span>
        </div>
        <span className="text-slate-500 text-sm">{inc.evidence?.length || 0} eventos · {open ? '▲' : '▼'}</span>
      </button>
      {open && (
        <div className="px-4 pb-4 space-y-3 border-t border-slate-800 pt-3">
          {inc.narrative && (
            <div>
              <div className="text-xs text-slate-400 mb-1">Resumen del incidente</div>
              <p className="text-sm text-slate-200 leading-relaxed">{inc.narrative}</p>
            </div>
          )}
          {inc.ai_narrative && (
            <div className="bg-sky-950/30 border border-sky-900/50 rounded p-2">
              <div className="text-xs text-sky-400 mb-1">Narrativa IA (Gemini)</div>
              <p className="text-sm text-slate-200 leading-relaxed">{inc.ai_narrative}</p>
            </div>
          )}
          {inc.justification && (
            <div className="text-sm"><span className="text-slate-400">Clasificación: </span>{inc.justification}</div>
          )}
          {inc.recommended_action && (
            <div className="text-sm"><span className="text-slate-400">Acción: </span>{inc.recommended_action}</div>
          )}
          {inc.mitre?.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {inc.mitre.map((m) => <span key={m} className="text-xs font-mono bg-slate-800 px-2 py-0.5 rounded">{m}</span>)}
            </div>
          )}
          {inc.timeline?.length > 0 && (
            <div>
              <div className="text-xs text-slate-400 mb-1">
                Línea de tiempo · hitos ({inc.timeline.length}) de {inc.event_count} eventos
              </div>
              <div className="space-y-1 max-h-96 overflow-y-auto pr-1">
                {inc.timeline.map((t, i) => (
                  <div key={i} className="text-xs grid grid-cols-[160px_60px_1fr] gap-2 items-baseline border-b border-slate-800/50 py-1">
                    <span className="font-mono text-amber-300 shrink-0">
                      {t.ts_start}{t.count > 1 ? ` → ${t.ts_end}` : ''}
                    </span>
                    <span className="font-mono text-slate-400 shrink-0">
                      {t.count > 1 ? `${t.count}×` : ''} {t.event_id}
                    </span>
                    <span className="text-slate-300">
                      {t.host && <span className="text-slate-500">{t.host} · </span>}
                      {t.fact}
                      {t.src_ip && <span className="text-slate-500"> ({t.src_ip})</span>}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
          <details className="text-xs">
            <summary className="text-slate-400 cursor-pointer">Evidencia ({inc.evidence?.length || 0} Log_ID)</summary>
            <div className="font-mono text-slate-500 mt-1 break-all">{(inc.evidence || []).join(', ')}</div>
          </details>
        </div>
      )}
    </div>
  )
}

export default function IncidentList({ data }) {
  if (!data) return null
  return (
    <div className="space-y-3">
      {data.incidents.map((inc) => <Incident key={inc.code} inc={inc} />)}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
        <div className="text-sm text-slate-300 mb-2">Indicadores de compromiso (IoC)</div>
        <table className="text-xs w-full">
          <tbody>
            {data.iocs.map((i, k) => (
              <tr key={k} className="border-t border-slate-800">
                <td className="py-1 text-slate-500 w-16">{i.type}</td>
                <td className="py-1 font-mono text-slate-300">{i.value}</td>
                <td className="py-1 text-slate-500">{i.context}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
