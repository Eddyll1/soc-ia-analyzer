import { useState } from 'react'
import { sevBadge } from '../lib/format'

function Incident({ inc }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg">
      <button onClick={() => setOpen(!open)} className="w-full flex items-center justify-between p-4 text-left gap-3">
        <div className="flex items-center gap-3 min-w-0">
          <span className="font-mono text-sky-400 shrink-0">{inc.code}</span>
          <span className="px-2 py-0.5 rounded text-xs font-medium shrink-0" style={sevBadge(inc.severity)}>{inc.severity}</span>
          <span className="text-sm text-slate-300 truncate">{inc.headline || 'Incidente correlacionado'}</span>
        </div>
        <span className="text-slate-500 text-sm shrink-0">{inc.event_count ?? (inc.evidence?.length || 0)} eventos · {open ? '▲' : '▼'}</span>
      </button>
      {open && (
        <div className="px-4 pb-4 space-y-3 border-t border-slate-800 pt-3">
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-sm">
            <span className="text-slate-200 font-medium">{inc.headline}</span>
            {inc.window && <span className="text-slate-500">🕐 {inc.window}</span>}
          </div>
          {inc.phases?.length > 0 && (
            <div>
              <div className="text-xs text-slate-400 mb-1">Fases del ataque</div>
              <div className="space-y-1.5">
                {inc.phases.map((p, i) => (
                  <div key={i} className="flex gap-2 text-sm">
                    <span className="text-amber-300 font-mono text-xs shrink-0 w-28">{p.t0?.slice(11) || ''}{p.t1 && p.t1 !== p.t0 ? `–${p.t1.slice(11)}` : ''}</span>
                    <span className="shrink-0 font-medium text-slate-200 w-48">{p.phase}</span>
                    <span className="text-slate-400">{p.detail}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          {inc.affected && (
            <div className="bg-slate-950/40 border border-slate-800 rounded p-2 text-sm">
              <div className="text-xs text-slate-400 mb-1">Entidades afectadas (para contención)</div>
              <div className="grid md:grid-cols-3 gap-2">
                <div>
                  <div className="text-xs text-slate-500">Hosts a aislar</div>
                  {(inc.affected.hosts || []).map((h) => (
                    <div key={h} className="font-mono text-slate-200">
                      {h}
                      {inc.affected.host_ips?.[h]?.length > 0 &&
                        <span className="text-slate-500"> · {inc.affected.host_ips[h].join(', ')}</span>}
                    </div>
                  ))}
                </div>
                <div>
                  <div className="text-xs text-slate-500">Usuarios a resetear</div>
                  <div className="font-mono text-slate-200">{(inc.affected.users || []).join(', ') || '—'}</div>
                </div>
                <div>
                  <div className="text-xs text-slate-500">IPs externas a bloquear</div>
                  <div className="font-mono text-red-300">{(inc.affected.external_ips || []).join(', ') || '—'}</div>
                  {inc.affected.exfil_dest?.length > 0 && (
                    <div className="text-xs text-slate-500 mt-1">Exfil → <span className="text-red-300 font-mono">{inc.affected.exfil_dest.join(', ')}</span></div>
                  )}
                </div>
              </div>
            </div>
          )}
          {inc.impact && <div className="text-sm"><span className="text-slate-400">Impacto: </span>{inc.impact}</div>}
          {inc.ai_narrative && (
            <div className="bg-sky-950/30 border border-sky-900/50 rounded p-2">
              <div className="text-xs text-sky-400 mb-1">Narrativa IA (Gemini)</div>
              <p className="text-sm text-slate-200 leading-relaxed">{inc.ai_narrative}</p>
            </div>
          )}
          {inc.recommended_action && (
            <div className="text-sm"><span className="text-slate-400">Acción: </span>{inc.recommended_action}</div>
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
