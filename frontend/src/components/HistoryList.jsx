import { sevBadge } from '../lib/format'

export default function HistoryList({ items, onOpen, onDelete }) {
  if (!items?.length) return <p className="text-slate-400 text-sm">No hay análisis guardados todavía.</p>
  return (
    <div className="space-y-2">
      {items.map((a) => (
        <div key={a.id} className="bg-slate-900 border border-slate-800 rounded-lg p-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-slate-500 text-xs">#{a.id}</span>
            <span className="text-sm text-slate-300">{a.filename}</span>
            {a.max_severity && <span className="px-2 py-0.5 rounded text-xs" style={sevBadge(a.max_severity)}>{a.max_severity}</span>}
            <span className="text-xs text-slate-500">{a.event_count} eventos · {a.incident_count} inc · {a.profile}</span>
          </div>
          <div className="flex gap-2">
            <button onClick={() => onOpen(a.id)} className="px-3 py-1 rounded bg-slate-700 hover:bg-slate-600 text-xs">Abrir</button>
            <button onClick={() => onDelete(a.id)} className="px-3 py-1 rounded bg-red-900/60 hover:bg-red-800 text-xs">Borrar</button>
          </div>
        </div>
      ))}
    </div>
  )
}
