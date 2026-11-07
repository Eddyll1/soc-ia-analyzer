import { useEffect, useMemo, useState } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  LineChart, Line, CartesianGrid,
} from 'recharts'
import { getEvents } from '../api/client'

const TOOLTIP = {
  contentStyle: { background: '#0f172a', border: '1px solid #334155', borderRadius: 6 },
  itemStyle: { color: '#f1f5f9' }, labelStyle: { color: '#f1f5f9' },
}
const Panel = ({ title, children, right }) => (
  <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
    <div className="flex items-center justify-between mb-3">
      <div className="text-sm text-slate-300">{title}</div>
      {right}
    </div>
    {children}
  </div>
)
const PAGE = 15
const hourOf = (ts) => (ts ? String(ts).slice(11, 13) : '')
const uniq = (arr) => [...new Set(arr.filter(Boolean))].sort()

export default function EventsExplorer({ analysisId }) {
  const [events, setEvents] = useState(null)
  const [f, setF] = useState({ host: '', user: '', event_id: '', severity: '', from: '', to: '', q: '' })
  const [page, setPage] = useState(0)

  useEffect(() => {
    if (!analysisId) return
    setEvents(null); setPage(0)
    getEvents(analysisId).then(setEvents).catch(() => setEvents([]))
  }, [analysisId])

  const opts = useMemo(() => ({
    host: uniq((events || []).map((e) => e.host)),
    user: uniq((events || []).map((e) => e.user)),
    event_id: uniq((events || []).map((e) => e.event_id)),
    severity: uniq((events || []).map((e) => e.severity)),
    hours: uniq((events || []).map((e) => hourOf(e.timestamp))),
  }), [events])

  const filtered = useMemo(() => {
    if (!events) return []
    const q = f.q.toLowerCase()
    return events.filter((e) => {
      if (f.host && e.host !== f.host) return false
      if (f.user && e.user !== f.user) return false
      if (f.event_id && e.event_id !== f.event_id) return false
      if (f.severity && e.severity !== f.severity) return false
      const h = hourOf(e.timestamp)
      if (f.from && h < f.from) return false
      if (f.to && h > f.to) return false
      if (q && !JSON.stringify(e).toLowerCase().includes(q)) return false
      return true
    })
  }, [events, f])

  const byHour = useMemo(() => {
    const m = {}
    filtered.forEach((e) => { const h = hourOf(e.timestamp); if (h) m[h + ':00'] = (m[h + ':00'] || 0) + 1 })
    return Object.entries(m).sort().map(([hour, n]) => ({ hour, n }))
  }, [filtered])

  const byEvent = useMemo(() => {
    const m = {}
    filtered.forEach((e) => { if (e.event_id) m[e.event_id] = (m[e.event_id] || 0) + 1 })
    return Object.entries(m).map(([id, n]) => ({ id, n })).sort((a, b) => b.n - a.n).slice(0, 10)
  }, [filtered])

  const topIps = useMemo(() => {
    const m = {}
    filtered.filter((e) => e.event_id === '4625').forEach((e) => {
      if (e.source_ip) m[e.source_ip] = (m[e.source_ip] || 0) + 1
    })
    return Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 5)
  }, [filtered])

  const set = (k) => (ev) => { setF((p) => ({ ...p, [k]: ev.target.value })); setPage(0) }
  const reset = () => { setF({ host: '', user: '', event_id: '', severity: '', from: '', to: '', q: '' }); setPage(0) }
  const pages = Math.ceil(filtered.length / PAGE) || 1
  const rows = filtered.slice(page * PAGE, page * PAGE + PAGE)

  const Sel = ({ k, label, options }) => (
    <select value={f[k]} onChange={set(k)}
      className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-xs text-slate-200">
      <option value="">{label}</option>
      {options.map((o) => <option key={o} value={o}>{o}</option>)}
    </select>
  )

  if (events === null) return <Panel title="Explorador de eventos"><div className="text-sm text-slate-500 animate-pulse">Cargando eventos…</div></Panel>

  return (
    <div className="space-y-4">
      <Panel title="Explorador de eventos — filtros interactivos"
        right={<span className="text-xs text-slate-400">{filtered.length} de {events.length} eventos</span>}>
        <div className="flex flex-wrap gap-2 items-center">
          <Sel k="host" label="Host" options={opts.host} />
          <Sel k="user" label="Usuario" options={opts.user} />
          <Sel k="event_id" label="Event_ID" options={opts.event_id} />
          <Sel k="severity" label="Severidad" options={opts.severity} />
          <div className="flex items-center gap-1 text-xs text-slate-400">
            <span>Hora</span>
            <Sel k="from" label="desde" options={opts.hours} />
            <Sel k="to" label="hasta" options={opts.hours} />
          </div>
          <input value={f.q} onChange={set('q')} placeholder="buscar (IP, texto…)"
            className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-xs text-slate-200 w-44" />
          <button onClick={reset} className="text-xs text-slate-400 hover:text-slate-200 underline">limpiar</button>
        </div>
      </Panel>

      <div className="grid md:grid-cols-2 gap-4">
        <Panel title="Eventos por hora (filtrado)">
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={byHour}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="hour" stroke="#64748b" fontSize={11} />
              <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
              <Tooltip {...TOOLTIP} />
              <Line type="monotone" dataKey="n" stroke="#38bdf8" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </Panel>
        <Panel title="Top tipos de evento (filtrado)">
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={byEvent} layout="vertical" margin={{ left: 20 }}>
              <XAxis type="number" stroke="#64748b" fontSize={11} allowDecimals={false} />
              <YAxis type="category" dataKey="id" stroke="#64748b" fontSize={11} width={90} />
              <Tooltip {...TOOLTIP} />
              <Bar dataKey="n" fill="#818cf8" />
            </BarChart>
          </ResponsiveContainer>
        </Panel>
      </div>

      <Panel title="Eventos (tabla filtrable y paginada)"
        right={
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <button disabled={page === 0} onClick={() => setPage((p) => p - 1)}
              className="px-2 py-0.5 rounded bg-slate-800 disabled:opacity-30">←</button>
            <span>{page + 1} / {pages}</span>
            <button disabled={page >= pages - 1} onClick={() => setPage((p) => p + 1)}
              className="px-2 py-0.5 rounded bg-slate-800 disabled:opacity-30">→</button>
          </div>
        }>
        <div className="overflow-x-auto">
          <table className="text-xs w-full">
            <thead>
              <tr className="text-slate-400 text-left">
                {['Hora', 'Log_ID', 'Host', 'Event_ID', 'Usuario', 'IP origen', 'Resultado'].map((h) =>
                  <th key={h} className="pb-1 pr-3 font-medium">{h}</th>)}
              </tr>
            </thead>
            <tbody>
              {rows.map((e) => (
                <tr key={e.log_id} className="border-t border-slate-800">
                  <td className="py-1 pr-3 font-mono text-amber-300">{String(e.timestamp || '').slice(11, 19)}</td>
                  <td className="py-1 pr-3 font-mono text-sky-400">{e.log_id}</td>
                  <td className="py-1 pr-3 text-slate-300">{e.host}</td>
                  <td className="py-1 pr-3 font-mono text-slate-400">{e.event_id}</td>
                  <td className="py-1 pr-3 text-slate-300">{e.user || '—'}</td>
                  <td className="py-1 pr-3 font-mono text-slate-400">{e.source_ip || '—'}</td>
                  <td className="py-1 text-slate-400">{e.result || '—'}</td>
                </tr>
              ))}
              {rows.length === 0 && <tr><td colSpan={7} className="py-3 text-center text-slate-500">Sin eventos para el filtro actual.</td></tr>}
            </tbody>
          </table>
        </div>
        {topIps.length > 0 && (
          <div className="mt-3 pt-2 border-t border-slate-800 text-xs text-slate-400">
            IPs con más fallos (4625) en el filtro: {topIps.map(([ip, n]) => `${ip} (${n})`).join(' · ')}
          </div>
        )}
      </Panel>
    </div>
  )
}
