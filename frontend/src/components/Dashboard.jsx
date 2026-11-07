import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, LineChart, Line, CartesianGrid, Legend,
} from 'recharts'
import { sevColor } from '../lib/format'
import ActionPlan from './ActionPlan'
import EventsExplorer from './EventsExplorer'

const TOOLTIP = {
  contentStyle: { background: '#0f172a', border: '1px solid #334155', borderRadius: 6 },
  itemStyle: { color: '#f1f5f9' },
  labelStyle: { color: '#f1f5f9' },
}

const Card = ({ label, value, color }) => (
  <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
    <div className="text-xs text-slate-400">{label}</div>
    <div className="text-2xl font-bold mt-1" style={{ color: color || '#e5e7eb' }}>{value}</div>
  </div>
)

const Panel = ({ title, children }) => (
  <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
    <div className="text-sm text-slate-300 mb-3">{title}</div>
    {children}
  </div>
)

export default function Dashboard({ data }) {
  if (!data) return null
  const s = data.stats || {}
  const byHour = Object.entries(s.by_hour || {}).map(([hour, n]) => ({ hour, n }))
  const byEvent = Object.entries(s.by_event_id || {}).map(([id, n]) => ({ id, n }))
    .sort((a, b) => b.n - a.n).slice(0, 10)
  const sevDist = {}
  data.incidents.forEach((i) => { sevDist[i.severity] = (sevDist[i.severity] || 0) + 1 })
  const sevData = Object.entries(sevDist).map(([name, value]) => ({ name, value }))

  const rank = { 'Crítico': 4, 'Alto': 3, 'Medio': 2, 'Bajo': 1 }
  const top = [...data.incidents].sort((a, b) => (rank[b.severity] || 0) - (rank[a.severity] || 0))[0]
  const topHost = top?.affected?.hosts?.[0]

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Card label="Eventos" value={data.event_count} />
        <Card label="Incidentes" value={data.incidents.length} />
        <Card label="Severidad máx." value={data.max_severity || '—'} color={sevColor(data.max_severity)} />
        <Card label="Hallazgos" value={data.findings.length} />
        <Card label="IoCs" value={data.iocs.length} />
      </div>

      {top && (
        <div className="rounded-lg p-4 border" style={{ borderColor: sevColor(top.severity) + '66', background: sevColor(top.severity) + '12' }}>
          <div className="flex items-center gap-2">
            <span className="text-lg">⚠️</span>
            <span className="font-semibold" style={{ color: sevColor(top.severity) }}>Prioridad de respuesta:</span>
            <span className="text-sm text-slate-200">
              atender <span className="font-mono text-sky-300">{top.code}</span> ({top.severity})
              {topHost && <> — aislar primero <span className="font-mono text-red-300">{topHost}</span></>}
            </span>
          </div>
        </div>
      )}

      <Panel title="Incidentes por criticidad">
        <ResponsiveContainer width="100%" height={220}>
          <PieChart>
            <Pie data={sevData} dataKey="value" nameKey="name" cx="38%" outerRadius={80}>
              {sevData.map((e) => <Cell key={e.name} fill={sevColor(e.name)} />)}
            </Pie>
            <Tooltip {...TOOLTIP} />
            <Legend layout="vertical" verticalAlign="middle" align="right" iconType="square"
              formatter={(v) => {
                const d = sevData.find((x) => x.name === v)
                return <span style={{ color: sevColor(v) }}>{v}: {d?.value ?? 0}</span>
              }} />
          </PieChart>
        </ResponsiveContainer>
      </Panel>

      {/* Explorador de eventos con filtros interactivos + tabla paginada */}
      <EventsExplorer analysisId={data.id} />

      {(data.limitations?.length > 0) && (
        <Panel title="Limitaciones declaradas del análisis">
          <ul className="text-sm text-slate-400 list-disc pl-5 space-y-1">
            {data.limitations.map((l, i) => <li key={i}>{l}</li>)}
          </ul>
        </Panel>
      )}

      <div className="border-t border-slate-800 pt-4 mt-2">
        <ActionPlan data={data} />
      </div>
    </div>
  )
}
