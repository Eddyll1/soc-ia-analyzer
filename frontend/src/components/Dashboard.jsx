import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, LineChart, Line, CartesianGrid, Legend,
} from 'recharts'
import { sevColor } from '../lib/format'

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

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Card label="Eventos" value={data.event_count} />
        <Card label="Incidentes" value={data.incidents.length} />
        <Card label="Severidad máx." value={data.max_severity || '—'} color={sevColor(data.max_severity)} />
        <Card label="Hallazgos" value={data.findings.length} />
        <Card label="IoCs" value={data.iocs.length} />
      </div>

      <div className="grid md:grid-cols-2 gap-4">
        <Panel title="Eventos por hora">
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={byHour}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="hour" stroke="#64748b" fontSize={11} />
              <YAxis stroke="#64748b" fontSize={11} />
              <Tooltip {...TOOLTIP} />
              <Line type="monotone" dataKey="n" stroke="#38bdf8" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </Panel>

        <Panel title="Incidentes por criticidad">
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie data={sevData} dataKey="value" nameKey="name" outerRadius={75}
                label={({ name, value }) => `${name}: ${value}`} labelLine={{ stroke: '#64748b' }}>
                {sevData.map((e) => <Cell key={e.name} fill={sevColor(e.name)} />)}
              </Pie>
              <Tooltip {...TOOLTIP} />
              <Legend verticalAlign="bottom" height={28}
                formatter={(v) => <span style={{ color: sevColor(v) }}>{v}</span>} />
            </PieChart>
          </ResponsiveContainer>
        </Panel>

        <Panel title="Top tipos de evento (Event_ID)">
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={byEvent} layout="vertical" margin={{ left: 20 }}>
              <XAxis type="number" stroke="#64748b" fontSize={11} />
              <YAxis type="category" dataKey="id" stroke="#64748b" fontSize={11} width={90} />
              <Tooltip {...TOOLTIP} />
              <Bar dataKey="n" fill="#818cf8" />
            </BarChart>
          </ResponsiveContainer>
        </Panel>

        <Panel title="Top IPs con fallos de login">
          <table className="text-sm w-full">
            <tbody>
              {Object.entries(s.top_failed_ips || {}).map(([ip, n]) => (
                <tr key={ip} className="border-t border-slate-800">
                  <td className="py-1.5 font-mono text-slate-300">{ip}</td>
                  <td className="py-1.5 text-right text-orange-400">{n} fallos</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      </div>

      {(data.limitations?.length > 0) && (
        <Panel title="Limitaciones declaradas del análisis">
          <ul className="text-sm text-slate-400 list-disc pl-5 space-y-1">
            {data.limitations.map((l, i) => <li key={i}>{l}</li>)}
          </ul>
        </Panel>
      )}
    </div>
  )
}
