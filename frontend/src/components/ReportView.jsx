import { useState } from 'react'
import { marked } from 'marked'
import {
  PieChart, Pie, Cell, Legend, Tooltip, ResponsiveContainer,
  LineChart, Line, XAxis, YAxis, CartesianGrid,
} from 'recharts'
import { exportMarkdownToPdf } from '../lib/pdf'
import { sevColor } from '../lib/format'

// Gráficos embebidos en el informe, con paleta corporativa (fondo blanco).
function ReportChart({ kind, data }) {
  if (kind === 'distribucion_incidentes_criticidad') {
    const dist = {}
    data.incidents.forEach((i) => { dist[i.severity] = (dist[i.severity] || 0) + 1 })
    const d = Object.entries(dist).map(([name, value]) => ({ name, value }))
    return (
      <div style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: 8, padding: 8, margin: '8px 0' }}>
        <div style={{ color: '#1E3A8A', fontWeight: 600, fontSize: 13, marginBottom: 4 }}>Distribución de incidentes por criticidad</div>
        <ResponsiveContainer width="100%" height={200}>
          <PieChart>
            <Pie data={d} dataKey="value" nameKey="name" cx="38%" outerRadius={70} label>
              {d.map((e) => <Cell key={e.name} fill={sevColor(e.name)} />)}
            </Pie>
            <Tooltip />
            <Legend layout="vertical" verticalAlign="middle" align="right"
              formatter={(v) => <span style={{ color: sevColor(v) }}>{v}</span>} />
          </PieChart>
        </ResponsiveContainer>
      </div>
    )
  }
  if (kind === 'eventos_por_hora') {
    const d = Object.entries(data.stats?.by_hour || {}).map(([hour, n]) => ({ hour, n }))
    return (
      <div style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: 8, padding: 8, margin: '8px 0' }}>
        <div style={{ color: '#1E3A8A', fontWeight: 600, fontSize: 13, marginBottom: 4 }}>Tendencia de eventos por hora</div>
        <ResponsiveContainer width="100%" height={200}>
          <LineChart data={d}>
            <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
            <XAxis dataKey="hour" stroke="#475569" fontSize={11} />
            <YAxis stroke="#475569" fontSize={11} />
            <Tooltip />
            <Line type="monotone" dataKey="n" stroke="#1E3A8A" strokeWidth={2} dot={false} />
          </LineChart>
        </ResponsiveContainer>
      </div>
    )
  }
  return null
}

// Parte el markdown por los marcadores [GRAFICO: x] e intercala gráficos reales.
function renderWithCharts(md, data) {
  const parts = md.split(/\[GRAFICO:\s*([^\]]+)\]/g)
  const nodes = []
  for (let i = 0; i < parts.length; i++) {
    if (i % 2 === 0) {
      if (parts[i].trim())
        nodes.push(<div key={`t${i}`} className="report-body"
          dangerouslySetInnerHTML={{ __html: marked.parse(parts[i]) }} />)
    } else {
      nodes.push(<ReportChart key={`c${i}`} kind={parts[i].trim()} data={data} />)
    }
  }
  return nodes
}

export default function ReportView({ data }) {
  const [tab, setTab] = useState('ejecutivo')
  const [busy, setBusy] = useState(false)
  if (!data) return null
  const md = data.reports?.[tab] || '_Informe no disponible_'

  const exportPdf = async () => {
    setBusy(true)
    try { await exportMarkdownToPdf(md, `informe_${tab}.pdf`) }
    finally { setBusy(false) }
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <div className="flex gap-1">
          {['ejecutivo', 'tecnico'].map((t) => (
            <button key={t} onClick={() => setTab(t)}
              className={`px-4 py-1.5 rounded text-sm capitalize ${tab === t ? 'bg-sky-600 text-white' : 'bg-slate-800 text-slate-400'}`}>
              {t === 'ejecutivo' ? 'Ejecutivo' : 'Técnico'}
            </button>
          ))}
        </div>
        <button onClick={exportPdf} disabled={busy}
          title="Abre el diálogo de impresión: elige 'Guardar como PDF'"
          className="px-4 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 text-sm">
          {busy ? 'Preparando...' : 'Exportar PDF'}
        </button>
      </div>
      <div className="bg-white rounded-lg p-6 max-w-none">
        {renderWithCharts(md, data)}
      </div>
    </div>
  )
}
