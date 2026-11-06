import { useState } from 'react'
import { marked } from 'marked'
import { exportMarkdownToPdf } from '../lib/pdf'

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
          className="px-4 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 text-sm">
          {busy ? 'Generando...' : 'Exportar PDF'}
        </button>
      </div>
      <div className="bg-white text-slate-900 rounded-lg p-6 prose-sm max-w-none report-body"
        dangerouslySetInnerHTML={{ __html: marked.parse(md) }} />
    </div>
  )
}
